"""The server as a login service (launchd on macOS, a systemd user unit on Linux) or a process."""

import os
import plistlib
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import httpx

from gatekeeper.setup import home, paths

COMMAND_TIMEOUT_SECONDS = 30
START_WAIT_SECONDS = 15
HEALTH_TIMEOUT_SECONDS = 2


class ServiceError(Exception):
    """Raised with a plain-language message when the server could not be managed."""


def server_command() -> list[str]:
    """The command that runs the server: the console script next to this Python, if installed."""
    script = Path(sys.executable).parent / "gatekeeper-server"
    if script.exists():
        return [str(script)]
    return [sys.executable, "-m", "gatekeeper.server.main"]


def render_launchd_plist(command: list[str], log_file: Path) -> bytes:
    """The launchd agent: start at login, restart if it dies, log to `server.log`."""
    return plistlib.dumps(
        {
            "Label": paths.SERVICE_LABEL,
            "ProgramArguments": command,
            "RunAtLoad": True,
            "KeepAlive": True,
            "StandardOutPath": str(log_file),
            "StandardErrorPath": str(log_file),
        }
    )


def render_systemd_unit(command: list[str], log_file: Path) -> str:
    """The systemd user unit: start at login, restart on failure, log to `server.log`."""
    return (
        "[Unit]\n"
        "Description=Gatekeeper server\n"
        "\n"
        "[Service]\n"
        f"ExecStart={' '.join(command)}\n"
        "Restart=on-failure\n"
        f"StandardOutput=append:{log_file}\n"
        f"StandardError=append:{log_file}\n"
        "\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    )


def service_file_path() -> Path:
    return paths.launchd_plist_path() if paths.is_macos() else paths.systemd_unit_path()


def is_service_installed() -> bool:
    return service_file_path().exists()


def install_service() -> list[str]:
    """Write the service file and load it; return what changed. Safe to repeat."""
    command, log_file = server_command(), paths.log_path()
    target = service_file_path()
    if paths.is_macos():
        content: bytes = render_launchd_plist(command, log_file)
    else:
        content = render_systemd_unit(command, log_file).encode()
    changed = not target.exists() or target.read_bytes() != content
    if changed:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    if paths.is_macos():
        if changed:
            _launchctl("bootout", _launchd_target(), check=False)
        if _launchctl("print", _launchd_target(), check=False).returncode != 0:
            _launchctl("bootstrap", _launchd_domain(), str(target))
            changed = True
    else:
        _systemctl("daemon-reload")
        _systemctl("enable", paths.SYSTEMD_UNIT_NAME)
    return ["installed the login service"] if changed else []


def uninstall_service() -> bool:
    """Stop and delete the login service; True if there was one."""
    target = service_file_path()
    if not target.exists():
        return False
    if paths.is_macos():
        _launchctl("bootout", _launchd_target(), check=False)
    else:
        _systemctl("disable", "--now", paths.SYSTEMD_UNIT_NAME, check=False)
    target.unlink()
    if not paths.is_macos():
        _systemctl("daemon-reload", check=False)
    return True


def start_server() -> str:
    """Start the server (through the login service if installed) and wait until it answers."""
    if server_is_up():
        return "already running"
    if _port_in_use():
        raise ServiceError(
            f"Port {paths.SERVER_PORT} is in use by another program (maybe a Gatekeeper server "
            "started with a different token or HOME). Stop it first."
        )
    if is_service_installed():
        _start_service()
    else:
        _spawn_process()
    deadline = time.monotonic() + START_WAIT_SECONDS
    while time.monotonic() < deadline:
        if server_is_up():
            return "started"
        time.sleep(0.5)
    raise ServiceError(f"The server did not answer in {START_WAIT_SECONDS}s. See {paths.log_path()}")


def stop_server() -> bool:
    """Stop the server; True if something was running or loaded."""
    stopped = False
    if is_service_installed():
        stopped = _stop_service()
    pid_file = paths.pid_path()
    if pid_file.exists():
        stopped = _stop_pid(pid_file) or stopped
    return _stop_listeners() or stopped


def server_is_up() -> bool:
    """Whether `GET /health` with the token answers 200."""
    try:
        token = home.read_token()
        response = httpx.get(
            f"{paths.SERVER_URL}/health",
            headers={"X-Gatekeeper-Token": token},
            timeout=HEALTH_TIMEOUT_SECONDS,
        )
    except (OSError, httpx.HTTPError):
        return False
    return response.status_code == httpx.codes.OK


def _port_in_use() -> bool:
    with socket.socket() as probe:
        return probe.connect_ex((paths.SERVER_HOST, paths.SERVER_PORT)) == 0


def _start_service() -> None:
    if paths.is_macos():
        if _launchctl("print", _launchd_target(), check=False).returncode != 0:
            _launchctl("bootstrap", _launchd_domain(), str(service_file_path()))
        _launchctl("kickstart", _launchd_target())
    else:
        _systemctl("start", paths.SYSTEMD_UNIT_NAME)


def _stop_service() -> bool:
    if paths.is_macos():
        return _launchctl("bootout", _launchd_target(), check=False).returncode == 0
    return _systemctl("stop", paths.SYSTEMD_UNIT_NAME, check=False).returncode == 0


def _spawn_process() -> None:
    log_file = paths.log_path()
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("ab") as log:
        process = subprocess.Popen(
            server_command(),
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=log,
            start_new_session=True,
        )
    paths.pid_path().write_text(str(process.pid))


def _stop_pid(pid_file: Path) -> bool:
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGTERM)
    except (ValueError, ProcessLookupError):
        stopped = False
    except PermissionError as error:
        raise ServiceError(f"Cannot stop the server (pid file {pid_file}): {error}") from error
    else:
        stopped = True
    pid_file.unlink(missing_ok=True)
    return stopped


def _stop_listeners() -> bool:
    """Stop a Gatekeeper server on our port that was started by hand (no service, no pid file)."""
    stopped = False
    for pid in _listening_pids():
        if "gatekeeper" not in _process_command(pid):
            continue  # some other program owns the port; leave it alone
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            continue
        except PermissionError as error:
            raise ServiceError(f"Cannot stop the server (pid {pid}): {error}") from error
        stopped = True
    return stopped


def _listening_pids() -> list[int]:
    if shutil.which("lsof") is None:
        return []
    result = subprocess.run(
        ["lsof", "-t", f"-iTCP:{paths.SERVER_PORT}", "-sTCP:LISTEN"],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )
    return [int(line) for line in result.stdout.split() if line.isdigit()]


def _process_command(pid: int) -> str:
    result = subprocess.run(
        ["ps", "-p", str(pid), "-o", "command="],
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        check=False,
    )
    return result.stdout.strip()


def _launchd_domain() -> str:
    return f"gui/{os.getuid()}"


def _launchd_target() -> str:
    return f"{_launchd_domain()}/{paths.SERVICE_LABEL}"


def _launchctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["launchctl", *args], check)


def _systemctl(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return _run(["systemctl", "--user", *args], check)


def _run(command: list[str], check: bool) -> subprocess.CompletedProcess[str]:
    if shutil.which(command[0]) is None:
        raise ServiceError(f"{command[0]} was not found, so the login service cannot be managed")
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=COMMAND_TIMEOUT_SECONDS, check=False
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ServiceError(f"{' '.join(command)} failed: {error}") from error
    if check and result.returncode != 0:
        raise ServiceError(f"{' '.join(command)} failed: {result.stderr.strip()}")
    return result
