"""Manages the sandbox base image, the internet-less network, and the connection logger.

Everything is defined in docker/compose.yaml and driven through the `docker` command line.
"""

import argparse
import io
import json
import re
import subprocess
import sys
import tarfile
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

COMPOSE_FILE: Path = Path(__file__).resolve().parents[3] / "docker" / "compose.yaml"

BASE_IMAGE_TAG = "gatekeeper-sandbox-base:latest"
LOGGER_IMAGE_TAG = "gatekeeper-connection-logger:latest"
NETWORK_NAME = "gk-sandbox"
LOGGER_NAME = "gk-connection-logger"
LOGGER_PORT = 8080
CA_SOURCE_PATH = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
CA_SANDBOX_PATH = "/etc/gatekeeper/ca.pem"
REGISTRY_DIR = "/registry"
LOG_LINE_PREFIX = "GK_CONN "
READY_TIMEOUT_SECONDS = 30

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

CA_ENVIRONMENT_VARIABLES: tuple[str, ...] = (
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
    "PIP_CERT",
    "NPM_CONFIG_CAFILE",
)


class SandboxEnvironmentError(Exception):
    """Raised with a plain-language message when the sandbox environment cannot be prepared."""


@dataclass
class EnvironmentStatus:
    base_image_present: bool = False
    network_present: bool = False
    network_internal: bool = False
    logger_state: str = "missing"  # missing | running | <other Docker state>

    @property
    def ok(self) -> bool:
        return (
            self.base_image_present
            and self.network_present
            and self.network_internal
            and self.logger_state == "running"
        )


def run_docker(
    *args: str, input: bytes | None = None, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    """Run `docker <args>`. With check=True, a failure raises SandboxEnvironmentError."""
    command = ["docker", *args]
    try:
        result = subprocess.run(command, input=input, capture_output=True, check=False)
    except FileNotFoundError as exc:
        raise SandboxEnvironmentError(
            "The docker command was not found. Install Docker Desktop and try again."
        ) from exc
    if check and result.returncode != 0:
        error_text = result.stderr.decode(errors="replace").strip()
        raise SandboxEnvironmentError(f"`docker {' '.join(args)}` failed: {error_text}")
    return result


def _run_compose(*args: str) -> None:
    run_docker("compose", "-f", str(COMPOSE_FILE), *args)


def _inspect_value(kind: str, name: str, template: str) -> str | None:
    """One value from `docker <kind> inspect`, or None if the object does not exist."""
    result = run_docker(kind, "inspect", "-f", template, name, check=False)
    return result.stdout.decode().strip() if result.returncode == 0 else None


def base_image_tag() -> str:
    return BASE_IMAGE_TAG


def ensure_environment(rebuild: bool = False) -> EnvironmentStatus:
    """Idempotent: builds missing images and starts the logger only if it is not running.

    Rebuilding replaces the images, which makes compose recreate the logger (and its CA), so
    it only happens when an image is missing or rebuild=True.
    """
    if run_docker("info", check=False).returncode != 0:
        raise SandboxEnvironmentError(
            "Docker is not reachable. Start Docker Desktop (or your Docker daemon) and try again."
        )
    status = get_status()
    logger_image_present = _inspect_value("image", LOGGER_IMAGE_TAG, "{{.Id}}") is not None
    needs_build = rebuild or not status.base_image_present or not logger_image_present
    if needs_build:
        _run_compose("--profile", "build", "build")
    elif status.ok:
        return status
    _run_compose(
        "up", "-d", "--wait", "--wait-timeout", str(READY_TIMEOUT_SECONDS), "connection-logger"
    )
    return get_status()


def get_status() -> EnvironmentStatus:
    """Read-only view of what exists. Never creates anything."""
    internal = _inspect_value("network", NETWORK_NAME, "{{.Internal}}")
    logger_state = _inspect_value("container", LOGGER_NAME, "{{.State.Status}}")
    return EnvironmentStatus(
        base_image_present=_inspect_value("image", BASE_IMAGE_TAG, "{{.Id}}") is not None,
        network_present=internal is not None,
        network_internal=internal == "true",
        logger_state=logger_state or "missing",
    )


def teardown_environment() -> None:
    """Remove the logger container and the network. Images are kept."""
    _run_compose("down")


def proxy_environment() -> dict[str, str]:
    """Environment for sandbox containers so web traffic goes to the logger and trusts its CA."""
    proxy_url = f"http://{LOGGER_NAME}:{LOGGER_PORT}"
    variables: dict[str, str] = {"NO_PROXY": "", "no_proxy": ""}
    for name in ("http_proxy", "https_proxy", "all_proxy"):
        variables[name] = proxy_url
        variables[name.upper()] = proxy_url  # curl ignores uppercase HTTP_PROXY, so set both
    for name in CA_ENVIRONMENT_VARIABLES:
        variables[name] = CA_SANDBOX_PATH
    return variables


def _tar_single_file(name: str, content: bytes, mode: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        info.mode = mode
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _require_logger_running() -> None:
    if get_status().logger_state != "running":
        raise SandboxEnvironmentError(
            "The connection logger is not running. "
            "Run: uv run python -m gatekeeper.sandbox.environment up"
        )


def ca_certificate_archive() -> bytes:
    """Tar with etc/gatekeeper/ca.pem for `docker cp - <container>:/`."""
    _require_logger_running()
    certificate = run_docker("exec", LOGGER_NAME, "cat", CA_SOURCE_PATH).stdout
    if not certificate:
        raise SandboxEnvironmentError("Could not read the logger's CA certificate.")
    return _tar_single_file("etc/gatekeeper/ca.pem", certificate, mode=0o644)


def _registry_filename(session_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_id) + ".json"


def register_session(session_id: str, seed: str) -> None:
    """Tell the logger which tripwire values to watch for in this session."""
    from gatekeeper.sandbox.tripwires import registry_entry

    _require_logger_running()
    archive = _tar_single_file(
        _registry_filename(session_id), registry_entry(session_id, seed), mode=0o644
    )
    run_docker("cp", "-", f"{LOGGER_NAME}:{REGISTRY_DIR}", input=archive)


def unregister_session(session_id: str) -> None:
    """Stop watching for this session's values. Does nothing if the logger is gone."""
    run_docker(
        "exec", LOGGER_NAME, "rm", "-f", f"{REGISTRY_DIR}/{_registry_filename(session_id)}",
        check=False,
    )


def _parse_log_line(line: str) -> dict | None:
    """Parse one GK_CONN line. Returns None for anything else or for malformed JSON."""
    if not line.startswith(LOG_LINE_PREFIX):
        return None
    try:
        record = json.loads(line[len(LOG_LINE_PREFIX):])
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def read_connection_log(since: datetime | float, client_ip: str | None = None) -> list[dict]:
    """GK_CONN records from the logger since `since`, optionally only for one client IP."""
    since_seconds = since.timestamp() if isinstance(since, datetime) else since
    result = run_docker("logs", "--since", str(since_seconds), LOGGER_NAME, check=False)
    if result.returncode != 0:
        return []
    records = (_parse_log_line(line) for line in result.stdout.decode(errors="replace").splitlines())
    return [
        record
        for record in records
        if record is not None and (client_ip is None or record.get("client_ip") == client_ip)
    ]


def _print_status(status: EnvironmentStatus) -> None:
    base = "present" if status.base_image_present else "MISSING"
    network = f"internal={status.network_internal}" if status.network_present else "MISSING"
    print(f"base image:  {BASE_IMAGE_TAG} ({base})")
    print(f"network:     {NETWORK_NAME} {network}")
    print(f"logger:      {LOGGER_NAME} {status.logger_state}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gatekeeper.sandbox.environment")
    parser.add_argument("command", choices=["up", "status", "down"])
    parser.add_argument("--rebuild", action="store_true", help="with up: rebuild the images")
    args = parser.parse_args(argv)

    try:
        if args.command == "up":
            _print_status(ensure_environment(rebuild=args.rebuild))
            return EXIT_SUCCESS

        if args.command == "status":
            status = get_status()
            _print_status(status)
            return EXIT_SUCCESS if status.ok else EXIT_FAILURE

        teardown_environment()
        print("Removed logger container and network (images kept).")
        return EXIT_SUCCESS
    except SandboxEnvironmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
