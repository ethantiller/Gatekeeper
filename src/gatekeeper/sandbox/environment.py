"""Builds and manages the sandbox base image, the internet-less network, and the connection logger."""

import argparse
import hashlib
import io
import json
import re
import sys
import tarfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from docker.errors import DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from docker.models.networks import Network
from docker.types import LogConfig

import docker
from docker import DockerClient

DOCKER_DIR: Path = Path(__file__).resolve().parents[3] / "docker"

NETWORK_NAME = "gk-sandbox"
LOGGER_NAME = "gk-connection-logger"
LOGGER_PORT = 8080
MANAGED_LABEL = "com.gatekeeper.managed"
CA_SOURCE_PATH = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
CA_SANDBOX_PATH = "/etc/gatekeeper/ca.pem"
REGISTRY_DIR = "/registry"
READY_MARKER = b"GK_READY"
LOG_LINE_PREFIX = "GK_CONN "
READY_TIMEOUT_SECONDS = 20.0
READY_POLL_SECONDS = 0.3

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


def _hash_files(files: tuple[Path, ...]) -> str:
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.name.encode())
        digest.update(path.read_bytes())
    return digest.hexdigest()[:12]


@dataclass(frozen=True)
class ImageSpec:
    """An image built from files in the repo. The tag changes when any of those files change."""

    repository: str
    context_dir: Path
    dockerfile: str
    hashed_files: tuple[Path, ...]

    @property
    def tag(self) -> str:
        return f"{self.repository}:{_hash_files(self.hashed_files)}"


BASE_IMAGE = ImageSpec(
    repository="gatekeeper-sandbox-base",
    context_dir=DOCKER_DIR,
    dockerfile="base.Dockerfile",
    hashed_files=(DOCKER_DIR / "base.Dockerfile",),
)
LOGGER_IMAGE = ImageSpec(
    repository="gatekeeper-connection-logger",
    context_dir=DOCKER_DIR / "connection_logger",
    dockerfile="Dockerfile",
    hashed_files=tuple(
        DOCKER_DIR / "connection_logger" / name
        for name in ("Dockerfile", "logger.py", "tripwire_match.py")
    ),
)


@dataclass
class EnvironmentStatus:
    docker_reachable: bool = False
    base_image: str = ""
    base_image_present: bool = False
    logger_image: str = ""
    logger_image_present: bool = False
    network_present: bool = False
    network_internal: bool = False
    logger_state: str = "missing"  # missing | running | <other Docker state>
    changes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return (
            self.docker_reachable
            and self.base_image_present
            and self.logger_image_present
            and self.network_present
            and self.network_internal
            and self.logger_state == "running"
        )


# --- Error handling and Docker connection -------------------------------------------------


@contextmanager
def _docker_errors(action: str) -> Iterator[None]:
    """Turn any Docker failure into a SandboxEnvironmentError that says what we were doing."""
    try:
        yield
    except SandboxEnvironmentError:
        raise
    except DockerException as exc:
        raise SandboxEnvironmentError(f"Docker error while {action}: {exc}") from exc


def _connect(client: DockerClient | None = None) -> DockerClient:
    """Return the given client, or connect to the local Docker daemon."""
    if client is not None:
        return client
    try:
        connected = docker.from_env()
        connected.ping()
    except DockerException as exc:
        raise SandboxEnvironmentError(
            "Docker is not reachable. Start Docker Desktop (or your Docker daemon) and try again."
        ) from exc
    return connected


# --- Images -------------------------------------------------------------------------------


def base_image_tag() -> str:
    return BASE_IMAGE.tag


def logger_image_tag() -> str:
    return LOGGER_IMAGE.tag


def _image_exists(client: DockerClient, tag: str) -> bool:
    try:
        client.images.get(tag)
    except ImageNotFound:
        return False
    return True


def _build_image(client: DockerClient, spec: ImageSpec) -> None:
    """Build the image under its hashed tag and also tag it :latest."""
    with _docker_errors(f"building image {spec.tag}"):
        image, _ = client.images.build(
            path=str(spec.context_dir),
            dockerfile=spec.dockerfile,
            tag=spec.tag,
            rm=True,
            labels={MANAGED_LABEL: "true"},
        )
        image.tag(spec.repository, "latest")


def _ensure_image(client: DockerClient, spec: ImageSpec, status: EnvironmentStatus) -> None:
    """Build the image if it is missing, and record that in status.changes."""
    if _image_exists(client, spec.tag):
        return
    _build_image(client, spec)
    status.changes.append(f"built {spec.repository}")


# --- Network ------------------------------------------------------------------------------


def _find_network(client: DockerClient) -> Network | None:
    try:
        return client.networks.get(NETWORK_NAME)
    except NotFound:
        return None


def _ensure_network(client: DockerClient, status: EnvironmentStatus) -> None:
    network = _find_network(client)
    if network is None:
        client.networks.create(
            NETWORK_NAME, driver="bridge", internal=True, labels={MANAGED_LABEL: "true"}
        )
        status.changes.append("created network")
    elif not network.attrs.get("Internal"):
        raise SandboxEnvironmentError(
            f"Docker network '{NETWORK_NAME}' exists but is not internal, so it has a route "
            f"to the internet. Remove it with 'docker network rm {NETWORK_NAME}' and retry."
        )


# --- Logger container ---------------------------------------------------------------------


def _find_logger(client: DockerClient) -> Container | None:
    try:
        return client.containers.get(LOGGER_NAME)
    except NotFound:
        return None


def _require_logger(client: DockerClient) -> Container:
    logger = _find_logger(client)
    if logger is None or logger.status != "running":
        raise SandboxEnvironmentError(
            "The connection logger is not running. "
            "Run: uv run python -m gatekeeper.sandbox.environment up"
        )
    return logger


def _start_logger(client: DockerClient) -> Container:
    return client.containers.run(
        LOGGER_IMAGE.tag,
        name=LOGGER_NAME,
        detach=True,
        network=NETWORK_NAME,
        restart_policy={"Name": "unless-stopped"},
        log_config=LogConfig(
            type=LogConfig.types.JSON, config={"max-size": "10m", "max-file": "3"}
        ),
        labels={MANAGED_LABEL: "true"},
    )


def _wait_until_ready(logger: Container, timeout_seconds: float = READY_TIMEOUT_SECONDS) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        logger.reload()
        if logger.status not in ("created", "running"):
            break
        if READY_MARKER in logger.logs():
            return
        time.sleep(READY_POLL_SECONDS)
    recent_logs = logger.logs(tail=20).decode(errors="replace")
    raise SandboxEnvironmentError(
        f"The connection logger did not report ready within {timeout_seconds:.0f}s. "
        f"Last logs:\n{recent_logs}"
    )


def _ensure_logger(client: DockerClient, status: EnvironmentStatus) -> None:
    expected_image_id = client.images.get(LOGGER_IMAGE.tag).id
    logger = _find_logger(client)
    is_stale = logger is not None and (
        logger.status != "running" or logger.image.id != expected_image_id
    )
    if is_stale:
        logger.remove(force=True)
        logger = None
    if logger is None:
        logger = _start_logger(client)
        status.changes.append("started logger")
    _wait_until_ready(logger)
    status.logger_state = "running"


# --- Public: ensure, status, teardown -----------------------------------------------------


def _new_status() -> EnvironmentStatus:
    return EnvironmentStatus(
        docker_reachable=True, base_image=BASE_IMAGE.tag, logger_image=LOGGER_IMAGE.tag
    )


def ensure_environment(client: DockerClient | None = None) -> EnvironmentStatus:
    """Idempotent: builds/creates only what is missing. `changes` lists what was done."""
    docker_client = _connect(client)
    status = _new_status()
    with _docker_errors("preparing the sandbox"):
        _ensure_image(docker_client, BASE_IMAGE, status)
        status.base_image_present = True
        _ensure_image(docker_client, LOGGER_IMAGE, status)
        status.logger_image_present = True
        _ensure_network(docker_client, status)
        status.network_present = status.network_internal = True
        _ensure_logger(docker_client, status)
    return status


def get_status(client: DockerClient | None = None) -> EnvironmentStatus:
    """Read-only view of what exists. Never creates anything."""
    docker_client = _connect(client)
    status = _new_status()
    with _docker_errors("reading the sandbox status"):
        status.base_image_present = _image_exists(docker_client, BASE_IMAGE.tag)
        status.logger_image_present = _image_exists(docker_client, LOGGER_IMAGE.tag)
        network = _find_network(docker_client)
        if network is not None:
            status.network_present = True
            status.network_internal = bool(network.attrs.get("Internal"))
        logger = _find_logger(docker_client)
        if logger is not None:
            status.logger_state = logger.status
    return status


def teardown_environment(client: DockerClient) -> None:
    """Remove the logger container and the network. Images are kept."""
    with _docker_errors("removing the sandbox environment"):
        logger = _find_logger(client)
        if logger is not None:
            logger.remove(force=True)
        network = _find_network(client)
        if network is not None:
            network.remove()


# --- Proxy and CA settings for sandbox containers -----------------------------------------


def proxy_environment() -> dict[str, str]:
    """Environment for sandbox containers so web traffic goes to the logger and trusts its CA."""
    proxy_url = f"http://{LOGGER_NAME}:{LOGGER_PORT}" # noqa
    variables: dict[str, str] = {"NO_PROXY": "", "no_proxy": ""}
    for name in ("http_proxy", "https_proxy", "all_proxy"):
        variables[name] = proxy_url
        variables[name.upper()] = proxy_url  # curl ignores uppercase HTTP_PROXY, so set both
    for name in CA_ENVIRONMENT_VARIABLES:
        variables[name] = CA_SANDBOX_PATH
    return variables


# --- Files copied into containers ---------------------------------------------------------


def _tar_single_file(name: str, content: bytes, mode: int) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(name)
        info.size = len(content)
        info.mode = mode
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _read_ca_certificate(logger: Container) -> bytes:
    result = logger.exec_run(["cat", CA_SOURCE_PATH])
    if result.exit_code != 0 or not result.output:
        raise SandboxEnvironmentError("Could not read the logger's CA certificate.")
    return result.output


def ca_certificate_archive(client: DockerClient) -> bytes:
    """Tar with etc/gatekeeper/ca.pem for put_archive("/", data)."""
    with _docker_errors("reading the logger's CA certificate"):
        certificate = _read_ca_certificate(_require_logger(client))
    return _tar_single_file("etc/gatekeeper/ca.pem", certificate, mode=0o644)


# --- Session registry ---------------------------------------------------------------------


def _registry_filename(session_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_id) + ".json"


def register_session(client: DockerClient, session_id: str, seed: str) -> None:
    """Tell the logger which tripwire values to watch for in this session."""
    from gatekeeper.sandbox.tripwires import registry_entry

    archive = _tar_single_file(
        _registry_filename(session_id), registry_entry(session_id, seed), mode=0o644
    )
    with _docker_errors(f"registering session {session_id}"):
        _require_logger(client).put_archive(REGISTRY_DIR, archive)


def unregister_session(client: DockerClient, session_id: str) -> None:
    """Stop watching for this session's values. Does nothing if the logger is gone."""
    with _docker_errors(f"unregistering session {session_id}"):
        logger = _find_logger(client)
        if logger is not None and logger.status == "running":
            logger.exec_run(["rm", "-f", f"{REGISTRY_DIR}/{_registry_filename(session_id)}"])


# --- Reading the connection log -----------------------------------------------------------


def _parse_log_line(line: str) -> dict | None:
    """Parse one GK_CONN line. Returns None for anything else or for malformed JSON."""
    if not line.startswith(LOG_LINE_PREFIX):
        return None
    try:
        record = json.loads(line[len(LOG_LINE_PREFIX):])
    except ValueError:
        return None
    return record if isinstance(record, dict) else None


def read_connection_log(
    client: DockerClient, since: datetime | float, client_ip: str | None = None
) -> list[dict]:
    """GK_CONN records from the logger since `since`, optionally only for one client IP."""
    since_seconds = since.timestamp() if isinstance(since, datetime) else since
    with _docker_errors("reading the connection log"):
        logger = _find_logger(client)
        if logger is None:
            return []
        raw_log = logger.logs(stdout=True, stderr=False, since=since_seconds).decode(
            errors="replace"
        )
    records = (_parse_log_line(line) for line in raw_log.splitlines())
    return [
        record
        for record in records
        if record is not None and (client_ip is None or record.get("client_ip") == client_ip)
    ]


# --- Command line -------------------------------------------------------------------------


def _print_status(status: EnvironmentStatus) -> None:
    base = "present" if status.base_image_present else "MISSING"
    logger_image = "present" if status.logger_image_present else "MISSING"
    network = (
        f"internal={status.network_internal}" if status.network_present else "MISSING"
    )
    print(f"base image:    {status.base_image} ({base})")
    print(f"logger image:  {status.logger_image} ({logger_image})")
    print(f"network:       {NETWORK_NAME} {network}")
    print(f"logger:        {LOGGER_NAME} {status.logger_state}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m gatekeeper.sandbox.environment")
    parser.add_argument("command", choices=["up", "status", "down"])
    args = parser.parse_args(argv)

    try:
        if args.command == "up":
            status = ensure_environment()
            _print_status(status)
            print("changes: " + (", ".join(status.changes) or "none"))
            return EXIT_SUCCESS

        if args.command == "status":
            status = get_status()
            _print_status(status)
            return EXIT_SUCCESS if status.ok else EXIT_FAILURE

        teardown_environment(_connect())
        print("Removed logger container and network (images kept).")
        return EXIT_SUCCESS
    except SandboxEnvironmentError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
