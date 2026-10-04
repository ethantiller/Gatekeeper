"""Manages the sandbox base image, the internet-less network, and the connection logger.

Everything is created through the Docker Python SDK.
"""

import argparse
import io
import json
import re
import sys
import tarfile
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import requests
from docker.errors import APIError, BuildError, DockerException, ImageNotFound, NotFound
from docker.models.containers import Container
from docker.models.networks import Network
from docker.types import LogConfig

import docker

DOCKER_DIR: Path = Path(__file__).resolve().parents[3] / "docker"

BASE_IMAGE_TAG = "gatekeeper-sandbox-base:latest"
BASE_DOCKERFILE = "base.Dockerfile"
LOGGER_IMAGE_TAG = "gatekeeper-connection-logger:latest"
LOGGER_BUILD_DIR: Path = DOCKER_DIR / "connection_logger"
NETWORK_NAME = "gk-sandbox"
NETWORK_LABELS = {"com.gatekeeper.managed": "true"}
LOGGER_NAME = "gk-connection-logger"
LOGGER_PORT = 8080
LOGGER_LOG_OPTIONS = {"max-size": "10m", "max-file": "3"}
CA_SOURCE_PATH = "/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem"
CA_SANDBOX_PATH = "/etc/gatekeeper/ca.pem"
REGISTRY_DIR = "/registry"
LOG_LINE_PREFIX = "GK_CONN "
READY_TIMEOUT_SECONDS = 30
READY_POLL_SECONDS = 1
PING_INTERVAL_SECONDS = 30  # how long a successful ping vouches for the cached client
SANDBOX_CONTAINER_LABEL = "com.gatekeeper.sandbox"
SANDBOX_STARTED_LABEL = "com.gatekeeper.started-at"  # epoch seconds, read by the reaper
STALE_CONTAINER_SECONDS = 10 * 60  # far longer than any run, so a live run is never reaped

NANOSECONDS_PER_SECOND = 1_000_000_000
LOGGER_HEALTHCHECK = {
    "test": [
        "CMD", "python", "-c",
        f"import socket; socket.create_connection(('127.0.0.1', {LOGGER_PORT}), 2)",
    ],
    "interval": 2 * NANOSECONDS_PER_SECOND,
    "timeout": 3 * NANOSECONDS_PER_SECOND,
    "retries": 10,
    "start_period": 3 * NANOSECONDS_PER_SECOND,
}

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
    logger_state: str = "missing"  # missing | running | starting | unhealthy | <other Docker state>

    @property
    def ok(self) -> bool:
        return (
            self.base_image_present
            and self.network_present
            and self.network_internal
            and self.logger_state == "running"
        )


_client_lock = threading.Lock()
_cached_client: docker.DockerClient | None = None
_last_ping: float = 0.0


def get_docker_client() -> docker.DockerClient:
    """The shared client for the local Docker daemon, pinged at most every PING_INTERVAL_SECONDS."""
    global _cached_client, _last_ping
    with _client_lock:
        now = time.monotonic()
        if _cached_client is not None and now - _last_ping < PING_INTERVAL_SECONDS:
            return _cached_client
        try:
            client = _cached_client or docker.from_env()
            client.ping()
        except (DockerException, requests.exceptions.RequestException) as exc:
            _cached_client = None
            raise SandboxEnvironmentError(
                "Docker is not reachable. Start Docker Desktop (or your Docker daemon) and try again."
            ) from exc
        _cached_client = client
        _last_ping = now
        return client


def _find_image_id(client: docker.DockerClient, tag: str) -> str | None:
    try:
        return client.images.get(tag).id
    except ImageNotFound:
        return None


def _find_network(client: docker.DockerClient) -> Network | None:
    try:
        return client.networks.get(NETWORK_NAME)
    except NotFound:
        return None


def _find_logger(client: docker.DockerClient) -> Container | None:
    try:
        return client.containers.get(LOGGER_NAME)
    except NotFound:
        return None


def base_image_tag() -> str:
    return BASE_IMAGE_TAG


def ensure_environment(rebuild: bool = False) -> EnvironmentStatus:
    """Idempotent: builds missing images and starts the logger only if it is not running.

    Rebuilding replaces the images and recreates the logger (and its CA), so it only happens
    when an image is missing or rebuild=True.
    """
    client = get_docker_client()
    try:
        status = _read_status(client)
        logger_image_present = _find_image_id(client, LOGGER_IMAGE_TAG) is not None
        needs_build = rebuild or not status.base_image_present or not logger_image_present
        if not needs_build and status.ok:
            _remove_stale_sandboxes(client)
            return status
        if needs_build:
            _build_images(client)
            _remove_logger(client)
        _ensure_network(client)
        _ensure_logger(client)
        _remove_stale_sandboxes(client)
        return _read_status(client)
    except BuildError as exc:
        raise SandboxEnvironmentError(f"Building the sandbox images failed: {exc}") from exc
    except ImageNotFound as exc:
        raise SandboxEnvironmentError(f"A sandbox image is missing: {exc}") from exc
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not set up the sandbox: {exc}") from exc


def sandbox_container_labels() -> dict[str, str]:
    """Labels for a new sandbox container, so a crash or Ctrl-C leaves something the reaper finds."""
    return {SANDBOX_CONTAINER_LABEL: "true", SANDBOX_STARTED_LABEL: str(time.time())}


def _remove_stale_sandboxes(client: docker.DockerClient) -> None:
    """Remove labelled sandbox containers older than STALE_CONTAINER_SECONDS (left by crashes)."""
    stale_before = time.time() - STALE_CONTAINER_SECONDS
    leftovers = client.containers.list(
        all=True, filters={"label": f"{SANDBOX_CONTAINER_LABEL}=true"}
    )
    for container in leftovers:
        try:
            started_at = float(container.labels.get(SANDBOX_STARTED_LABEL, "0"))
        except ValueError:
            started_at = 0.0
        if started_at < stale_before:
            try:
                container.remove(force=True)
            except NotFound:
                pass  # removed by its own run in the meantime


def _build_images(client: docker.DockerClient) -> None:
    client.images.build(
        path=str(DOCKER_DIR), dockerfile=BASE_DOCKERFILE, tag=BASE_IMAGE_TAG, rm=True
    )
    client.images.build(path=str(LOGGER_BUILD_DIR), tag=LOGGER_IMAGE_TAG, rm=True)


def _ensure_network(client: docker.DockerClient) -> None:
    network = _find_network(client)
    if network is None:
        client.networks.create(
            NETWORK_NAME, driver="bridge", internal=True, labels=NETWORK_LABELS
        )
    elif not network.attrs.get("Internal"):
        raise SandboxEnvironmentError(
            f"The Docker network {NETWORK_NAME} exists but is not internal, so sandbox "
            "containers could reach the internet. Remove it and try again."
        )


def _ensure_logger(client: docker.DockerClient) -> None:
    """Start the logger (creating it if needed) and wait until it is healthy."""
    logger = _find_logger(client)
    if logger is None:
        logger = client.containers.run(
            LOGGER_IMAGE_TAG,
            name=LOGGER_NAME,
            detach=True,
            network=NETWORK_NAME,
            restart_policy={"Name": "unless-stopped"},
            log_config=LogConfig(type=LogConfig.types.JSON, config=LOGGER_LOG_OPTIONS),
            healthcheck=LOGGER_HEALTHCHECK,
        )
    elif logger.status != "running":
        logger.start()
    _wait_until_healthy(logger)


def _wait_until_healthy(logger: Container) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        logger.reload()
        if logger.status != "running":
            raise SandboxEnvironmentError(
                f"The connection logger stopped while starting (state: {logger.status})."
            )
        if logger.attrs["State"].get("Health", {}).get("Status") == "healthy":
            return
        time.sleep(READY_POLL_SECONDS)
    raise SandboxEnvironmentError(
        f"The connection logger was not healthy after {READY_TIMEOUT_SECONDS} seconds."
    )


def _remove_logger(client: docker.DockerClient) -> None:
    logger = _find_logger(client)
    if logger is not None:
        logger.remove(force=True)


def get_status() -> EnvironmentStatus:
    """Read-only view of what exists. Never creates anything."""
    client = get_docker_client()
    try:
        return _read_status(client)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not report the status: {exc}") from exc


def _read_status(client: docker.DockerClient) -> EnvironmentStatus:
    network = _find_network(client)
    logger = _find_logger(client)
    return EnvironmentStatus(
        base_image_present=_find_image_id(client, BASE_IMAGE_TAG) is not None,
        network_present=network is not None,
        network_internal=network is not None and bool(network.attrs.get("Internal")),
        logger_state=_logger_state(logger),
    )


def _logger_state(logger: Container | None) -> str:
    """"running" only if the logger is also healthy: a running but broken logger records nothing."""
    if logger is None:
        return "missing"
    if logger.status != "running":
        return logger.status
    health = logger.attrs["State"].get("Health", {}).get("Status")
    return "running" if health in (None, "healthy") else health


def teardown_environment() -> None:
    """Remove the logger container and the network. Images are kept."""
    client = get_docker_client()
    try:
        _remove_logger(client)
        network = _find_network(client)
        if network is not None:
            network.remove()
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not remove the sandbox: {exc}") from exc


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


def _running_logger(client: docker.DockerClient) -> Container:
    logger = _find_logger(client)
    if logger is None or logger.status != "running":
        raise SandboxEnvironmentError(
            "The connection logger is not running. "
            "Run: uv run python -m gatekeeper.sandbox.environment up"
        )
    return logger


def ca_certificate_archive() -> bytes:
    """Tar with etc/gatekeeper/ca.pem, for `container.put_archive("/", data)`."""
    client = get_docker_client()
    try:
        exit_code, certificate = _running_logger(client).exec_run(["cat", CA_SOURCE_PATH])
    except APIError as exc:
        raise SandboxEnvironmentError(f"Could not read the logger's CA certificate: {exc}") from exc
    if exit_code != 0 or not certificate:
        raise SandboxEnvironmentError("Could not read the logger's CA certificate.")
    return _tar_single_file("etc/gatekeeper/ca.pem", certificate, mode=0o644)


def _registry_filename(session_label: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_label) + ".json"


def register_tripwires(session_label: str, seed: str) -> None:
    """Tell the logger which tripwire values to watch for in this session."""
    from gatekeeper.sandbox.tripwires import registry_entry

    client = get_docker_client()
    archive = _tar_single_file(
        _registry_filename(session_label), registry_entry(session_label, seed), mode=0o644
    )
    try:
        copied = _running_logger(client).put_archive(REGISTRY_DIR, archive)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Could not register tripwires with the logger: {exc}") from exc
    if not copied:
        raise SandboxEnvironmentError("The logger did not accept the tripwire registry file.")


def unregister_tripwires(session_label: str) -> None:
    """Stop watching for this session's values. Does nothing if the logger is not running."""
    client = get_docker_client()
    try:
        logger = _find_logger(client)
        if logger is not None and logger.status == "running":
            logger.exec_run(["rm", "-f", f"{REGISTRY_DIR}/{_registry_filename(session_label)}"])
    except APIError as exc:
        raise SandboxEnvironmentError(f"Could not unregister tripwires: {exc}") from exc


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
    client = get_docker_client()
    try:
        output = _running_logger(client).logs(since=since_seconds, stdout=True, stderr=True)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Could not read the connection log: {exc}") from exc
    records = (_parse_log_line(line) for line in output.decode(errors="replace").splitlines())
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
