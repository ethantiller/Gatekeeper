"""Runs one command from an agent in a throwaway container and reports what it did."""

import os
import posixpath
import shlex
import subprocess
import tarfile
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import IO
from uuid import uuid4

from docker.api.client import APIClient
from docker.client import DockerClient
from docker.errors import APIError, ImageNotFound, NotFound
from docker.models.containers import Container

from gatekeeper.sandbox.environment import (
    EXIT_SUCCESS,
    LOGGER_NAME,
    LOGGER_PORT,
    NETWORK_NAME,
    SandboxEnvironmentError,
    base_image_tag,
    ca_certificate_archive,
    ensure_environment,
    get_docker_client,
    proxy_environment,
    read_connection_log,
    register_tripwires,
    sandbox_container_labels,
    unregister_tripwires,
)
from gatekeeper.sandbox.repo_images import (
    RepoChanges,
    RepoImageState,
    changes_since,
    ready_repo_image,
    repo_image_status,
)
from gatekeeper.sandbox.saved_changes import CaptureOutcome, capture_changes
from gatekeeper.sandbox.strace_log import (
    TRACED_CHANGE_SYSCALLS,
    TRACED_SYSCALLS,
    StraceFindings,
    parse_strace_log,
)
from gatekeeper.sandbox.tripwires import (
    AWS_CREDENTIALS_PATH,
    SANDBOX_GID,
    SANDBOX_UID,
    WORKSPACE_ENV_PATH,
    build_tripwire_archive,
    generate_tripwire_values,
)
from gatekeeper.server.types import SandboxReport, SandboxSession, StandardAction

WORKSPACE = "/workspace"
RUN_TIMEOUT_SECONDS = 30
KILL_GRACE_SECONDS = 2
HARD_DEADLINE_SECONDS = RUN_TIMEOUT_SECONDS + KILL_GRACE_SECONDS + 5
POLL_SECONDS = 0.02
ORPHAN_CHECK_AFTER_SECONDS = 1.0
ORPHAN_POLL_SECONDS = 0.25
ORPHAN_GRACE_SECONDS = 3.0  # strace may still be writing a big trace after the command ends
OUTPUT_TAIL_BYTES = 4096
REDACTION_MARGIN_BYTES = 128  # read a little extra so a secret cut by the tail is still redacted
MAX_FILE_SIZE_KIB = 262144  # per file the command writes; stops one command filling the disk
CPU_LIMIT_NANO_CPUS = 1_000_000_000
MEMORY_LIMIT = "1g"
PIDS_LIMIT = 256
STRACE_LOG_PATH = "/tmp/gk-strace.log"
INODE_PATH = "/tmp/gk-strace-inode"  # which file strace was given, to notice a swap
STRACE_TEXT_MAX_BYTES = 32 * 1024**2  # most trace lines read back; the rest is counted, not read
EXIT_CODE_PATH = "/tmp/gk-exit"
STDOUT_PATH = "/tmp/gk-stdout"
STDERR_PATH = "/tmp/gk-stderr"
UNTRACKED_TAG = b"?"  # `git ls-files -t` marks untracked files with ?
DISK_LIMIT_BYTES = 2 * 1024**3  # what the command may add to the container's writable layer
DISK_CHECK_SECONDS = 1.0
# PID 1 (`sleep infinity`) ignores SIGKILL from inside its own namespace, so the container survives.
KILL_ALL_COMMAND = ["sh", "-c", "kill -9 -1"]
SETUP_WORKERS = 5
LOGGER_SETTLE_POLL_SECONDS = 0.25
LOGGER_SETTLE_MAX_SECONDS = 2.0
KILLED_EXIT_CODES = (124, 137)  # `timeout` stopped the command, or had to force-kill it

DIFF_ADDED = 1
DIFF_DELETED = 2

TRIPWIRE_PATHS = (WORKSPACE_ENV_PATH, AWS_CREDENTIALS_PATH)
SYSTEM_PROGRAM_DIRECTORIES = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin")
# Redirect targets and the like (`> /dev/null`) are not host files the command could damage.
NOISE_HOST_PREFIXES = ("/dev/", "/proc/", "/sys/")

# The agent's command comes in through $GK_COMMAND so it never needs shell quoting. `timeout`
# is outside `strace` because strace waits for background processes the command leaves behind;
# the exit status goes to a file because that is the only reliable sign the command finished.
COMMAND_VARIABLE = "GK_COMMAND"
_INNER_SCRIPT = (
    f"stat -c %i {STRACE_LOG_PATH} >{INODE_PATH}; "
    f'ulimit -f {MAX_FILE_SIZE_KIB}; bash -c "${COMMAND_VARIABLE}"; '
    f"status=$?; echo $status >{EXIT_CODE_PATH}; exit $status"  # strace then reports the same code
)
WRAPPER_SCRIPT = (
    f"timeout --kill-after={KILL_GRACE_SECONDS} {RUN_TIMEOUT_SECONDS} "
    f"strace -f -y -e trace={TRACED_SYSCALLS} -o {STRACE_LOG_PATH} "
    f"bash -c '{_INNER_SCRIPT}' >{STDOUT_PATH} 2>{STDERR_PATH}"
)


def run(action: StandardAction, session: SandboxSession) -> SandboxReport:
    """Run the action's command in a container and report. Sandbox failures go in report.error."""
    if not action.command:
        return SandboxReport(image=base_image_tag(), error="The action has no command to run.")
    try:
        return _run_in_container(action, action.command, session)
    except SandboxEnvironmentError as exc:
        return SandboxReport(image=base_image_tag(), error=str(exc))


def _choose_image(
    repo_root: Path, warnings: list[str], untracked: list[str]
) -> tuple[str, RepoChanges | None]:
    """The repo image plus what changed since it was built, else the base image and no changes."""
    repo_image = ready_repo_image(repo_root)
    if repo_image is None:
        status = repo_image_status(repo_root)
        if status.state is RepoImageState.FAILED:
            warnings.append(
                f"The repo image build failed ({status.detail}); ran on the base image "
                "without the repo's dependencies."
            )
        elif status.state is RepoImageState.BUILDING:
            warnings.append("The repo image is still building; ran without the repo's dependencies.")
        elif status.detail:
            warnings.append("No repo image has been built yet; ran without the repo's dependencies.")
        return base_image_tag(), None
    changes = changes_since(repo_root, repo_image.commit, untracked)
    if changes is None:
        warnings.append("git no longer has the repo image's commit; ran on the base image.")
        return base_image_tag(), None
    return repo_image.tag, changes


def _container_workdir(cwd: str, repo_root: Path, warnings: list[str]) -> str:
    """Where in the container the command starts: the folder the agent was in, inside the repo."""
    try:
        relative = Path(cwd).resolve().relative_to(repo_root.resolve())
    except ValueError:
        warnings.append(f"The command's folder {cwd} is outside the repo; ran from the repo root.")
        return WORKSPACE
    return posixpath.normpath(posixpath.join(WORKSPACE, relative.as_posix()))


def _existing_workdir(container: Container, workdir: str, warnings: list[str]) -> str:
    missing = container.exec_run(["test", "-d", workdir]).exit_code != EXIT_SUCCESS
    if workdir != WORKSPACE and missing:
        warnings.append(f"{workdir} is not in the sandbox; ran from the repo root.")
        return WORKSPACE
    return workdir


def _run_in_container(
    action: StandardAction, command: str, session: SandboxSession
) -> SandboxReport:
    ensure_environment()
    warnings: list[str] = []
    repo_files = _list_repo_files(session.repo_root)
    image, changes = _choose_image(session.repo_root, warnings, repo_files.untracked)
    workdir = _container_workdir(action.cwd, session.repo_root, warnings)
    warnings += _host_path_warnings(command, Path(action.cwd), session.repo_root, repo_files.paths)
    client = get_docker_client()
    started_at = time.time()

    # One label per run: two runs of the same session must not unregister each other's values.
    run_label = f"{session.session_id}-{uuid4().hex[:8]}"
    resources = _RunResources()
    try:
        # The logger must know the fake values before the command can send them anywhere.
        _set_up(resources, client, image, session, run_label, repo_files.paths, changes)
        sandbox_container = resources.container
        sandbox_container.start()
        client_ip = _container_ip(sandbox_container)
        proxy_address = (_logger_ip(client), LOGGER_PORT)
        if changes is not None:
            _delete_removed_files(sandbox_container, changes.deleted_paths)
        workdir = _existing_workdir(sandbox_container, workdir, warnings)
        observation = _observe_run(client, sandbox_container, command, workdir)
        saved = capture_changes(
            sandbox_container,
            WORKSPACE,
            session.repo_root,
            written_paths=observation.files_created + observation.files_modified,
            deleted_paths=observation.files_deleted,
            secret_values=list(generate_tripwire_values(session.tripwire_seed).values()),
        )
        # Read while the values are still registered: late events can still be scanned.
        records = _read_settled_log(started_at, client_ip, observation.strace_log, warnings)
    except ImageNotFound as exc:
        raise SandboxEnvironmentError(f"The sandbox image {image} is missing: {exc}") from exc
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker failed while running the command: {exc}") from exc
    finally:
        _release(resources, run_label)

    return _build_report(
        _RunEvidence(
            image=image,
            observation=observation,
            findings=parse_strace_log(observation.strace_log, {proxy_address}),
            records=records,
            run_label=run_label,
            tripwire_seed=session.tripwire_seed,
            saved=saved,
            warnings=warnings,
        )
    )


@dataclass
class _RunResources:
    """What a run created, so cleanup can release it even if setup stopped half way."""

    container: Container | None = None
    archives: list[IO[bytes] | bytes] = field(default_factory=list)


def _set_up(
    resources: _RunResources,
    client: DockerClient,
    image: str,
    session: SandboxSession,
    run_label: str,
    repo_file_paths: list[str],
    changes: RepoChanges | None,
) -> None:
    """Create the container, build the three tars and register the tripwires at the same time,
    then copy the tars in. With a repo image only the files changed since it was built are copied.
    """
    copied_paths = repo_file_paths if changes is None else changes.changed_paths
    with ThreadPoolExecutor(max_workers=SETUP_WORKERS) as pool:
        container_future = pool.submit(_create_container, client, image)
        register_future = pool.submit(register_tripwires, run_label, session.tripwire_seed)
        repo_future = pool.submit(_build_repo_copy_archive, session.repo_root, copied_paths)
        # A repo that ships its own .env must not be overwritten by the planted one.
        secrets_future = pool.submit(
            build_tripwire_archive, session.tripwire_seed, skip_workspace_env=".env" in repo_file_paths
        )
        ca_future = pool.submit(ca_certificate_archive)
    # Everything has finished. Record what succeeded before raising, so cleanup can release it.
    if container_future.exception() is None:
        resources.container = container_future.result()
    for archive_future in (repo_future, secrets_future, ca_future):
        if archive_future.exception() is None:
            resources.archives.append(archive_future.result())
    for future in (container_future, register_future, repo_future, secrets_future, ca_future):
        future.result()  # raises the first failure
    _copy_into_container(container_future.result(), resources.archives)


def _release(resources: _RunResources, run_label: str) -> None:
    """Unregister the tripwires, remove the container and close the temp files; each step runs
    even if an earlier one fails."""
    try:
        unregister_tripwires(run_label)
    finally:
        try:
            if resources.container is not None:
                _remove_container(resources.container)
        finally:
            for archive in resources.archives:
                if not isinstance(archive, bytes):
                    archive.close()


def _read_settled_log(
    started_at: float, client_ip: str, strace_log: str, warnings: list[str]
) -> list[dict]:
    """Connection records for this run. A dead logger gives a partial report plus a warning.

    The logger can write a late event (such as a failed TLS handshake) after the command has
    ended, so when the command connected anywhere this waits for the record count to stop growing.
    """
    try:
        records = read_connection_log(started_at, client_ip=client_ip)
        if "connect(" not in strace_log:
            return records
        deadline = time.monotonic() + LOGGER_SETTLE_MAX_SECONDS
        while time.monotonic() < deadline:
            time.sleep(LOGGER_SETTLE_POLL_SECONDS)
            latest = read_connection_log(started_at, client_ip=client_ip)
            if len(latest) == len(records):
                return latest
            records = latest
        return records
    except SandboxEnvironmentError as exc:
        warnings.append(
            f"The connection log could not be read, so hosts contacted and secrets sent are "
            f"unknown: {exc}"
        )
        return []


def _copy_into_container(container: Container, archives: list[IO[bytes] | bytes]) -> None:
    for archive in archives:
        if not container.put_archive("/", archive):
            raise SandboxEnvironmentError("Docker did not accept files copied into the sandbox.")


def _container_ip(container: Container) -> str:
    """The container's address on the sandbox network. Only available while it is running."""
    container.reload()
    return container.attrs["NetworkSettings"]["Networks"][NETWORK_NAME]["IPAddress"]


def _logger_ip(client: DockerClient) -> str:
    return _container_ip(client.containers.get(LOGGER_NAME))


def _delete_removed_files(container: Container, deleted_paths: list[str]) -> None:
    """Remove files the repo image still has but the working tree deleted."""
    if deleted_paths:
        _run_checked(container, ["rm", "-rf", "--", *(f"{WORKSPACE}/{path}" for path in deleted_paths)])


@dataclass(frozen=True)
class _CommandResult:
    exit_code: int | None  # None if the command never finished
    timed_out: bool
    ended_abnormally: bool  # no exit status recorded, but not a timeout (killed, or strace failed)
    left_processes: bool  # the command finished but background processes were still running
    disk_limit_hit: bool = False  # stopped for writing more than DISK_LIMIT_BYTES
    tracer_stopped: bool = False  # strace ended before the command did (it was probably killed)


@dataclass(frozen=True)
class _RunObservation:
    """Everything measured inside the container while the command ran."""

    result: _CommandResult
    stdout: bytes
    stderr: bytes
    duration_ms: int
    files_created: list[str]
    files_modified: list[str]
    files_deleted: list[str]
    strace_log: str  # only the lines that matter (see _read_strace_text), not the whole trace
    strace_truncated: bool
    evidence_problems: list[str]


@dataclass(frozen=True)
class _RunEvidence:
    """Everything the report is built from."""

    image: str
    observation: _RunObservation
    findings: StraceFindings
    records: list[dict]
    run_label: str
    tripwire_seed: str
    saved: CaptureOutcome
    warnings: list[str]


def _observe_run(
    client: DockerClient, container: Container, command: str, workdir: str
) -> _RunObservation:
    """Run the command under strace and collect the file changes around it."""
    files_before = _workspace_diff(container)
    # The container's clock, not a file the command could touch: ctime cannot be set by a user.
    started_epoch = _run_checked(container, ["date", "+%s.%N"]).decode().strip()

    start = time.monotonic()
    result = _exec_traced(client, container, command, workdir)
    duration_ms = int((time.monotonic() - start) * 1000)

    files_after = _workspace_diff(container)
    added_before = _paths_of_kind(files_before, DIFF_ADDED)
    added_after = _paths_of_kind(files_after, DIFF_ADDED)
    deleted_before = _paths_of_kind(files_before, DIFF_DELETED)
    deleted_after = _paths_of_kind(files_after, DIFF_DELETED)
    files_created = sorted(added_after - added_before)
    tail_bytes = OUTPUT_TAIL_BYTES + REDACTION_MARGIN_BYTES
    strace_log, strace_truncated = _read_strace_text(container)
    return _RunObservation(
        result=result,
        stdout=_read_tail(container, STDOUT_PATH, tail_bytes),
        stderr=_read_tail(container, STDERR_PATH, tail_bytes),
        duration_ms=duration_ms,
        files_created=files_created,
        files_modified=_modified_files(container, set(files_created), started_epoch),
        files_deleted=sorted((added_before - added_after) | (deleted_after - deleted_before)),
        strace_log=strace_log,
        strace_truncated=strace_truncated,
        evidence_problems=_evidence_problems(container),
    )


def _build_report(evidence: _RunEvidence) -> SandboxReport:
    observation = evidence.observation
    result = observation.result
    findings = evidence.findings
    direct = [f"{address} (not via the proxy)" for address in findings.direct_connections]
    return SandboxReport(
        image=evidence.image,
        exit_code=None if result.timed_out else result.exit_code,
        timed_out=result.timed_out,
        duration_ms=observation.duration_ms,
        stdout_tail=_tail(observation.stdout, evidence.tripwire_seed),
        stderr_tail=_tail(observation.stderr, evidence.tripwire_seed),
        files_created=observation.files_created,
        files_modified=observation.files_modified,
        files_deleted=observation.files_deleted,
        network_attempts=_hosts(evidence.records) + direct,
        tripwires_triggered=_tripwire_hits(findings, evidence.records, evidence.run_label),
        saved_changes_id=evidence.saved.change_id,
        notes=evidence.warnings + _run_warnings(evidence),
    )


def _run_warnings(evidence: _RunEvidence) -> list[str]:
    """Things the file and host lists cannot show, so the reader does not assume a clean run."""
    result = evidence.observation.result
    findings = evidence.findings
    warnings = []
    if result.left_processes:
        warnings.append("Background processes were still running when the command finished.")
    if result.ended_abnormally:
        warnings.append("The command ended without recording an exit status (it was killed).")
    warnings += evidence.observation.evidence_problems
    if evidence.observation.strace_truncated:
        warnings.append(
            f"The trace was larger than {STRACE_TEXT_MAX_BYTES // 1024**2} MiB, so later file "
            "changes and connections may be missing from this report."
        )
    if result.tracer_stopped:
        warnings.append(
            "strace stopped before the command ended (it was probably killed), so later file "
            "and network activity is unknown."
        )
    if result.disk_limit_hit:
        warnings.append(
            f"The command was stopped after writing more than {DISK_LIMIT_BYTES // 1024**2} MiB."
        )
    if findings.outside_writes:
        warnings.append(
            "Changed files outside the repo, which the file lists do not show: "
            + ", ".join(findings.outside_writes)
        )
    if findings.failed_changes:
        warnings.append(
            "Tried to change paths that do not exist in the sandbox (the host may have them): "
            + ", ".join(findings.failed_changes)
        )
    if findings.direct_connections:
        warnings.append("Connected to addresses without going through the logging proxy.")
    # Through the proxy, DNS is only used to find the proxy itself, so that alone proves nothing.
    if findings.used_dns and not findings.used_proxy:
        warnings.append("Looked up a hostname without going through the proxy, so the name was not logged.")
    if evidence.saved.skipped_reason:
        warnings.append(f"The changes were not saved: {evidence.saved.skipped_reason}.")
    return warnings


@dataclass(frozen=True)
class _RepoFiles:
    paths: list[str]  # tracked and untracked files that are not gitignored
    untracked: list[str]  # the untracked ones among them


def _list_repo_files(repo_root: Path) -> _RepoFiles:
    """The repo's files relative to its root, from one git call (-t tags tracked and untracked)."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z", "-t", "--cached", "--others", "--exclude-standard"],
            cwd=repo_root, capture_output=True, check=False,
        )
    except FileNotFoundError as exc:
        raise SandboxEnvironmentError("The git command was not found.") from exc
    if result.returncode != EXIT_SUCCESS:
        raise SandboxEnvironmentError(f"{repo_root} is not a git repository, so it cannot be copied.")
    paths: list[str] = []
    untracked: list[str] = []
    for entry in result.stdout.split(b"\0"):
        # Each entry is "<tag> <path>"; fsdecode, not decode: a file name need not be UTF-8.
        tag, _, name_bytes = entry.partition(b" ")
        name = os.fsdecode(name_bytes)
        if name and (repo_root / name).is_file():
            paths.append(name)
            if tag == UNTRACKED_TAG:
                untracked.append(name)
    return _RepoFiles(paths=paths, untracked=untracked)


def _host_path_warnings(
    command: str, cwd: Path, repo_root: Path, repo_file_paths: list[str]
) -> list[str]:
    """Warn about paths in the command that the sandbox does not have, so "no change" is not trusted.

    The sandbox holds only the repo's non-ignored files, so a command aimed at an ignored folder
    or at a path outside the repo looks harmless there.
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return []
    root = repo_root.resolve()
    warnings = []
    for token in tokens:
        if token.startswith("-"):
            continue
        path = Path(os.path.expanduser(token))
        path = path if path.is_absolute() else cwd / path
        if not path.exists():
            continue
        resolved = path.resolve()
        try:
            relative = resolved.relative_to(root).as_posix()
        except ValueError:
            if not str(resolved).startswith(SYSTEM_PROGRAM_DIRECTORIES + NOISE_HOST_PREFIXES):
                warnings.append(
                    f"{token} is a host path outside the repo; the sandbox has no copy of it, "
                    "so what the command does to it is not shown."
                )
            continue
        in_sandbox = relative == "." or any(
            file == relative or file.startswith(f"{relative}/") for file in repo_file_paths
        )
        if not in_sandbox:
            warnings.append(
                f"{token} exists on the host but is not copied into the sandbox (gitignored), "
                "so what the command does to it is not shown."
            )
    return list(dict.fromkeys(warnings))


def _owned_by_sandbox(info: tarfile.TarInfo) -> tarfile.TarInfo:
    info.uid = SANDBOX_UID
    info.gid = SANDBOX_GID
    return info


def _build_repo_copy_archive(repo_root: Path, repo_file_paths: list[str]) -> IO[bytes]:
    """Tar of the repo under workspace/.

    Parent directories get explicit entries owned by the sandbox user; otherwise Docker would
    create them as root and the command could not delete or write inside them. The tar goes to a
    temp file (closed by `_release`) so a large repo is never held in memory.
    """
    directories = set()
    for name in repo_file_paths:
        for parent in Path(name).parents:
            if parent != Path("."):
                directories.add(parent.as_posix())
    buffer = tempfile.TemporaryFile()  # noqa: SIM115 - the run's cleanup closes it
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for directory in sorted(directories):
            info = tarfile.TarInfo(f"workspace/{directory}")
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            archive.addfile(_owned_by_sandbox(info))
        for name in repo_file_paths:
            try:
                archive.add(repo_root / name, arcname=f"workspace/{name}", filter=_owned_by_sandbox)
            except OSError as exc:
                raise SandboxEnvironmentError(
                    f"Could not read {name} to copy it into the sandbox: {exc}"
                ) from exc
    buffer.seek(0)
    return buffer


def _create_container(client: DockerClient, image: str) -> Container:
    """Create (not start) a locked-down container on the internet-less network."""
    return client.containers.create(
        image,
        network=NETWORK_NAME,  # without this the container would get internet access
        environment=proxy_environment(),
        cap_drop=["ALL"],
        security_opt=["no-new-privileges"],
        nano_cpus=CPU_LIMIT_NANO_CPUS,
        mem_limit=MEMORY_LIMIT,
        memswap_limit=MEMORY_LIMIT,
        pids_limit=PIDS_LIMIT,
        labels=sandbox_container_labels(),  # lets ensure_environment reap it after a crash
    )


def _exec_traced(
    client: DockerClient, container: Container, command: str, workdir: str
) -> _CommandResult:
    """Run the command under strace, with its output going to files inside the container.

    The wrapper can outlive the command (strace waits for background processes), so completion
    is judged by the exit status file, and the wait has a hard deadline.
    """
    api = client.api
    exec_id = api.exec_create(
        container.id,
        ["sh", "-c", WRAPPER_SCRIPT],
        workdir=workdir,
        environment={COMMAND_VARIABLE: command},
    )["Id"]
    api.exec_start(exec_id, detach=True)

    started = time.monotonic()
    wrapper_exit_code: int | None = None
    left_processes = False
    hit_deadline = False
    next_disk_check = DISK_CHECK_SECONDS
    while True:
        elapsed = time.monotonic() - started
        info = api.exec_inspect(exec_id)
        if not info["Running"]:
            wrapper_exit_code = info["ExitCode"]
            break
        if elapsed >= HARD_DEADLINE_SECONDS:
            hit_deadline = True
            break
        if elapsed >= next_disk_check:
            next_disk_check = elapsed + DISK_CHECK_SECONDS
            if _writable_layer_bytes(client, container) > DISK_LIMIT_BYTES:
                container.exec_run(KILL_ALL_COMMAND)
                return _CommandResult(None, False, False, False, disk_limit_hit=True)
        if elapsed >= ORPHAN_CHECK_AFTER_SECONDS and _read_exit_code(container) is not None:
            wrapper_exit_code = _wait_for_wrapper(api, exec_id)
            left_processes = wrapper_exit_code is None
            break
        time.sleep(POLL_SECONDS if elapsed < ORPHAN_CHECK_AFTER_SECONDS else ORPHAN_POLL_SECONDS)

    command_exit_code = _read_exit_code(container)
    if left_processes or command_exit_code is None:
        # strace detaches from its tracees when it is stopped, so nothing else ends them, and the
        # snapshot taken next must not race with a command that is still changing files.
        container.exec_run(KILL_ALL_COMMAND)
    if command_exit_code is not None:
        # strace passes the command's exit code through, so any other code means strace stopped.
        tracer_stopped = wrapper_exit_code is not None and wrapper_exit_code != command_exit_code
        return _CommandResult(
            command_exit_code, False, False, left_processes, tracer_stopped=tracer_stopped
        )
    killed = wrapper_exit_code in KILLED_EXIT_CODES and elapsed >= RUN_TIMEOUT_SECONDS
    timed_out = hit_deadline or killed
    return _CommandResult(
        exit_code=None if timed_out else wrapper_exit_code,
        timed_out=timed_out,
        ended_abnormally=not timed_out,
        left_processes=False,
    )


def _wait_for_wrapper(api: APIClient, exec_id: str) -> int | None:
    """The wrapper's exit code once it ends, or None if it is still running after the grace."""
    deadline = time.monotonic() + ORPHAN_GRACE_SECONDS
    while time.monotonic() < deadline:
        info = api.exec_inspect(exec_id)
        if not info["Running"]:
            return info["ExitCode"]
        time.sleep(POLL_SECONDS)
    return None


def _writable_layer_bytes(client: DockerClient, container: Container) -> int:
    """How much the container has written so far, as Docker measures its writable layer."""
    rows = client.api.containers(all=True, size=True, filters={"id": container.id})
    return int(rows[0].get("SizeRw") or 0) if rows else 0


def _read_exit_code(container: Container) -> int | None:
    """The command's own exit status, written when it finished. None while it is still running."""
    result = container.exec_run(["cat", EXIT_CODE_PATH])
    if result.exit_code != EXIT_SUCCESS:
        return None
    try:
        return int(result.output.strip())
    except ValueError:
        return None


def _read_tail(container: Container, path: str, byte_count: int | None) -> bytes:
    """Last `byte_count` bytes of a file in the container (all of it for None); empty if missing."""
    command = ["cat", path] if byte_count is None else ["tail", "-c", str(byte_count), path]
    result = container.exec_run(command)
    return result.output if result.exit_code == EXIT_SUCCESS else b""


def _read_strace_text(container: Container) -> tuple[str, bool]:
    """The trace lines that matter, read inside the container so a huge trace is never loaded.

    Lines for the tripwire files always come first, so flooding the trace cannot push them out.
    The second filter (connections and anything that changes a file) is capped; the flag says
    whether the cap cut it off.
    """
    tripwire_filter = " ".join(f"-e '<{path}>'" for path in TRIPWIRE_PATHS)
    relevant = "connect\\(|O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND|" + "|".join(TRACED_CHANGE_SYSCALLS)
    script = (
        f"grep -a -F {tripwire_filter} {STRACE_LOG_PATH}; "
        f"grep -a -E '{relevant}' {STRACE_LOG_PATH} | head -c {STRACE_TEXT_MAX_BYTES}"
    )
    result = container.exec_run(["sh", "-c", f"({script}) 2>/dev/null"])
    return result.output.decode(errors="replace"), len(result.output) >= STRACE_TEXT_MAX_BYTES


def _evidence_problems(container: Container) -> list[str]:
    """Notes for anything that suggests the command tampered with the trace.

    The command runs as the same user as strace, so it can delete, replace or overwrite the trace
    file or kill strace; this cannot be prevented here, but it can be noticed.
    """
    problems = []
    baseline = _read_tail(container, INODE_PATH, None).strip()
    current = container.exec_run(["stat", "-c", "%i", STRACE_LOG_PATH])
    if not baseline:
        problems.append("The trace's starting state was not recorded, so the trace cannot be trusted.")
    elif current.exit_code != EXIT_SUCCESS:
        problems.append("The command deleted the trace file, so its file and network activity is unknown.")
    elif current.output.strip() != baseline:
        problems.append("The command replaced the trace file, so its file and network activity is unknown.")
    elif container.exec_run(["grep", "-q", "-a", "-P", "\\x00", STRACE_LOG_PATH]).exit_code == EXIT_SUCCESS:
        problems.append("The command overwrote part of the trace file, so its activity may be hidden.")
    return problems


def _run_checked(container: Container, command: list[str]) -> bytes:
    """Run a helper command inside the container; a failure is a sandbox failure."""
    result = container.exec_run(command)
    if result.exit_code != EXIT_SUCCESS:
        raise SandboxEnvironmentError(f"`{' '.join(command)}` failed inside the sandbox.")
    return result.output


def _workspace_diff(container: Container) -> dict[str, int]:
    """Path -> change kind from container.diff(), files and folders under /workspace."""
    changes = container.diff() or []
    workspace_changes = {}
    for change in changes:
        if change["Path"].startswith(f"{WORKSPACE}/"):
            workspace_changes[change["Path"]] = change["Kind"]
    return workspace_changes


def _paths_of_kind(changes: dict[str, int], kind: int) -> set[str]:
    return {path for path, path_kind in changes.items() if path_kind == kind}


def _modified_files(
    container: Container, created_paths: set[str], started_epoch: str
) -> list[str]:
    """Files changed since the run started that the command did not create.

    The diff cannot see these for copied files (they are all 'added'). The change time is used,
    not the modification time: a command can set mtime to anything (`touch -r`, `cp -p`), but
    only the kernel sets ctime.
    """
    output = _run_checked(
        container, ["find", WORKSPACE, "-type", "f", "-newerct", f"@{started_epoch}"]
    ).decode(errors="replace")
    return sorted(set(output.splitlines()) - created_paths)


def _remove_container(container: Container) -> None:
    try:
        container.remove(force=True)
    except NotFound:
        pass  # already gone
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not remove the sandbox container: {exc}") from exc


def _hosts(records: list[dict]) -> list[str]:
    """Hosts the command tried to reach, in first-seen order."""
    hosts = (record.get("host") for record in records)
    return list(dict.fromkeys(host for host in hosts if host))


def _tripwire_hits(findings: StraceFindings, records: list[dict], run_label: str) -> list[str]:
    """Names only, never the secret values."""
    hits = [f"read {path}" for path in findings.opened_paths if path in TRIPWIRE_PATHS]
    for record in records:
        for hit in record.get("tripwire_hits", []):
            if hit.get("session_id") == run_label:
                hits.append(f"sent {hit['name']} in {hit['location']} to {record.get('host')}")
    return list(dict.fromkeys(hits))


def _redact(text: str, tripwire_seed: str) -> str:
    """Replace this session's fake secret values: they must never end up in reports or logs."""
    for name, value in generate_tripwire_values(tripwire_seed).items():
        text = text.replace(value, f"[tripwire {name}]")
    return text


def _tail(data: bytes, tripwire_seed: str) -> str:
    redacted = _redact(data.decode(errors="replace"), tripwire_seed)
    return redacted[-OUTPUT_TAIL_BYTES:]
