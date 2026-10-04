"""Builds and caches one image per repo, with its dependencies installed from the lockfiles.

The image is built from the repo as of its latest commit plus the lockfiles in the working tree.
A run starts from it and copies in only what changed since that commit (see `changes_since`).
"""

import hashlib
import io
import subprocess
import tarfile
import tempfile
import threading
import time
from contextlib import closing
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import IO

import requests
from docker.client import DockerClient
from docker.errors import APIError, ImageNotFound
from docker.models.images import Image
from urllib3.exceptions import HTTPError

from gatekeeper.sandbox.environment import (
    SandboxEnvironmentError,
    base_image_tag,
    ensure_environment,
    get_docker_client,
)

REPO_IMAGE_REPOSITORY = "gatekeeper-repo"
COMMIT_LABEL = "com.gatekeeper.commit"
REPO_LABEL = "com.gatekeeper.repo"  # the repo path, so superseded images of one repo can be found
TAG_HASH_LENGTH = 16
SANDBOX_USER = "sandbox_user"
BUILD_TIMEOUT_SECONDS = 15 * 60
BUILD_IDLE_TIMEOUT_SECONDS = 5 * 60  # a build that prints nothing for this long is stuck
ARCHIVE_PREFIX = "repo/"
DOCKER_CONFLICT_STATUS = 409  # the image is still used by a container
GIT_ATTRIBUTE_FIELDS = 3  # path, attribute, value per `git check-attr -z` entry

# The build has network access and runs outside the sandbox, so installs must not run the
# repo's own scripts (npm postinstall, sdist builds and the like). Each group is one ecosystem;
# the first lockfile found in a group wins, and every group with a lockfile gets installed.
INSTALL_GROUPS: tuple[tuple[tuple[str, str], ...], ...] = (
    (
        ("package-lock.json", "npm ci --ignore-scripts"),
        ("pnpm-lock.yaml", "corepack pnpm install --frozen-lockfile --ignore-scripts"),
    ),
    (
        ("uv.lock", "uv sync --frozen --no-install-project --no-build"),
        ("requirements.txt", "uv venv && uv pip install --no-build -r requirements.txt"),
    ),
)


class RepoImageState(StrEnum):
    NONE = "none"  # no commit or no supported lockfile: runs use the base image
    BUILDING = "building"
    READY = "ready"
    FAILED = "failed"


@dataclass(frozen=True)
class RepoImageStatus:
    state: RepoImageState
    detail: str | None = None  # the build error when state is FAILED


@dataclass(frozen=True)
class RepoImage:
    tag: str
    commit: str  # the commit the image was built from


@dataclass(frozen=True)
class RepoChanges:
    """What differs between the image's commit and the working tree, relative to the repo root."""

    changed_paths: list[str]  # modified or new files to copy in
    deleted_paths: list[str]  # files to remove from the container


@dataclass(frozen=True)
class _BuildPlan:
    commit: str
    tag: str
    lockfiles: tuple[tuple[str, bytes], ...]  # working-tree name and content
    install_commands: tuple[str, ...]


_build_lock = threading.Lock()
_active_builds: set[str] = set()
_failed_builds: dict[str, str] = {}


def _run_git(
    repo_root: Path, *args: str, input_bytes: bytes | None = None
) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo_root), *args],
            input=input_bytes, capture_output=True, check=False,
        )
    except FileNotFoundError as exc:
        raise SandboxEnvironmentError("The git command was not found.") from exc


def _git(repo_root: Path, *args: str, input_bytes: bytes | None = None) -> bytes:
    result = _run_git(repo_root, *args, input_bytes=input_bytes)
    if result.returncode != 0:
        error_text = result.stderr.decode(errors="replace").strip()
        raise SandboxEnvironmentError(f"`git {' '.join(args)}` failed: {error_text}")
    return result.stdout


def _read_lockfile(repo_root: Path, name: str) -> bytes | None:
    path = repo_root / name
    if path.is_symlink() or not path.is_file():
        return None
    try:
        return path.read_bytes()
    except OSError as exc:
        raise SandboxEnvironmentError(f"Could not read {path}: {exc}") from exc


def _build_plan(repo_root: Path) -> _BuildPlan | None:
    """What to build for the latest commit, or None if there is nothing to build.

    Lockfiles come from the working tree, so an uncommitted lockfile change gets its own image
    instead of running against dependencies from the old one.
    """
    head = _run_git(repo_root, "rev-parse", "HEAD")
    if head.returncode != 0:
        return None
    commit = head.stdout.decode().strip()
    lockfiles: list[tuple[str, bytes]] = []
    install_commands: list[str] = []
    for group in INSTALL_GROUPS:
        for lockfile, install_command in group:
            content = _read_lockfile(repo_root, lockfile)
            if content is not None:
                lockfiles.append((lockfile, content))
                install_commands.append(install_command)
                break
    if not lockfiles:
        return None
    # The repo path is part of the hash: two repos can share a lockfile but not source.
    digest = hashlib.sha256(str(repo_root).encode() + b"\0" + commit.encode())
    for (name, content), install_command in zip(lockfiles, install_commands, strict=True):
        digest.update(b"\0" + name.encode() + b"\0" + install_command.encode() + b"\0" + content)
    tag = f"{REPO_IMAGE_REPOSITORY}:{digest.hexdigest()[:TAG_HASH_LENGTH]}"
    return _BuildPlan(commit, tag, tuple(lockfiles), tuple(install_commands))


def _dockerfile(install_commands: tuple[str, ...]) -> bytes:
    lines = [
        f"FROM {base_image_tag()}",
        f"COPY --chown={SANDBOX_USER}:{SANDBOX_USER} {ARCHIVE_PREFIX} ./",
        *(f"RUN {command}" for command in install_commands),
    ]
    return ("\n".join(lines) + "\n").encode()


def _archive_gaps(repo_root: Path) -> list[str]:
    """Tracked files `git archive` leaves out or only stubs: export-ignore, submodules, LFS.

    They are added to the build from the working tree. If one was edited since the commit, the
    edit shows up in `changes_since` and is copied at run time anyway.
    """
    tracked = _git(repo_root, "ls-files", "-z").split(b"\0")
    with_submodules = _git(repo_root, "ls-files", "-z", "--recurse-submodules").split(b"\0")
    gaps = set(with_submodules) - set(tracked)
    attributes = _git(
        repo_root, "check-attr", "-z", "--stdin", "export-ignore", "filter",
        input_bytes=b"\0".join(name for name in tracked if name) + b"\0",
    ).split(b"\0")
    for index in range(0, len(attributes) - GIT_ATTRIBUTE_FIELDS + 1, GIT_ATTRIBUTE_FIELDS):
        path, attribute, value = attributes[index:index + GIT_ATTRIBUTE_FIELDS]
        if (attribute, value) in ((b"export-ignore", b"set"), (b"filter", b"lfs")):
            gaps.add(path)
    return sorted(name.decode() for name in gaps if name)


def _build_context(repo_root: Path, plan: _BuildPlan) -> IO[bytes]:
    """Temp-file tar: the Dockerfile, the repo at the commit under repo/, then lockfiles and gaps.

    Appended entries come later in the tar, so they win over what `git archive` wrote.
    """
    context = tempfile.TemporaryFile()  # noqa: SIM115 - the caller closes it
    try:
        archived = subprocess.run(
            ["git", "-C", str(repo_root), "archive", "--format=tar",
             f"--prefix={ARCHIVE_PREFIX}", plan.commit],
            stdout=context, stderr=subprocess.PIPE, check=False,
        )
    except FileNotFoundError as exc:
        context.close()
        raise SandboxEnvironmentError("The git command was not found.") from exc
    if archived.returncode != 0:
        context.close()
        error_text = archived.stderr.decode(errors="replace").strip()
        raise SandboxEnvironmentError(f"`git archive` failed: {error_text}")
    context.seek(0)
    with tarfile.open(fileobj=context, mode="a") as archive:
        dockerfile = _dockerfile(plan.install_commands)
        dockerfile_info = tarfile.TarInfo("Dockerfile")
        dockerfile_info.size = len(dockerfile)
        archive.addfile(dockerfile_info, io.BytesIO(dockerfile))
        for name, content in plan.lockfiles:
            lockfile_info = tarfile.TarInfo(f"{ARCHIVE_PREFIX}{name}")
            lockfile_info.size = len(content)
            archive.addfile(lockfile_info, io.BytesIO(content))
        for name in _archive_gaps(repo_root):
            source = repo_root / name
            if source.is_file() or source.is_symlink():
                archive.add(source, arcname=f"{ARCHIVE_PREFIX}{name}", recursive=False)
    context.seek(0)
    return context


def _find_image(client: DockerClient, tag: str) -> Image | None:
    try:
        return client.images.get(tag)
    except ImageNotFound:
        return None


def _as_repo_image(image: Image, tag: str) -> RepoImage:
    return RepoImage(tag=tag, commit=image.labels.get(COMMIT_LABEL, ""))


def _existing_image(plan: _BuildPlan) -> RepoImage | None:
    client = get_docker_client()
    try:
        image = _find_image(client, plan.tag)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not look up the repo image: {exc}") from exc
    return _as_repo_image(image, plan.tag) if image is not None else None


def ready_repo_image(repo_root: Path) -> RepoImage | None:
    """The repo's image if it has been built. Never starts a build."""
    plan = _build_plan(repo_root)
    return _existing_image(plan) if plan is not None else None


def _stream_build(client: DockerClient, plan: _BuildPlan, repo_root: Path) -> None:
    """Run the Docker build, failing if it errors, goes silent or runs past the time limit."""
    deadline = time.monotonic() + BUILD_TIMEOUT_SECONDS
    with _build_context(repo_root, plan) as context:
        try:
            stream = client.api.build(
                fileobj=context,
                custom_context=True,
                tag=plan.tag,
                labels={COMMIT_LABEL: plan.commit, REPO_LABEL: str(repo_root)},
                rm=True,
                decode=True,
                timeout=BUILD_IDLE_TIMEOUT_SECONDS,
            )
            with closing(stream):
                for chunk in stream:
                    if "error" in chunk:
                        raise SandboxEnvironmentError(
                            f"Building the repo image failed: {chunk['error']}"
                        )
                    if time.monotonic() > deadline:
                        raise SandboxEnvironmentError(
                            f"Building the repo image took longer than {BUILD_TIMEOUT_SECONDS} seconds."
                        )
        except (requests.exceptions.RequestException, HTTPError, TimeoutError) as exc:
            raise SandboxEnvironmentError(
                f"The repo image build stopped responding for {BUILD_IDLE_TIMEOUT_SECONDS} seconds "
                f"or lost its connection to Docker: {exc}"
            ) from exc


def _remove_superseded_images(client: DockerClient, repo_root: Path, keep_tag: str) -> None:
    """Remove this repo's older images; an image still used by a container stays."""
    older = client.images.list(
        name=REPO_IMAGE_REPOSITORY, filters={"label": f"{REPO_LABEL}={repo_root}"}
    )
    for image in older:
        if keep_tag in image.tags:
            continue
        try:
            client.images.remove(image.id)
        except APIError as exc:
            if exc.status_code != DOCKER_CONFLICT_STATUS:
                raise


def _build_from_plan(repo_root: Path, plan: _BuildPlan) -> RepoImage:
    ensure_environment()
    client = get_docker_client()
    try:
        image = _find_image(client, plan.tag)
        if image is None:
            _stream_build(client, plan, repo_root)
            image = client.images.get(plan.tag)
            _remove_superseded_images(client, repo_root, plan.tag)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not build the repo image: {exc}") from exc
    return _as_repo_image(image, plan.tag)


def build_repo_image(repo_root: Path) -> RepoImage | None:
    """Build the repo image, or reuse it if it exists. Blocks until done.

    Returns None when the repo has no commit or no supported lockfile.
    """
    plan = _build_plan(repo_root)
    return _build_from_plan(repo_root, plan) if plan is not None else None


def start_repo_image_build(repo_root: Path) -> RepoImageStatus:
    """Start building in the background unless the image exists or is already being built."""
    plan = _build_plan(repo_root)
    if plan is None:
        return RepoImageStatus(RepoImageState.NONE)
    if _existing_image(plan) is not None:
        return RepoImageStatus(RepoImageState.READY)
    with _build_lock:
        if plan.tag not in _active_builds:
            _active_builds.add(plan.tag)
            _failed_builds.pop(plan.tag, None)
            threading.Thread(
                target=_build_in_background, args=(repo_root, plan), daemon=True
            ).start()
    return RepoImageStatus(RepoImageState.BUILDING)


def repo_image_status(repo_root: Path) -> RepoImageStatus:
    """Where the repo image stands: none, building, ready or failed."""
    plan = _build_plan(repo_root)
    if plan is None:
        return RepoImageStatus(RepoImageState.NONE)
    with _build_lock:
        if plan.tag in _active_builds:
            return RepoImageStatus(RepoImageState.BUILDING)
        failure = _failed_builds.get(plan.tag)
    if failure is not None:
        return RepoImageStatus(RepoImageState.FAILED, failure)
    if _existing_image(plan) is not None:
        return RepoImageStatus(RepoImageState.READY)
    return RepoImageStatus(RepoImageState.NONE, "not built yet")


def _build_in_background(repo_root: Path, plan: _BuildPlan) -> None:
    try:
        _build_from_plan(repo_root, plan)
    except SandboxEnvironmentError as exc:
        with _build_lock:
            _failed_builds[plan.tag] = str(exc)
    finally:
        with _build_lock:
            _active_builds.discard(plan.tag)


def changes_since(
    repo_root: Path, commit: str, untracked: list[str] | None = None
) -> RepoChanges | None:
    """Files that differ between `commit` and the working tree, or None if git lacks the commit.

    Pass `untracked` (paths git does not track and does not ignore) if the caller already has
    them, to save a git call.
    """
    if _run_git(repo_root, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        return None
    # Output is NUL-separated: status, path, status, path, ...
    diff = _git(repo_root, "diff", "--name-status", "--no-renames", "-z", commit).split(b"\0")
    changed: list[str] = []
    deleted: list[str] = []
    for status, path in zip(diff[0::2], diff[1::2], strict=False):
        (deleted if status == b"D" else changed).append(path.decode())
    if untracked is None:
        listing = _git(repo_root, "ls-files", "-z", "--others", "--exclude-standard")
        untracked = [path.decode() for path in listing.split(b"\0") if path]
    changed.extend(untracked)
    existing = [path for path in changed if (repo_root / path).is_file()]
    return RepoChanges(changed_paths=existing, deleted_paths=deleted)
