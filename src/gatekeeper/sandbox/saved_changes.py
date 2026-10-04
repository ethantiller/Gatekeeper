"""Keeps the files a sandboxed command changed, so an approval applies exactly what was checked.

The tar comes from a command that may be malicious, so applying it is strict: only regular
files, folders and symlinks that stay inside the repo, never anything under `.git`, and nothing
is applied if the host files changed since the sandbox run.
"""

import hashlib
import io
import json
import os
import posixpath
import shutil
import tarfile
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from docker.errors import APIError
from docker.models.containers import Container

from gatekeeper.sandbox.environment import EXIT_SUCCESS, SandboxEnvironmentError
from gatekeeper.server.types import new_id

STATE_DIR_VARIABLE = "GATEKEEPER_SAVED_CHANGES"
DEFAULT_STATE_DIR = Path.home() / ".gatekeeper" / "saved_changes"
ARCHIVE_FILENAME = "changes.tar"
MANIFEST_FILENAME = "manifest.json"
MAX_ARCHIVE_BYTES = 200 * 1024 * 1024
FILE_LIST_PATH = "/tmp/gk-changed.list"
CONTAINER_ARCHIVE_PATH = "/tmp/gk-changed.tar"
PROTECTED_DIRECTORY = ".git"  # a hook written here would run on the host
DIRECTORY_HASH = "directory"
OWNER_READ_WRITE = 0o600
PERMISSION_BITS = 0o777
HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class CaptureOutcome:
    """The saved id, or why nothing was saved (None for the id with no reason means no changes)."""

    change_id: str | None
    skipped_reason: str | None = None


class SavedChangesDriftError(SandboxEnvironmentError):
    """Raised when host files changed after the sandbox run, so the saved changes are stale."""

    def __init__(self, paths: list[str]) -> None:
        shown = ", ".join(paths[:5])
        super().__init__(f"Files changed on the host since the sandbox run: {shown}")
        self.paths = paths


def _state_dir(change_id: str) -> Path:
    return Path(os.environ.get(STATE_DIR_VARIABLE, DEFAULT_STATE_DIR)) / change_id


def capture_changes(
    container: Container,
    workspace: str,
    repo_root: Path,
    written_paths: list[str],
    deleted_paths: list[str],
    secret_values: list[str],
) -> CaptureOutcome:
    """Save the changed files from the container so an approval can apply exactly them.

    The paths are container paths under `workspace`, as reported by `container.diff()`.
    Nothing is saved (and the reason is returned) if the changes are too large or if any file
    contains one of `secret_values`: applying planted fake secrets would write them into the repo.
    """
    written = _relative_paths(written_paths, workspace)
    deleted = _relative_paths(deleted_paths, workspace)
    if not written and not deleted:
        return CaptureOutcome(None)
    change_id = new_id()
    state_dir = _state_dir(change_id)
    state_dir.mkdir(parents=True)
    try:
        outcome = _save_into(
            state_dir, container, workspace, repo_root, written, deleted, secret_values
        )
    except BaseException:
        shutil.rmtree(state_dir, ignore_errors=True)
        raise
    if outcome.change_id is None:
        shutil.rmtree(state_dir, ignore_errors=True)
    return outcome


def _save_into(
    state_dir: Path,
    container: Container,
    workspace: str,
    repo_root: Path,
    written: list[str],
    deleted: list[str],
    secret_values: list[str],
) -> CaptureOutcome:
    """Fill state_dir; a CaptureOutcome whose id is None (with a reason) means nothing is kept."""
    archive_path = state_dir / ARCHIVE_FILENAME
    if written:
        if not _save_changed_files(container, workspace, written, archive_path):
            return CaptureOutcome(None, "the changed files are too large to save")
        if _contains_secret(archive_path, secret_values):
            return CaptureOutcome(None, "a changed file contains the sandbox's planted fake secrets")
    manifest = {
        "written": written,
        "deleted": deleted,
        "host_hashes": _host_hashes(repo_root, written + deleted),
    }
    (state_dir / MANIFEST_FILENAME).write_text(json.dumps(manifest))
    return CaptureOutcome(state_dir.name)


def check_drift(change_id: str, repo_root: Path) -> list[str]:
    """Host paths whose content differs from when the sandbox run was checked. Read-only."""
    return _drifted_paths(_load_manifest(change_id), repo_root)


def apply_saved_changes(change_id: str, repo_root: Path) -> None:
    """Apply exactly the saved changes to the repo, then discard them.

    Raises SavedChangesDriftError if a host file changed since the run. Every path and archive
    entry is checked before anything on disk is touched.
    """
    manifest = _load_manifest(change_id)
    drifted = _drifted_paths(manifest, repo_root)
    if drifted:
        raise SavedChangesDriftError(drifted)
    root = repo_root.resolve()
    deleted = [_checked_relative_path(path) for path in manifest["deleted"]]
    if manifest["written"]:
        with tarfile.open(_state_dir(change_id) / ARCHIVE_FILENAME) as archive:
            members = archive.getmembers()
            for member in members:
                _check_member(member)
            _delete_paths(root, deleted)
            for member in members:
                _write_member(root, archive, member)
    else:
        _delete_paths(root, deleted)
    discard_saved_changes(change_id)


def discard_saved_changes(change_id: str) -> None:
    """Remove the saved changes, for example after a denial. Does nothing if already gone."""
    shutil.rmtree(_state_dir(change_id), ignore_errors=True)


def _is_protected(path: PurePosixPath) -> bool:
    """Whether any part is `.git`. Case-folded: macOS folders are case-insensitive by default."""
    return any(
        unicodedata.normalize("NFKC", part).casefold() == PROTECTED_DIRECTORY for part in path.parts
    )


def _contains_secret(archive_path: Path, secret_values: list[str]) -> bool:
    """Whether any saved file contains a secret value. Files are read in chunks, overlapping by
    the longest value so one split across two chunks is still found."""
    if not secret_values:
        return False
    needles = [value.encode() for value in secret_values]
    overlap = max(len(needle) for needle in needles) - 1
    with tarfile.open(archive_path) as packed:
        for member in packed:
            content = packed.extractfile(member) if member.isreg() else None
            if content is None:
                continue
            carried = b""
            while chunk := content.read(HASH_CHUNK_BYTES):
                window = carried + chunk
                if any(needle in window for needle in needles):
                    return True
                carried = window[-overlap:] if overlap else b""
    return False


def _relative_paths(paths: list[str], workspace: str) -> list[str]:
    """Container paths made relative to the workspace, dropping anything under `.git`."""
    relative = (str(PurePosixPath(path).relative_to(workspace)) for path in paths)
    return sorted(path for path in relative if not _is_protected(PurePosixPath(path)))


def _tar_single_file(path: str, content: bytes) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        info = tarfile.TarInfo(path.lstrip("/"))
        info.size = len(content)
        info.mode = 0o644
        archive.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def _save_changed_files(
    container: Container, workspace: str, relative_paths: list[str], archive_path: Path
) -> bool:
    """Tar the given files inside the container and stream the tar to archive_path, never
    holding it in memory. False if it would be too large."""
    file_list = b"".join(path.encode() + b"\0" for path in relative_paths)
    try:
        container.put_archive("/", _tar_single_file(FILE_LIST_PATH, file_list))
        result = container.exec_run(
            ["tar", "-c", "--no-recursion", "--null", "-T", FILE_LIST_PATH,
             "-f", CONTAINER_ARCHIVE_PATH],
            workdir=workspace,
        )
        if result.exit_code != EXIT_SUCCESS:
            raise SandboxEnvironmentError("Could not archive the changed files in the sandbox.")
        chunks, stat = container.get_archive(CONTAINER_ARCHIVE_PATH)
        if stat["size"] > MAX_ARCHIVE_BYTES:
            return False
        with tempfile.TemporaryFile() as wrapped:
            for chunk in chunks:
                wrapped.write(chunk)
            wrapped.seek(0)
            # get_archive wraps the file in another tar; unpack that one.
            with tarfile.open(fileobj=wrapped) as outer:
                extracted = outer.extractfile(posixpath.basename(CONTAINER_ARCHIVE_PATH))
                if extracted is None:
                    raise SandboxEnvironmentError("The sandbox's changed-files archive was empty.")
                with archive_path.open("wb") as saved:
                    shutil.copyfileobj(extracted, saved)
    except APIError as exc:
        raise SandboxEnvironmentError(f"Docker could not read the changed files: {exc}") from exc
    return True


def _hash_path(path: Path) -> str:
    if path.is_symlink():
        return "link:" + os.readlink(path)
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(HASH_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint(path: Path) -> str:
    """Cheap stand-in for a hash: size and mtime. Used for files inside folders, where hashing
    everything (a whole node_modules) would be slow. A touched file counts as drift."""
    if path.is_symlink():
        return "link:" + os.readlink(path)
    info = path.stat()
    return f"stat:{info.st_size}:{info.st_mtime_ns}"


def _host_hashes(repo_root: Path, relative_paths: list[str]) -> dict[str, str | None]:
    """Relative path -> content hash on the host, None where nothing exists.

    Folders are walked; the files inside get a size/mtime fingerprint instead of a full hash.
    """
    hashes: dict[str, str | None] = {}
    for relative in relative_paths:
        target = repo_root / relative
        if target.is_dir() and not target.is_symlink():
            hashes[relative] = DIRECTORY_HASH
            for child in sorted(target.rglob("*")):
                if child.is_symlink() or child.is_file():
                    hashes[child.relative_to(repo_root).as_posix()] = _fingerprint(child)
        elif target.is_symlink() or target.exists():
            hashes[relative] = _hash_path(target)
        else:
            hashes[relative] = None
    return hashes


def _load_manifest(change_id: str) -> dict:
    manifest_path = _state_dir(change_id) / MANIFEST_FILENAME
    try:
        return json.loads(manifest_path.read_text())
    except FileNotFoundError as exc:
        raise SandboxEnvironmentError(f"No saved changes found for {change_id}.") from exc


def _drifted_paths(manifest: dict, repo_root: Path) -> list[str]:
    saved = manifest["host_hashes"]
    current = _host_hashes(repo_root, manifest["written"] + manifest["deleted"])
    return sorted(path for path in saved.keys() | current.keys() if saved.get(path) != current.get(path))


def _checked_relative_path(name: str) -> PurePosixPath:
    path = PurePosixPath(posixpath.normpath(name))
    unsafe = (
        path.is_absolute()
        or str(path) == "."
        or ".." in path.parts
        or _is_protected(path)
    )
    if unsafe:
        raise SandboxEnvironmentError(f"Refusing to apply an unsafe path from the sandbox: {name}")
    return path


def _check_member(member: tarfile.TarInfo) -> None:
    """Reject anything but files, folders and symlinks that point inside the repo."""
    path = _checked_relative_path(member.name)
    if member.issym():
        target = posixpath.normpath(posixpath.join(posixpath.dirname(str(path)), member.linkname))
        if posixpath.isabs(member.linkname) or target.startswith(".."):
            raise SandboxEnvironmentError(f"Refusing a symlink that leaves the repo: {member.name}")
    elif not (member.isreg() or member.isdir()):
        raise SandboxEnvironmentError(f"Refusing an unsupported entry from the sandbox: {member.name}")


def _require_inside(root: Path, path: Path) -> None:
    """The real location of `path` (following symlinks that already exist) must be in the repo."""
    if not Path(os.path.realpath(path)).is_relative_to(root):
        raise SandboxEnvironmentError(f"Refusing to write outside the repo: {path}")


def _delete_paths(root: Path, relative_paths: list[PurePosixPath]) -> None:
    for relative in relative_paths:
        target = root / relative
        _require_inside(root, target.parent)
        if target.is_symlink() or target.is_file():
            target.unlink()
        elif target.is_dir():
            shutil.rmtree(target)


def _write_member(root: Path, archive: tarfile.TarFile, member: tarfile.TarInfo) -> None:
    relative = _checked_relative_path(member.name)
    target = root / relative
    _require_inside(root, target.parent)
    target.parent.mkdir(parents=True, exist_ok=True)
    if member.isdir():
        target.mkdir(exist_ok=True)
        return
    if target.is_symlink():
        target.unlink()
    if target.is_dir():
        raise SandboxEnvironmentError(f"Cannot replace a folder with a file: {relative}")
    if member.issym():
        os.symlink(member.linkname, target)
        return
    content = archive.extractfile(member)
    if content is None:
        raise SandboxEnvironmentError(f"Could not read {member.name} from the saved changes.")
    target.write_bytes(content.read())
    target.chmod((member.mode & PERMISSION_BITS) | OWNER_READ_WRITE)
