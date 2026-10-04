"""Applying saved sandbox changes: what is applied, and everything that must be refused."""

import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

import pytest

from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.saved_changes import (
    ARCHIVE_FILENAME,
    MANIFEST_FILENAME,
    STATE_DIR_VARIABLE,
    SavedChangesDriftError,
    apply_saved_changes,
    check_drift,
    discard_saved_changes,
)

CHANGE_ID = "test-change"


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(STATE_DIR_VARIABLE, str(tmp_path / "state"))
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    return repo_root


def _file(name: str, content: bytes = b"data") -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(content)
    info.mode = 0o644
    return info


def _save(
    members: list[tuple[tarfile.TarInfo, bytes | None]],
    written: list[str] | None = None,
    deleted: list[str] | None = None,
    host_hashes: dict[str, str | None] | None = None,
) -> None:
    """Write a saved change by hand, the way capture_changes would."""
    state_dir = Path(os.environ[STATE_DIR_VARIABLE]) / CHANGE_ID
    state_dir.mkdir(parents=True)
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for info, content in members:
            archive.addfile(info, io.BytesIO(content) if content is not None else None)
    (state_dir / ARCHIVE_FILENAME).write_bytes(buffer.getvalue())
    names = written if written is not None else [info.name for info, _ in members]
    manifest = {"written": names, "deleted": deleted or [], "host_hashes": host_hashes or {}}
    (state_dir / MANIFEST_FILENAME).write_text(json.dumps(manifest))


def _symlink(name: str, target: str) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info


def test_applies_files_folders_symlinks_and_deletions(repo: Path) -> None:
    (repo / "old.txt").write_text("old")
    folder = tarfile.TarInfo("pkg")
    folder.type = tarfile.DIRTYPE
    folder.mode = 0o755
    hashes = {
        "pkg": None,
        "pkg/new.txt": None,
        "pkg/link": None,
        "old.txt": hashlib.sha256(b"old").hexdigest(),
    }
    _save(
        [(folder, None), (_file("pkg/new.txt", b"hello"), b"hello"), (_symlink("pkg/link", "new.txt"), None)],
        deleted=["old.txt"],
        host_hashes=hashes,
    )

    apply_saved_changes(CHANGE_ID, repo)

    assert (repo / "pkg" / "new.txt").read_text() == "hello"
    assert os.readlink(repo / "pkg" / "link") == "new.txt"
    assert not (repo / "old.txt").exists()


@pytest.mark.parametrize(
    "member",
    [
        _file("../escape.txt"),
        _file("/etc/escape.txt"),
        _file(".git/hooks/pre-commit"),
        _file(".GIT/hooks/pre-commit"),
        _file("Sub/.Git/config"),
        _file("sub/.git/config"),
        _symlink("link", "../outside"),
        _symlink("link", "/etc/passwd"),
    ],
)
def test_refuses_unsafe_entries_before_changing_anything(repo: Path, member: tarfile.TarInfo) -> None:
    content = b"data" if member.isreg() else None
    _save([(_file("harmless.txt"), b"data"), (member, content)], host_hashes={})

    with pytest.raises(SandboxEnvironmentError):
        apply_saved_changes(CHANGE_ID, repo)

    assert not (repo / "harmless.txt").exists()


def test_refuses_hard_links_and_devices(repo: Path) -> None:
    hard_link = tarfile.TarInfo("hard")
    hard_link.type = tarfile.LNKTYPE
    hard_link.linkname = "target"
    _save([(hard_link, None)])

    with pytest.raises(SandboxEnvironmentError):
        apply_saved_changes(CHANGE_ID, repo)


def test_refuses_to_write_through_a_symlink_that_leaves_the_repo(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / "escape").symlink_to(outside)
    _save([(_file("escape/pwned.txt"), b"data")], host_hashes={"escape/pwned.txt": None})

    with pytest.raises(SandboxEnvironmentError):
        apply_saved_changes(CHANGE_ID, repo)

    assert not (outside / "pwned.txt").exists()


def test_detects_drift_and_applies_nothing(repo: Path) -> None:
    (repo / "file.txt").write_text("changed on the host")
    _save([(_file("file.txt", b"from sandbox"), b"from sandbox")], host_hashes={"file.txt": "0" * 64})

    assert check_drift(CHANGE_ID, repo) == ["file.txt"]
    with pytest.raises(SavedChangesDriftError) as error:
        apply_saved_changes(CHANGE_ID, repo)

    assert error.value.paths == ["file.txt"]
    assert (repo / "file.txt").read_text() == "changed on the host"


def test_new_host_file_where_sandbox_created_one_is_drift(repo: Path) -> None:
    (repo / "new.txt").write_text("someone else made this")
    _save([(_file("new.txt"), b"data")], host_hashes={"new.txt": None})

    assert check_drift(CHANGE_ID, repo) == ["new.txt"]


def test_unknown_change_id_is_an_error(repo: Path) -> None:
    with pytest.raises(SandboxEnvironmentError):
        apply_saved_changes("missing", repo)


def test_discard_removes_the_saved_changes(repo: Path) -> None:
    _save([(_file("a.txt"), b"data")], host_hashes={"a.txt": None})

    discard_saved_changes(CHANGE_ID)

    with pytest.raises(SandboxEnvironmentError):
        check_drift(CHANGE_ID, repo)


def test_applies_a_deletion_only_change(repo: Path) -> None:
    (repo / "gone.txt").write_text("old")
    state_dir = Path(os.environ[STATE_DIR_VARIABLE]) / CHANGE_ID
    state_dir.mkdir(parents=True)
    (state_dir / ARCHIVE_FILENAME).write_bytes(b"")  # what capture_changes saved for a delete
    hashes = {"gone.txt": hashlib.sha256(b"old").hexdigest()}
    manifest = {"written": [], "deleted": ["gone.txt"], "host_hashes": hashes}
    (state_dir / MANIFEST_FILENAME).write_text(json.dumps(manifest))

    apply_saved_changes(CHANGE_ID, repo)

    assert not (repo / "gone.txt").exists()
