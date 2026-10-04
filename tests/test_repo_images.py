"""Repo image planning and change detection, using real git repos in a temp folder (no Docker)."""

import subprocess
import tarfile
from pathlib import Path

import pytest

from gatekeeper.sandbox import repo_images
from gatekeeper.sandbox.repo_images import (
    _archive_gaps,
    _build_context,
    _build_plan,
    changes_since,
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    _git(repo_root, "init", "-q")
    _git(repo_root, "config", "user.email", "test@example.com")
    _git(repo_root, "config", "user.name", "Test")
    return repo_root


def _commit(repo: Path, **files: str) -> None:
    for name, content in files.items():
        path = repo / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "-m", "commit")


def test_no_plan_without_a_lockfile(repo: Path) -> None:
    _commit(repo, readme="hello")
    assert _build_plan(repo) is None


def test_no_plan_without_a_commit(repo: Path) -> None:
    (repo / "uv.lock").write_text("lock")
    assert _build_plan(repo) is None


def test_every_ecosystem_with_a_lockfile_is_installed(repo: Path) -> None:
    _commit(repo, **{"package-lock.json": "{}", "uv.lock": "lock"})
    plan = _build_plan(repo)
    assert plan is not None
    assert plan.install_commands == (
        "npm ci --ignore-scripts",
        "uv sync --frozen --no-install-project --no-build",
    )


def test_requirements_txt_is_the_fallback_only_without_uv_lock(repo: Path) -> None:
    _commit(repo, **{"requirements.txt": "requests"})
    plan = _build_plan(repo)
    assert plan is not None
    assert "uv pip install --no-build" in plan.install_commands[0]

    (repo / "uv.lock").write_text("lock")
    plan = _build_plan(repo)
    assert plan is not None
    assert len(plan.install_commands) == 1
    assert plan.install_commands[0].startswith("uv sync")


def test_uncommitted_lockfile_change_gets_a_different_image(repo: Path) -> None:
    _commit(repo, **{"uv.lock": "old"})
    committed = _build_plan(repo)
    (repo / "uv.lock").write_text("new")
    changed = _build_plan(repo)
    assert committed is not None and changed is not None
    assert committed.tag != changed.tag
    assert changed.lockfiles == (("uv.lock", b"new"),)


def test_build_context_prefers_working_tree_lockfile_and_has_dockerfile(repo: Path) -> None:
    _commit(repo, **{"uv.lock": "old", "app.py": "print(1)"})
    (repo / "uv.lock").write_text("new")
    plan = _build_plan(repo)
    assert plan is not None
    with _build_context(repo, plan) as context, tarfile.open(fileobj=context) as archive:
        names = archive.getnames()
        assert "Dockerfile" in names
        assert "repo/app.py" in names
        lockfile = [m for m in archive.getmembers() if m.name == "repo/uv.lock"][-1]
        assert archive.extractfile(lockfile).read() == b"new"  # the later entry wins on extraction


def test_archive_gaps_finds_export_ignored_files(repo: Path) -> None:
    _commit(repo, **{".gitattributes": "docs/* export-ignore\n", "docs__guide.md": "x", "a.py": "1"})
    assert _archive_gaps(repo) == ["docs/guide.md"]


def test_build_context_includes_export_ignored_files(repo: Path) -> None:
    _commit(
        repo,
        **{"uv.lock": "lock", ".gitattributes": "docs/* export-ignore\n", "docs__guide.md": "x"},
    )
    plan = _build_plan(repo)
    assert plan is not None
    with _build_context(repo, plan) as context, tarfile.open(fileobj=context) as archive:
        assert "repo/docs/guide.md" in archive.getnames()


def test_changes_since_reports_modified_deleted_and_untracked(repo: Path) -> None:
    _commit(repo, **{"keep.txt": "1", "edit.txt": "1", "gone.txt": "1"})
    commit = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True
    ).stdout.strip()
    (repo / "edit.txt").write_text("2")
    (repo / "gone.txt").unlink()
    (repo / "new.txt").write_text("3")

    changes = changes_since(repo, commit)
    assert changes is not None
    assert sorted(changes.changed_paths) == ["edit.txt", "new.txt"]
    assert changes.deleted_paths == ["gone.txt"]

    given = changes_since(repo, commit, untracked=["new.txt"])
    assert given == changes


def test_changes_since_unknown_commit_is_none(repo: Path) -> None:
    _commit(repo, a="1")
    assert changes_since(repo, "0" * 40) is None


def test_superseded_images_are_removed_but_the_current_and_busy_ones_stay() -> None:
    class FakeImage:
        def __init__(self, image_id: str, tags: list[str]) -> None:
            self.id = image_id
            self.tags = tags

    class FakeImages:
        def __init__(self) -> None:
            self.removed: list[str] = []

        def list(self, name: str, filters: dict) -> list[FakeImage]:
            return [
                FakeImage("current", ["gatekeeper-repo:new"]),
                FakeImage("old", ["gatekeeper-repo:old"]),
                FakeImage("busy", ["gatekeeper-repo:busy"]),
            ]

        def remove(self, image_id: str) -> None:
            if image_id == "busy":
                raise repo_images.APIError("in use", response=_Response(409))
            self.removed.append(image_id)

    class FakeClient:
        images = FakeImages()

    repo_images._remove_superseded_images(FakeClient(), Path("/repo"), "gatekeeper-repo:new")
    assert FakeClient.images.removed == ["old"]


class _Response:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.reason = "conflict"
        self.content = b""

    def json(self) -> dict:
        return {}
