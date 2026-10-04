"""Git checkpoints taken before an action runs, built without touching the working tree."""

import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

CHECKPOINT_REF_PREFIX = "refs/gatekeeper/checkpoints/"
GIT_TIMEOUT_SECONDS = 60
GIT_IDENTITY = {
    "GIT_AUTHOR_NAME": "Gatekeeper",
    "GIT_AUTHOR_EMAIL": "gatekeeper@localhost",
    "GIT_COMMITTER_NAME": "Gatekeeper",
    "GIT_COMMITTER_EMAIL": "gatekeeper@localhost",
}


class CheckpointError(Exception):
    """Raised when a git checkpoint could not be created or restored."""


@dataclass(frozen=True)
class CheckpointDiff:
    """Files that differ between two checkpoints."""

    changed: list[str]  # modified, type-changed or deleted since the older checkpoint
    added: list[str]  # present only in the newer checkpoint


def create_checkpoint(repo_root: Path, checkpoint_id: str) -> str | None:
    """Commit the repo's current files (tracked and untracked, not ignored) and return its sha.

    A temporary index is used, so the working tree, the real index and the current branch
    are untouched. The commit is kept alive by `refs/gatekeeper/checkpoints/<id>`.
    Returns None when `repo_root` is not a git repository.
    """
    if _git(repo_root, ["rev-parse", "--git-dir"], check=False) is None:
        return None

    with tempfile.TemporaryDirectory() as scratch:
        env = {"GIT_INDEX_FILE": str(Path(scratch) / "index"), **GIT_IDENTITY}
        parent = _git(repo_root, ["rev-parse", "--verify", "-q", "HEAD"], check=False)
        if parent:
            _git(repo_root, ["read-tree", "HEAD"], env=env)
        _git(repo_root, ["add", "-A"], env=env)
        tree = _git(repo_root, ["write-tree"], env=env)
        parent_args = ["-p", parent] if parent else []
        message = f"gatekeeper checkpoint {checkpoint_id}"
        sha = _git(repo_root, ["commit-tree", tree, *parent_args, "-m", message], env=env)

    _git(repo_root, ["update-ref", CHECKPOINT_REF_PREFIX + checkpoint_id, sha])
    return sha


def diff_checkpoints(repo_root: Path, old_sha: str, new_sha: str) -> CheckpointDiff:
    """Which files changed or were added going from `old_sha` to `new_sha`."""
    output = _git(
        repo_root,
        ["diff", "--name-status", "-z", "--no-renames", "--ignore-submodules=all", old_sha, new_sha],
    )
    tokens = [token for token in output.split("\0") if token]
    changed: list[str] = []
    added: list[str] = []
    for status, path in zip(tokens[::2], tokens[1::2], strict=True):
        (added if status == "A" else changed).append(path)
    return CheckpointDiff(changed=changed, added=added)


def restore_files(repo_root: Path, sha: str, paths: list[str]) -> None:
    """Write these files from the checkpoint into the working tree.

    Files come from a temporary index, so the real index, HEAD and the branch are not touched.
    """
    if not paths:
        return
    with tempfile.TemporaryDirectory() as scratch:
        env = {"GIT_INDEX_FILE": str(Path(scratch) / "index")}
        _git(repo_root, ["read-tree", sha], env=env)
        _git(
            repo_root,
            ["checkout-index", "-f", "-z", "--stdin"],
            env=env,
            stdin="\0".join(paths) + "\0",
        )


def delete_files(repo_root: Path, paths: list[str]) -> None:
    """Delete these files (a symlink is removed itself) and any folders left empty."""
    root = repo_root.resolve()
    for relative in paths:
        path = root / relative
        if not path.parent.resolve().is_relative_to(root):
            raise CheckpointError(f"Refusing to delete {relative}: it is outside the repo")
        try:
            path.unlink()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise CheckpointError(f"Could not delete {relative}: {error}") from error
        for folder in path.parents:
            if folder == root:
                break
            try:
                folder.rmdir()
            except OSError:
                break


def _git(
    repo_root: Path,
    args: list[str],
    env: dict[str, str] | None = None,
    check: bool = True,
    stdin: str | None = None,
) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            env={**os.environ, **(env or {})},
            input=stdin,
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckpointError(f"Could not run git: {error}") from error
    if result.returncode != 0:
        if check:
            raise CheckpointError(f"git {args[0]} failed: {result.stderr.strip()}")
        return None
    return result.stdout.strip()
