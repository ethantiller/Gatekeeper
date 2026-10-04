"""Git checkpoints taken before an action runs, built without touching the working tree."""

import os
import subprocess
import tempfile
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
    """Raised when a git checkpoint could not be created."""


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


def _git(
    repo_root: Path, args: list[str], env: dict[str, str] | None = None, check: bool = True
) -> str | None:
    try:
        result = subprocess.run(
            ["git", "-C", str(repo_root), *args],
            env={**os.environ, **(env or {})},
            capture_output=True,
            text=True,
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise CheckpointError(f"Could not run git to take a checkpoint: {error}") from error
    if result.returncode != 0:
        if check:
            raise CheckpointError(f"git {args[0]} failed: {result.stderr.strip()}")
        return None
    return result.stdout.strip()
