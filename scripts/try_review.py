"""Try `gatekeeper log`, `show` and `rollback` against a throwaway repo and database.

Run with: uv run python scripts/try_review.py
"""

import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from gatekeeper import database
from gatekeeper.core import decision_store
from gatekeeper.core.sessions import ensure_session
from gatekeeper.server.types import (
    ActionKind,
    ActionSource,
    Decision,
    StandardAction,
    Verdict,
)

GIT_IDENTITY = ["-c", "user.email=t@example.com", "-c", "user.name=T"]


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def gatekeeper(*args: str, input_text: str | None = None) -> None:
    print(f"\n$ gatekeeper {' '.join(args)}")
    result = subprocess.run(
        ["uv", "run", "gatekeeper", *args], input=input_text, capture_output=True, text=True, check=False
    )
    print(result.stdout + result.stderr, end="")
    print(f"[exit {result.returncode}]")


def main() -> None:
    scratch = Path(tempfile.mkdtemp(prefix="gk-try-"))
    repo = scratch / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "main.py").write_text("print('hi')\n")
    (repo / "a.txt").write_text("original\n")
    (repo / ".gitignore").write_text("ignored/\n")
    git(repo, "init", "-q")
    git(repo, *GIT_IDENTITY, "add", "-A")
    git(repo, *GIT_IDENTITY, "commit", "-q", "-m", "init")

    os.environ["GATEKEEPER_DB"] = str(scratch / "gk.db")
    conn = database.connect()
    ensure_session(conn, "try-session", str(repo), ActionSource.CLAUDE_HOOK)
    action = StandardAction(
        session_id="try-session", sequence=0, source=ActionSource.CLAUDE_HOOK,
        kind=ActionKind.RUN_COMMAND, tool_name="Bash", command="rm -rf src", cwd=str(repo),
    )
    decision = decision_store.save(
        conn,
        Decision(
            session_id="try-session", action=action, verdict=Verdict.ASK, reasons=["deletes files"]
        ),
        repo,
    )
    decision_store.record_approval(conn, decision.decision_id)
    short_id = decision.decision_id[:8]

    shutil.rmtree(repo / "src")  # what the approved command did
    (repo / "a.txt").write_text("edited\n")
    (repo / "added.txt").write_text("new file\n")
    (repo / "ignored").mkdir()
    (repo / "ignored" / "keep.txt").write_text("keep\n")
    index_before = (repo / ".git" / "index").read_bytes()

    os.chdir(repo)
    gatekeeper("log")
    gatekeeper("show", short_id)
    gatekeeper("rollback", short_id, input_text="n\n")
    print("\nsrc restored:", (repo / "src" / "main.py").exists())
    print("a.txt restored:", (repo / "a.txt").read_text() == "original\n")
    print("added.txt kept:", (repo / "added.txt").exists())
    print("ignored untouched:", (repo / "ignored" / "keep.txt").exists())
    print("index unchanged:", (repo / ".git" / "index").read_bytes() == index_before)
    gatekeeper("rollback", short_id)  # a second rollback must fail
    print(f"\nscratch folder left at {scratch}")


if __name__ == "__main__":
    main()
