"""Session records: finding the repo, the action counter, and source handling (GK-6)."""

import secrets
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from gatekeeper.server.types import (
    ActionSource,
    SandboxSession,
    SessionStartPayload,
    eastern_now,
)

TRIPWIRE_SEED_BYTES = 16


@dataclass(frozen=True)
class SessionRecord:
    """One row of the sessions table."""

    session_id: str
    repo_root: Path
    action_counter: int
    tripwire_seed: str = field(repr=False)  # a secret: keep it out of logs
    pending_useless_question: str | None


def find_repo_root(working_directory: Path) -> Path:
    """
    The repo's top folder for a folder inside it, even a deep subfolder.

    Falls back to the folder itself when it is not inside a git repo (or git is missing),
    so a session can still be recorded; the sandbox just has no repo to copy.
    """
    try:
        git_result = subprocess.run(
            ["git", "-C", str(working_directory), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False,
        )
    except (FileNotFoundError, NotADirectoryError):
        return working_directory

    top_level_folder = git_result.stdout.strip()
    if git_result.returncode != 0 or not top_level_folder:
        return working_directory
    return Path(top_level_folder)


def start_session(
    database_connection: sqlite3.Connection, hook_payload: SessionStartPayload
) -> SessionRecord:
    """Create the session record, or refresh the one that already exists.

    Every source goes through this one path, because what differs is only whether a
    record is already there:
    - startup and clear: Claude Code gives a new session id, so a new record is created.
    - resume and compact: the record normally exists and is kept; if the server's database
      was reset in between, a new one is created.

    A record that exists keeps its action counter and tripwire seed. The seed is random and
    is never derived from the session id, which the agent can read. Only the folders are
    refreshed, because a session can be resumed from a different folder.
    """
    repo_root = find_repo_root(Path(hook_payload.cwd))
    new_tripwire_seed = secrets.token_hex(TRIPWIRE_SEED_BYTES)

    with database_connection:  # one transaction, committed on success
        database_connection.execute(
            """
            INSERT INTO sessions (session_id, source, cwd, started_at, repo_root, tripwire_seed)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(session_id) DO UPDATE SET
                cwd = excluded.cwd,
                repo_root = excluded.repo_root,
                tripwire_seed = CASE WHEN sessions.tripwire_seed = ''
                                     THEN excluded.tripwire_seed
                                     ELSE sessions.tripwire_seed END
            """,
            (
                hook_payload.session_id,
                ActionSource.CLAUDE_HOOK.value,
                hook_payload.cwd,
                eastern_now().isoformat(),
                str(repo_root),
                new_tripwire_seed,
            ),
        )

    return get_session(database_connection, hook_payload.session_id)


def get_session(database_connection: sqlite3.Connection, session_id: str) -> SessionRecord:
    """Read a session record. Raises KeyError if there is none."""
    session_row = database_connection.execute(
        """
        SELECT session_id, repo_root, action_counter, tripwire_seed, pending_useless_question
        FROM sessions WHERE session_id = ?
        """,
        (session_id,),
    ).fetchone()
    if session_row is None:
        raise KeyError(f"No session with id {session_id}")
    return SessionRecord(
        session_id=session_row["session_id"],
        repo_root=Path(session_row["repo_root"]),
        action_counter=session_row["action_counter"],
        tripwire_seed=session_row["tripwire_seed"],
        pending_useless_question=session_row["pending_useless_question"],
    )


def sandbox_session_for(
    database_connection: sqlite3.Connection, session_id: str
) -> SandboxSession:
    """What `sandbox.run(action, session)` needs, built from the saved session record.

    Raises KeyError if the session was never started, and ValueError if the record has no
    tripwire seed (it predates migration 0002 and was never refreshed by start_session),
    because fake secrets made from an empty seed would be predictable.
    """
    session = get_session(database_connection, session_id)
    if not session.tripwire_seed:
        raise ValueError(f"Session {session_id} has no tripwire seed")
    return SandboxSession(
        session_id=session.session_id,
        repo_root=session.repo_root,
        tripwire_seed=session.tripwire_seed,
    )
