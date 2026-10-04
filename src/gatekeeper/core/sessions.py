"""Session records: finding the repo, the action counter, and source handling (GK-6)."""

import secrets
import sqlite3
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from gatekeeper.server.types import (
    ActionSource,
    PromptPayload,
    SandboxSession,
    SessionStartPayload,
    eastern_now,
    new_id,
)

TRIPWIRE_SEED_BYTES = 16


@dataclass(frozen=True)
class RecordedPrompt:
    """What saving a prompt produced."""

    prompt_id: str
    new_action_count: int
    answered_question: str | None  # the useless-mode question this prompt answered, if any


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
    _save_session(database_connection, hook_payload.session_id, hook_payload.cwd)
    return get_session(database_connection, hook_payload.session_id)


def _save_session(
    database_connection: sqlite3.Connection, session_id: str, working_directory: str
) -> None:
    """Insert the session row, or refresh its folders if it exists. Never touches the counter."""
    repo_root = find_repo_root(Path(working_directory))
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
                session_id,
                ActionSource.CLAUDE_HOOK.value,
                working_directory,
                eastern_now().isoformat(),
                str(repo_root),
                new_tripwire_seed,
            ),
        )


def record_prompt(
    database_connection: sqlite3.Connection, hook_payload: PromptPayload
) -> RecordedPrompt:
    """Count the prompt as an action, save it, and save it as an answer if one was awaited.

    If useless mode asked a question, this prompt is the answer: it is saved with that
    question and the pending question is cleared. A prompt for a session the server has no
    record of (for example after the database was reset) creates the session first.
    """
    session_is_known = database_connection.execute(
        "SELECT 1 FROM sessions WHERE session_id = ?", (hook_payload.session_id,)
    ).fetchone()
    if session_is_known is None:
        _save_session(database_connection, hook_payload.session_id, hook_payload.cwd)

    prompt_id = new_id()
    with database_connection:  # the first UPDATE takes the write lock for the whole block
        counter_row = database_connection.execute(
            """
            UPDATE sessions SET action_counter = action_counter + 1
            WHERE session_id = ?
            RETURNING action_counter, pending_useless_question
            """,
            (hook_payload.session_id,),
        ).fetchone()
        new_action_count = counter_row["action_counter"]
        answered_question = counter_row["pending_useless_question"]

        database_connection.execute(
            """
            INSERT INTO prompts (prompt_id, session_id, text, created_at, answers_question)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                prompt_id,
                hook_payload.session_id,
                hook_payload.prompt,
                eastern_now().isoformat(),
                answered_question,
            ),
        )
        if answered_question is not None:
            database_connection.execute(
                "UPDATE sessions SET pending_useless_question = NULL WHERE session_id = ?",
                (hook_payload.session_id,),
            )

    return RecordedPrompt(
        prompt_id=prompt_id,
        new_action_count=new_action_count,
        answered_question=answered_question,
    )


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
    tripwire seed (it predates migration 0003 and was never refreshed by start_session),
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
