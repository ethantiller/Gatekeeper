"""Session records: repo root, tripwire seed, action counter and saved prompts (GK-6)."""

import secrets
import sqlite3
import subprocess

from gatekeeper.server.types import ActionSource, eastern_now, new_id

TRIPWIRE_SEED_BYTES = 16


def find_repo_root(working_directory: str) -> str:
    """The repo's top folder, or the folder itself when it is not in a git repo."""
    result = subprocess.run(
        ["git", "-C", working_directory, "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else working_directory


def ensure_session(
    connection: sqlite3.Connection, session_id: str, working_directory: str, source: ActionSource
) -> None:
    """Create the session, or refresh its folders. The counter, source and seed are kept."""
    connection.execute(
        """
        INSERT INTO sessions (session_id, source, cwd, started_at, repo_root, tripwire_seed)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(session_id) DO UPDATE SET cwd = excluded.cwd, repo_root = excluded.repo_root
        """,
        (
            session_id,
            source.value,
            working_directory,
            eastern_now().isoformat(),
            find_repo_root(working_directory),
            secrets.token_hex(TRIPWIRE_SEED_BYTES),
        ),
    )
    connection.commit()


def record_prompt(
    connection: sqlite3.Connection,
    session_id: str,
    working_directory: str,
    text: str,
    source: ActionSource,
) -> None:
    """Add 1 to the action counter and save the prompt, as the answer if a question was pending."""
    ensure_session(connection, session_id, working_directory, source)
    with connection:
        pending_question = connection.execute(
            "SELECT pending_useless_question FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()[0]
        connection.execute(
            "UPDATE sessions SET action_counter = action_counter + 1, pending_useless_question = NULL"
            " WHERE session_id = ?",
            (session_id,),
        )
        connection.execute(
            "INSERT INTO prompts (prompt_id, session_id, text, created_at, answers_question)"
            " VALUES (?, ?, ?, ?, ?)",
            (new_id(), session_id, text, eastern_now().isoformat(), pending_question),
        )
