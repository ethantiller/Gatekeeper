"""SQLite connection and table definitions."""

import os
import sqlite3
from importlib import resources
from pathlib import Path

DEFAULT_DB_PATH = Path.home() / ".gatekeeper" / "gatekeeper.db"
MIGRATIONS = resources.files("gatekeeper") / "migrations"


def connect(path: Path | None = None) -> sqlite3.Connection:
    """Open the database, creating the file, folders, and tables if needed."""
    if path is None:
        path = Path(os.environ.get("GATEKEEPER_DB", DEFAULT_DB_PATH))
    path.parent.mkdir(parents=True, exist_ok=True)

    # FastAPI runs handlers on a threadpool, so one connection is used across threads.
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA synchronous=NORMAL")
    migrate(conn)
    return conn


def migrate(conn: sqlite3.Connection) -> None:
    """Apply any migrations the database hasn't seen yet, in order.

    Files are named NNNN_description.sql. The database's user_version holds the number
    of the last migration applied. Each migration and its version bump commit together.
    """
    current_version = conn.execute("PRAGMA user_version").fetchone()[0]
    migration_files = sorted(
        (file for file in MIGRATIONS.iterdir() if file.name.endswith(".sql")),
        key=lambda file: file.name,
    )
    for file in migration_files:
        version = int(file.name.split("_", 1)[0])
        if version <= current_version:
            continue
        try:
            conn.executescript(
                f"BEGIN;\n{file.read_text()}\nPRAGMA user_version={version};\nCOMMIT;"
            )
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
