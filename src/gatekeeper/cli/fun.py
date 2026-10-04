"""`gatekeeper fun on|off|watch`: useless mode (GK-10) and its brain rot sounds."""

import os
import sqlite3
import sys
import time
from dataclasses import dataclass, field
from typing import Annotated, TextIO

import typer

from gatekeeper import database
from gatekeeper.cli import brainrot
from gatekeeper.cli.review import format_row
from gatekeeper.core import decision_store, sessions

POLL_SECONDS = 0.5
WATCH_ROW_LIMIT = 50

fun_app = typer.Typer(help="Useless mode: sarcastic questions and brain rot.", no_args_is_help=True)

SessionOption = Annotated[
    str | None,
    typer.Option(help="Session id (default: the latest session in this repo)"),
]


@dataclass
class WatchState:
    seen: set[str] = field(default_factory=set)
    next_scare_at: float | None = None


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(1)


def _resolve_session(conn: sqlite3.Connection, session: str | None) -> str:
    if session is not None:
        return session
    session_id = decision_store.latest_session_for_repo(conn, sessions.find_repo_root(os.getcwd()))
    if session_id is None:
        raise _fail("No Gatekeeper session found for this repo. Pass --session ID.")
    return session_id


def _switch(session: str | None, enabled: bool) -> None:
    conn = database.connect()
    session_id = _resolve_session(conn, session)
    if not sessions.set_useless_mode(conn, session_id, enabled):
        raise _fail(f"No session {session_id}.")
    state = "on" if enabled else "off"
    typer.echo(f"Useless mode is {state} for session {session_id}.")
    if enabled:
        typer.echo('Run "gatekeeper fun watch" for the full experience.')


@fun_app.command()
def on(session: SessionOption = None) -> None:
    """Turn useless mode on for a session."""
    _switch(session, True)


@fun_app.command()
def off(session: SessionOption = None) -> None:
    """Turn useless mode off for a session."""
    _switch(session, False)


def tick(
    conn: sqlite3.Connection,
    session_id: str,
    state: WatchState,
    now: float,
    *,
    interactive: bool,
    out: TextIO | None = None,
) -> None:
    """Print new decisions with a sound each, and play a random scare sound when one is due.

    Useless mode is read every tick, so `gatekeeper fun on|off` in another terminal applies live.
    """
    stream = out or sys.stdout
    useless = brainrot.useless_mode_on(conn, session_id)
    rows = decision_store.list_decisions(conn, session_id, WATCH_ROW_LIMIT)
    for row in reversed(rows):
        if row["decision_id"] in state.seen:
            continue
        state.seen.add(row["decision_id"])
        stream.write(format_row(row) + "\n")
        stream.flush()
        brainrot.play(brainrot.sound_for(row["verdict"], row["summary"]) if useless else None, stream)
    if not useless:
        state.next_scare_at = None
    elif interactive:
        if state.next_scare_at is None:
            state.next_scare_at = now + brainrot.next_scare_delay()
        elif now >= state.next_scare_at:
            brainrot.scare(stream)
            state.next_scare_at = time.monotonic() + brainrot.next_scare_delay()


@fun_app.command()
def watch(session: SessionOption = None) -> None:
    """Follow a session's decisions live. With useless mode on: brain rot sounds."""
    conn = database.connect()
    session_id = _resolve_session(conn, session)
    state = WatchState(
        seen={row["decision_id"] for row in decision_store.list_decisions(conn, session_id, WATCH_ROW_LIMIT)}
    )
    typer.echo(f"Watching session {session_id}. Press Ctrl+C to stop.")
    interactive = sys.stdout.isatty()
    try:
        while True:
            tick(conn, session_id, state, time.monotonic(), interactive=interactive)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        typer.echo("")
