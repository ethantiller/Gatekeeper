"""`gatekeeper fun on|off|toggle|status|watch`: useless mode (GK-10) and its brain rot sounds."""

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
from gatekeeper.pipeline import useless_mode

POLL_SECONDS = 0.5
WATCH_ROW_LIMIT = 50
SOURCE_NAMES = {
    "session": "this session's own switch",
    "global": "the global switch",
    "rules": "rules.yaml",
}

fun_app = typer.Typer(help="Useless mode: sarcastic questions and brain rot.", no_args_is_help=True)

SessionOption = Annotated[
    str | None,
    typer.Option(help="Session id (default: the latest session in this repo)"),
]
GlobalOption = Annotated[
    bool,
    typer.Option("--global", help="Switch every session that has no switch of its own"),
]


@dataclass
class WatchState:
    seen: set[str] = field(default_factory=set)
    next_scare_at: float | None = None
    was_on: bool | None = None


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(1)


def _target(conn: sqlite3.Connection, session: str | None, use_global: bool) -> str | None:
    """The session to switch, or None for the global switch.

    With no `--session`, it is the latest session in this repo, or the global switch when this
    repo has no session yet (so the mode can be turned on before the agent starts).
    """
    if use_global:
        return None
    if session is not None:
        return session
    found = decision_store.latest_session_for_repo(conn, sessions.find_repo_root(os.getcwd()))
    if found is None:
        typer.echo("No session in this repo yet, so this changes the global switch.")
    return found


def _current(conn: sqlite3.Connection, session_id: str | None) -> tuple[bool, str]:
    return useless_mode.state(conn, session_id, useless_mode.session_config(conn, session_id))


def _switch(session: str | None, use_global: bool, enabled: bool | None) -> None:
    """Turn the mode on or off for the target; `enabled=None` flips whatever it is now."""
    conn = database.connect()
    target = _target(conn, session, use_global)
    if enabled is None:
        enabled = not _current(conn, target)[0]
    if target is None:
        sessions.set_global_useless_mode(conn, enabled)
    elif not sessions.set_useless_mode(conn, target, enabled):
        raise _fail(f"No session {target}.")
    where = f"session {target}" if target else "all sessions without their own switch"
    typer.echo(f"Useless mode is {'on' if enabled else 'off'} for {where}.")
    if target is None:
        own = decision_store.latest_session_for_repo(conn, sessions.find_repo_root(os.getcwd()))
        override = sessions.useless_mode_override(conn, own) if own else None
        if override is not None and override != enabled:
            typer.echo(f"Note: session {own} has its own switch ({'on' if override else 'off'}), which wins.")
    if enabled:
        typer.echo('Run "gatekeeper fun watch" for the full experience.')


@fun_app.command()
def on(session: SessionOption = None, use_global: GlobalOption = False) -> None:
    """Turn useless mode on."""
    _switch(session, use_global, True)


@fun_app.command()
def off(session: SessionOption = None, use_global: GlobalOption = False) -> None:
    """Turn useless mode off."""
    _switch(session, use_global, False)


@fun_app.command()
def toggle(session: SessionOption = None, use_global: GlobalOption = False) -> None:
    """Flip useless mode: on becomes off and off becomes on."""
    _switch(session, use_global, None)


@fun_app.command()
def status(session: SessionOption = None) -> None:
    """Say whether useless mode is on, and which switch decided it."""
    conn = database.connect()
    session_id = session or decision_store.latest_session_for_repo(
        conn, sessions.find_repo_root(os.getcwd())
    )
    enabled, source = _current(conn, session_id)
    scope = f"session {session_id}" if session_id else "no session in this repo yet"
    typer.echo(f"Useless mode is {'ON' if enabled else 'OFF'} ({scope}), set by {SOURCE_NAMES[source]}.")


def tick(
    conn: sqlite3.Connection,
    session_id: str | None,
    state: WatchState,
    now: float,
    *,
    interactive: bool,
    out: TextIO | None = None,
) -> None:
    """Print new decisions with a sound each, and play a random scare sound when one is due.

    Useless mode is read every tick, so `gatekeeper fun on|off|toggle` in another terminal
    applies live.
    """
    stream = out or sys.stdout
    useless = brainrot.useless_mode_on(conn, session_id)
    if state.was_on is not None and useless != state.was_on:
        stream.write(f"*** Useless mode is now {'ON' if useless else 'OFF'} ***\n")
        stream.flush()
    state.was_on = useless
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
    session_id = session or decision_store.latest_session_for_repo(
        conn, sessions.find_repo_root(os.getcwd())
    )
    if session_id is None:
        raise _fail("No Gatekeeper session found for this repo. Start your agent first, or pass --session ID.")
    state = WatchState(
        seen={row["decision_id"] for row in decision_store.list_decisions(conn, session_id, WATCH_ROW_LIMIT)}
    )
    enabled, source = _current(conn, session_id)
    typer.echo(
        f"Watching session {session_id}. Useless mode is {'ON' if enabled else 'OFF'}"
        f" (set by {SOURCE_NAMES[source]}). Press Ctrl+C to stop."
    )
    interactive = sys.stdout.isatty()
    try:
        while True:
            tick(conn, session_id, state, time.monotonic(), interactive=interactive)
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        typer.echo("")
