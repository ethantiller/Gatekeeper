"""`gatekeeper fun on|off|toggle|status`: the useless mode switch (GK-10)."""

import os
import sqlite3
from typing import Annotated

import typer

from gatekeeper import database
from gatekeeper.core import decision_store, sessions
from gatekeeper.pipeline import useless_mode

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
        typer.echo("Brain rot sounds play on each prompt and each reply. Set GATEKEEPER_MUTE=1 on the server to silence them.")


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
