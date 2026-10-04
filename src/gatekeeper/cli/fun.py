"""`gatekeeper fun on|off|toggle|status`: the useless mode switch (GK-10)."""

import os
import sqlite3
from typing import Annotated

import typer

from gatekeeper import database
from gatekeeper.core import decision_store, sessions
from gatekeeper.pipeline import useless_mode
from gatekeeper.setup import service

SOURCE_NAMES = {
    "session": "this session's own switch",
    "global": "the global switch",
    "rules": "rules.yaml",
}

fun_app = typer.Typer(help="Useless mode: sarcastic questions and brain rot.", no_args_is_help=True)

SessionOption = Annotated[
    str | None,
    typer.Option(help="Switch only this session (default: every session, including new ones)"),
]
StatusSessionOption = Annotated[
    str | None,
    typer.Option(help="Session id (default: the latest session in this repo)"),
]


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(1)


def _current(conn: sqlite3.Connection, session_id: str | None) -> tuple[bool, str]:
    return useless_mode.state(conn, session_id, useless_mode.session_config(conn, session_id))


def _latest_session(conn: sqlite3.Connection) -> str | None:
    return decision_store.latest_session_for_repo(conn, sessions.find_repo_root(os.getcwd()))


def _switch(session: str | None, enabled: bool | None) -> None:
    """Turn the mode on or off; `enabled=None` flips whatever it is now.

    Without `--session` this is the global switch, which also clears every session's own
    switch, so on and off apply to every chat, including ones started later.
    """
    conn = database.connect()
    if enabled is None:
        enabled = not _current(conn, session or _latest_session(conn))[0]
    if session is None:
        sessions.set_global_useless_mode(conn, enabled)
    elif not sessions.set_useless_mode(conn, session, enabled):
        raise _fail(f"No session {session}.")
    where = f"session {session}" if session else "every session"
    typer.echo(f"Useless mode is {'on' if enabled else 'off'} for {where}.")
    if not enabled:
        return
    typer.echo("Brain rot sounds play on each prompt and each reply. Set GATEKEEPER_MUTE=1 on the server to silence them.")
    if not service.server_is_up():
        typer.echo('The server is not running, so nothing will play. Start it with "gatekeeper server start".')


@fun_app.command()
def on(session: SessionOption = None) -> None:
    """Turn useless mode on."""
    _switch(session, True)


@fun_app.command()
def off(session: SessionOption = None) -> None:
    """Turn useless mode off."""
    _switch(session, False)


@fun_app.command()
def toggle(session: SessionOption = None) -> None:
    """Flip useless mode: on becomes off and off becomes on."""
    _switch(session, None)


@fun_app.command()
def status(session: StatusSessionOption = None) -> None:
    """Say whether useless mode is on, and which switch decided it."""
    conn = database.connect()
    session_id = session or _latest_session(conn)
    enabled, source = _current(conn, session_id)
    scope = f"session {session_id}" if session_id else "no session in this repo yet"
    typer.echo(f"Useless mode is {'ON' if enabled else 'OFF'} ({scope}), set by {SOURCE_NAMES[source]}.")
