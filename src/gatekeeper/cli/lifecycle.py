"""`gatekeeper remove`, `pause`, `resume` and `teardown`."""

import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer

from gatekeeper.cli.init import CLIENT_HELP, EXIT_FAILURE, validate_clients
from gatekeeper.core.sessions import find_repo_root
from gatekeeper.sandbox.environment import SandboxEnvironmentError, teardown_environment
from gatekeeper.setup import clients, paths, service

SERVICE_TARGET = "service"
PAUSE_WARNING = "Gatekeeper is not checking {names} until you run `gatekeeper resume`."


def _apply(names: list[str], action: Callable[[str], list[str]], verb: str) -> bool:
    """Run `action` for each client, printing what changed; True if any of them failed."""
    failed = False
    for name in names:
        try:
            changes = action(name)
        except clients.ClientConfigError as error:
            typer.echo(f"{name}: {error}", err=True)
            failed = True
            continue
        typer.echo(f"{name}: " + ("; ".join(changes) if changes else f"nothing to {verb}"))
    return failed


def _remove_client(name: str) -> list[str]:
    """Remove a client's user-level entries and the ones in the current repo's own files."""
    repo_root = Path(find_repo_root(os.getcwd()))
    return [*clients.remove(name), *clients.remove_project(name, repo_root)]


def remove(
    targets: Annotated[
        list[str],
        typer.Argument(help=f"What to remove: {', '.join(clients.CLIENTS)}, or {SERVICE_TARGET}"),
    ],
) -> None:
    """Remove Gatekeeper's entries from client configs (yours and this repo's); nothing else changes."""
    unknown = [name for name in targets if name not in (*clients.CLIENTS, SERVICE_TARGET)]
    if unknown:
        typer.echo(f"Unknown target {', '.join(unknown)}.", err=True)
        raise typer.Exit(EXIT_FAILURE)
    failed = _apply([name for name in targets if name in clients.CLIENTS], _remove_client, "remove")
    if SERVICE_TARGET in targets:
        failed = _stop_service() or failed
    if failed:
        raise typer.Exit(EXIT_FAILURE)


def _stop_service() -> bool:
    try:
        stopped = service.stop_server()
        removed = service.uninstall_service()
    except service.ServiceError as error:
        typer.echo(f"server: {error}", err=True)
        return True
    typer.echo("server: " + ("stopped" if stopped else "was not running"))
    if removed:
        typer.echo("login service: removed")
    return False


def pause(
    client: Annotated[list[str] | None, typer.Option("--client", "-c", help=CLIENT_HELP)] = None,
) -> None:
    """Take the hooks out of the client configs without forgetting them. Undo with `resume`."""
    names = validate_clients(client)
    failed = _apply(names, clients.pause, "pause")
    typer.echo(PAUSE_WARNING.format(names=", ".join(names)))
    if failed:
        raise typer.Exit(EXIT_FAILURE)


def resume(
    client: Annotated[list[str] | None, typer.Option("--client", "-c", help=CLIENT_HELP)] = None,
) -> None:
    """Put the hooks back after `pause` (all clients that are paused, unless --client is given)."""
    names = validate_clients(client) if client else [n for n in clients.CLIENTS if clients.is_paused(n)]
    if not names:
        typer.echo("Nothing is paused.")
        return
    if _apply(names, clients.install, "resume"):
        raise typer.Exit(EXIT_FAILURE)


def teardown(
    yes: Annotated[bool, typer.Option("--yes", help="Do not ask first")] = False,
    purge: Annotated[
        bool,
        typer.Option(help="Also delete ~/.gatekeeper (database, token, rules) and the sandbox"),
    ] = False,
) -> None:
    """Remove every client config and the server (login service and process)."""
    extra = " and DELETE ~/.gatekeeper and the sandbox environment" if purge else ""
    if not yes and not typer.confirm(
        f"Remove Gatekeeper from Claude Code, Codex and VS Code, and stop the server{extra}?",
        default=False,
    ):
        raise typer.Exit(EXIT_FAILURE)
    failed = _apply(list(clients.CLIENTS), _remove_client, "remove")
    failed = _stop_service() or failed
    if purge:
        try:
            teardown_environment()
        except SandboxEnvironmentError as error:
            typer.echo(f"sandbox: {error}", err=True)
            failed = True
        shutil.rmtree(paths.gatekeeper_home(), ignore_errors=True)
        typer.echo(f"deleted {paths.gatekeeper_home()}")
    typer.echo("Gatekeeper is removed. Agents are no longer checked.")
    if failed:
        raise typer.Exit(EXIT_FAILURE)
