"""`gatekeeper init` and `gatekeeper doctor`."""

import os
import sys
from typing import Annotated

import typer

from gatekeeper.sandbox.environment import SandboxEnvironmentError, ensure_environment
from gatekeeper.setup import clients, home, paths, service
from gatekeeper.setup import doctor as health

CLIENT_HELP = f"Client to set up (repeat for several). Default: all of {', '.join(clients.CLIENTS)}"
EXIT_FAILURE = 1


def validate_clients(selected: list[str] | None) -> list[str]:
    """The chosen client names (all of them when none were given); exits on an unknown name."""
    chosen = selected or list(clients.CLIENTS)
    unknown = [name for name in chosen if name not in clients.CLIENTS]
    if unknown:
        typer.echo(f"Unknown client {', '.join(unknown)}. Choose from {', '.join(clients.CLIENTS)}.", err=True)
        raise typer.Exit(EXIT_FAILURE)
    return chosen


def _step(title: str, changes: list[str]) -> None:
    typer.echo(f"{title}: " + ("; ".join(changes) if changes else "already correct"))


def _setup_api_key() -> bool:
    """Save the key for the server; True if the saved file changed."""
    api_key = os.environ.get(home.API_KEY_NAME) or home.saved_api_key()
    if not api_key and sys.stdin.isatty():
        api_key = typer.prompt(
            f"{home.API_KEY_NAME} (Enter to skip; without it risky actions are asked)",
            default="",
            hide_input=True,
            show_default=False,
        )
    if not api_key:
        typer.echo("API key: not set (skipped)")
        return False
    changed = home.save_api_key(api_key)
    _step("API key", ["saved to ~/.gatekeeper/.env"] if changed else [])
    return changed


def _setup_server(install_login_service: bool, restart: bool) -> None:
    try:
        if install_login_service:
            _step("Login service", service.install_service())
        if restart:
            service.stop_server()
        typer.echo(f"Server: {service.start_server()}")
    except service.ServiceError as error:
        typer.echo(f"Server: {error}", err=True)


def init(
    client: Annotated[list[str] | None, typer.Option("--client", "-c", help=CLIENT_HELP)] = None,
    skip_docker: Annotated[bool, typer.Option(help="Do not build the sandbox environment")] = False,
    skip_service: Annotated[bool, typer.Option(help="Do not install the login service")] = False,
) -> None:
    """Set up Gatekeeper on this machine and check that it works. Safe to run again."""
    chosen = validate_clients(client)
    _step("Home folder", home.create_home())

    if not skip_docker:
        typer.echo("Docker: building the sandbox environment (the first run takes a few minutes)")
        try:
            ensure_environment()
        except SandboxEnvironmentError as error:
            typer.echo(f"Docker: {error}", err=True)

    key_changed = _setup_api_key()
    _setup_server(not skip_service, restart=key_changed)

    for name in chosen:
        try:
            _step(f"Client {name}", clients.install(name))
        except clients.ClientConfigError as error:
            typer.echo(f"Client {name}: {error}", err=True)

    if clients.CODEX in chosen:
        typer.echo(clients.CODEX_TRUST_MESSAGE)
    typer.echo("")
    _report(health.run_checks())


def doctor() -> None:
    """Check that Gatekeeper is set up and working."""
    _report(health.run_checks())


def _report(checks: list[health.Check]) -> None:
    for check in checks:
        typer.echo(check.line())
    if health.has_failure(checks):
        raise typer.Exit(EXIT_FAILURE)
    typer.echo(f"Gatekeeper is ready. Logs: {paths.log_path()}")
