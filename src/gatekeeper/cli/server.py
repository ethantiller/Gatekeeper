"""`gatekeeper server start|down|status`."""

import typer

from gatekeeper.setup import paths, service

EXIT_FAILURE = 1
app = typer.Typer(help="Start and stop the Gatekeeper server.", no_args_is_help=True)


@app.command()
def start() -> None:
    """Start the server in the background and wait until it answers."""
    try:
        typer.echo(f"Server {service.start_server()} on {paths.SERVER_URL}. Log: {paths.log_path()}")
    except service.ServiceError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(EXIT_FAILURE) from error


@app.command()
def down() -> None:
    """Stop the server. Hooks fail closed while it is down: risky actions are blocked."""
    try:
        stopped = service.stop_server()
    except service.ServiceError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(EXIT_FAILURE) from error
    typer.echo("Server stopped." if stopped else "The server was not running.")


@app.command()
def status() -> None:
    """Say whether the server is answering."""
    up = service.server_is_up()
    typer.echo(f"Server is {'running' if up else 'not running'} on {paths.SERVER_URL}.")
    raise typer.Exit(0 if up else EXIT_FAILURE)
