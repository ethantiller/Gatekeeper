"""The `gatekeeper` command."""

import typer

from gatekeeper.cli import dev, fun, init, lifecycle, review, server

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command()(init.init)
app.command()(init.doctor)
app.command()(lifecycle.remove)
app.command()(lifecycle.pause)
app.command()(lifecycle.resume)
app.command()(lifecycle.teardown)
app.add_typer(server.app, name="server")
app.command()(review.log)
app.command()(review.show)
app.command()(review.rollback)
app.command("sandbox-test")(dev.sandbox_test)
app.add_typer(fun.fun_app, name="fun")

if __name__ == "__main__":
    app()
