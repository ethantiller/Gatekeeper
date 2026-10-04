"""The `gatekeeper` command."""

import typer

from gatekeeper.cli import dev, fun, review

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command()(review.log)
app.command()(review.show)
app.command()(review.rollback)
app.command("sandbox-test")(dev.sandbox_test)
app.add_typer(fun.fun_app, name="fun")

if __name__ == "__main__":
    app()
