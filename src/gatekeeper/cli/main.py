"""The `gatekeeper` command."""

import typer

from gatekeeper.cli import dev, review

app = typer.Typer(no_args_is_help=True, add_completion=False)
app.command()(review.log)
app.command()(review.show)
app.command()(review.rollback)
app.command("sandbox-test")(dev.sandbox_test)

if __name__ == "__main__":
    app()
