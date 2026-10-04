"""Developer commands: `gatekeeper sandbox-test`."""

import secrets
from pathlib import Path
from typing import Annotated
from uuid import uuid4

import typer

from gatekeeper.sandbox.repo_images import build_repo_image
from gatekeeper.sandbox.runner import run
from gatekeeper.sandbox.saved_changes import discard_saved_changes
from gatekeeper.server.types import (
    ActionKind,
    ActionSource,
    SandboxReport,
    SandboxSession,
    StandardAction,
)

TRIPWIRE_SEED_BYTES = 16


def _print_list(label: str, items: list[str]) -> None:
    print(f"{label} ({len(items)})")
    for item in items:
        print(f"  {item}")


def _print_report(report: SandboxReport) -> None:
    if report.error:
        print(f"sandbox error: {report.error}")
        return
    outcome = "timed out" if report.timed_out else f"exit code {report.exit_code}"
    print(f"image: {report.image}")
    print(f"result: {outcome} in {report.duration_ms} ms")
    _print_list("files created", report.files_created)
    _print_list("files modified", report.files_modified)
    _print_list("files deleted", report.files_deleted)
    _print_list("hosts contacted", report.network_attempts)
    _print_list("tripwires triggered", report.tripwires_triggered)
    print(f"saved changes: {report.saved_changes_id or 'none'}")
    _print_list("notes", report.notes)
    print("--- stdout (tail) ---")
    print(report.stdout_tail)
    print("--- stderr (tail) ---")
    print(report.stderr_tail)


def sandbox_test(
    command: Annotated[str, typer.Argument(help="Shell command to run in the sandbox")],
    repo: Annotated[Path, typer.Option(help="Repository to copy into the sandbox")] = Path("."),
    cwd: Annotated[
        Path | None, typer.Option(help="Folder inside the repo to run from (default: repo root)")
    ] = None,
    build_image: Annotated[
        bool, typer.Option(help="Build (or reuse) the repo image first and wait for it")
    ] = False,
) -> None:
    """Run a command in the sandbox and print what it did."""
    repo_root = repo.resolve()
    if build_image:
        repo_image = build_repo_image(repo_root)
        print(f"repo image: {repo_image.tag if repo_image else 'none (no lockfile or commit)'}")
    session = SandboxSession(
        session_id=f"sandbox-test-{uuid4().hex[:8]}",
        repo_root=repo_root,
        tripwire_seed=secrets.token_hex(TRIPWIRE_SEED_BYTES),
    )
    action = StandardAction(
        session_id=session.session_id,
        sequence=0,
        source=ActionSource.CLAUDE_HOOK,
        kind=ActionKind.RUN_COMMAND,
        tool_name="Bash",
        command=command,
        cwd=str((cwd or repo_root).resolve()),
    )
    report = run(action, session)
    _print_report(report)
    if report.saved_changes_id:
        discard_saved_changes(report.saved_changes_id)  # a test run must not leave state behind
    raise typer.Exit(1 if report.error else 0)


if __name__ == "__main__":
    typer.run(sandbox_test)
