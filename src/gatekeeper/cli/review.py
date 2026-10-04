"""Review commands: `gatekeeper log`, `gatekeeper show` and `gatekeeper rollback`."""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from gatekeeper import database
from gatekeeper.core import decision_store, sessions
from gatekeeper.core.checkpoints import (
    CHECKPOINT_REF_PREFIX,
    CheckpointError,
    create_checkpoint,
    delete_files,
    diff_checkpoints,
    restore_files,
)
from gatekeeper.pipeline.untrusted import display_source, get_many
from gatekeeper.sandbox.tripwires import generate_tripwire_values
from gatekeeper.server.types import ActionKind, Decision, SandboxReport, Verdict, new_id

DEFAULT_LOG_LIMIT = 20
LIST_PREVIEW_LIMIT = 20
ID_DISPLAY_LENGTH = 8
NO_CHECKPOINT_KINDS = {ActionKind.READ_FILE, ActionKind.FETCH_URL, ActionKind.OTHER}


def _fail(message: str) -> typer.Exit:
    typer.echo(message, err=True)
    return typer.Exit(1)


def _redact(text: str, tripwire_seed: str) -> str:
    """Replace the session's fake secrets with their names."""
    if not tripwire_seed:
        return text
    for name, value in generate_tripwire_values(tripwire_seed).items():
        text = text.replace(value, f"[tripwire {name}]")
    return text


def _tripwire_seed(conn: sqlite3.Connection, session_id: str) -> str:
    row = conn.execute(
        "SELECT tripwire_seed FROM sessions WHERE session_id = ?", (session_id,)
    ).fetchone()
    return row["tripwire_seed"] if row else ""


def _find_decision(conn: sqlite3.Connection, id_or_prefix: str) -> Decision:
    try:
        return decision_store.find_decision(conn, id_or_prefix)
    except (KeyError, ValueError) as error:
        raise _fail(error.args[0]) from error


def log(
    session: Annotated[str | None, typer.Option(help="Show this session")] = None,
    all_sessions: Annotated[bool, typer.Option("--all", help="Show every session")] = False,
    limit: Annotated[int, typer.Option(help="Most recent decisions to show")] = DEFAULT_LOG_LIMIT,
) -> None:
    """List recent decisions, oldest first."""
    conn = database.connect()
    session_id = None if all_sessions else session
    if not all_sessions and session is None:
        session_id = decision_store.latest_session_for_repo(
            conn, sessions.find_repo_root(os.getcwd())
        )
        if session_id is None:
            raise _fail("No Gatekeeper session found for this repo. Use --all to see every session.")
    for row in reversed(decision_store.list_decisions(conn, session_id, limit)):
        when = datetime.fromisoformat(row["created_at"]).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        verdict = "ASK (not approved)" if row["verdict"] == Verdict.ASK else row["verdict"].upper()
        approved_by = row["approved_by"] or "-"
        typer.echo(
            f"{when}  {row['decision_id'][:ID_DISPLAY_LENGTH]}  {verdict}  {approved_by}  {row['summary']}"
        )


def _capped(items: list[str]) -> list[str]:
    lines = [f"    {item}" for item in items[:LIST_PREVIEW_LIMIT]]
    if len(items) > LIST_PREVIEW_LIMIT:
        lines.append(f"    … and {len(items) - LIST_PREVIEW_LIMIT} more")
    return lines


def _sandbox_lines(report: SandboxReport) -> list[str]:
    if report.error:
        return [f"  error: {report.error}"]
    outcome = "timed out" if report.timed_out else f"exit code {report.exit_code}"
    lines = [f"  {outcome} in {report.duration_ms} ms"]
    for label, items in (
        ("files created", report.files_created),
        ("files modified", report.files_modified),
        ("files deleted", report.files_deleted),
        ("hosts contacted", report.network_attempts),
        ("tripwires triggered", report.tripwires_triggered),
        ("notes", report.notes),
    ):
        if items:
            lines.append(f"  {label} ({len(items)})")
            lines.extend(_capped(items))
    return lines


def _describe(conn: sqlite3.Connection, decision: Decision) -> str:
    action = decision.action
    target = action.command or action.path or action.url or action.tool_name
    lines = [
        f"Action: {action.kind.value} `{target}`",
        f"  id {decision.decision_id}, session {decision.session_id}, cwd {action.cwd}",
        f"Verdict: {decision.verdict.value.upper()}"
        + (f" (approved by {decision.approved_by})" if decision.approved_by else ""),
        *[f"  {reason}" for reason in decision.reasons],
        "Rules:",
    ]
    if decision.rules is None:
        lines.append("  none")
    else:
        lines.append(f"  matched: {', '.join(decision.rules.matched_rule_ids) or 'none'}")
        lines.append(f"  tags: {', '.join(decision.rules.tags) or 'none'}")
        lines.extend(f"  {reason}" for reason in decision.rules.reasons)
    lines.append("Judge:")
    if decision.judge is None:
        lines.append("  not consulted")
    elif decision.judge.error:
        lines.append(f"  failed: {decision.judge.error}")
    else:
        lines.append(f"  {decision.judge.risk.value} ({decision.judge.score:.2f})")
        lines.append(f"  {decision.judge.reasoning}")
    lines.append("Sandbox:")
    lines.extend(["  not run"] if decision.sandbox is None else _sandbox_lines(decision.sandbox))
    lines.append("Caused by:")
    reads = get_many(conn, decision.tainted_by)
    if not reads:
        lines.append("  none")
    for read in reads:
        flags = ", ".join(read.scanner_flags) or "no findings"
        lines.append(f"  {display_source(read.source)} (score {read.score:.2f}): {flags}")
    lines.append("Checkpoint:")
    checkpoint = decision_store.find_checkpoint(conn, decision.decision_id)
    if checkpoint is None:
        lines.append("  none")
    else:
        state = f"rolled back {checkpoint.rolled_back_at}" if checkpoint.rolled_back_at else "available"
        lines.append(f"  {CHECKPOINT_REF_PREFIX}{checkpoint.checkpoint_id} ({state})")
    return "\n".join(lines)


def show(
    decision_id: Annotated[str, typer.Argument(help="Decision id or a prefix of 8+ characters")],
    as_json: Annotated[bool, typer.Option("--json", help="Print the stored decision as JSON")] = False,
) -> None:
    """Explain why Gatekeeper decided what it did."""
    conn = database.connect()
    decision = _find_decision(conn, decision_id)
    text = decision.model_dump_json(indent=2) if as_json else _describe(conn, decision)
    typer.echo(_redact(text, _tripwire_seed(conn, decision.session_id)))


def _explain_missing_checkpoint(decision: Decision) -> str:
    if decision.verdict == Verdict.DENY:
        return "This action was denied, so it never ran and there is nothing to roll back."
    if decision.action.kind in NO_CHECKPOINT_KINDS:
        return f"A {decision.action.kind.value} action does not change files, so there is no checkpoint."
    if any("No rollback checkpoint could be taken" in reason for reason in decision.reasons):
        return "Gatekeeper could not take a checkpoint for this action."
    return "No checkpoint was taken: the folder is not a git repository."


def rollback(
    decision_id: Annotated[str, typer.Argument(help="Decision id or a prefix of 8+ characters")],
    yes: Annotated[bool, typer.Option("--yes", help="Delete added files without asking")] = False,
) -> None:
    """Restore the files an approved action changed, using its checkpoint."""
    conn = database.connect()
    decision = _find_decision(conn, decision_id)
    checkpoint = decision_store.find_checkpoint(conn, decision.decision_id)
    if checkpoint is None:
        raise _fail(_explain_missing_checkpoint(decision))
    if checkpoint.rolled_back_at:
        raise _fail(f"Already rolled back at {checkpoint.rolled_back_at}.")

    repo_root = Path(checkpoint.repo_path)
    try:
        safety_id = new_id()
        safety_sha = create_checkpoint(repo_root, safety_id)
        if safety_sha is None:
            raise _fail(f"{repo_root} is no longer a git repository.")
        decision_store.save_checkpoint(conn, safety_id, checkpoint.session_id, repo_root, safety_sha)
        typer.echo(f"Safety checkpoint: {CHECKPOINT_REF_PREFIX}{safety_id}")
        typer.echo(
            f"To undo this rollback: git restore --source={CHECKPOINT_REF_PREFIX}{safety_id}"
            " --worktree -- ."
        )
        diff = diff_checkpoints(repo_root, checkpoint.git_ref, safety_sha)
        restore_files(repo_root, checkpoint.git_ref, diff.changed)
        deleted: list[str] = []
        if diff.added:
            typer.echo(f"Files added since the checkpoint ({len(diff.added)}):")
            typer.echo("\n".join(_capped(diff.added)))
            if yes or typer.confirm(f"Delete these {len(diff.added)} files?", default=False):
                delete_files(repo_root, diff.added)
                deleted = diff.added
    except CheckpointError as error:
        raise _fail(f"Rollback failed: {error}") from error

    try:
        decision_store.mark_rolled_back(conn, checkpoint.checkpoint_id)
    except ValueError as error:
        raise _fail(str(error)) from error
    typer.echo(f"Restored {len(diff.changed)} files.")
    if diff.added:
        typer.echo(f"Deleted {len(deleted)} added files." if deleted else "Kept the added files.")
    typer.echo("Files ignored by git (such as node_modules or .env) are never restored or deleted.")
