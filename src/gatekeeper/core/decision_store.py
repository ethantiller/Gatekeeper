"""Saves decisions to SQLite with a git checkpoint, a user summary and an agent reason."""

import sqlite3
from pathlib import Path

from gatekeeper.core.checkpoints import create_checkpoint
from gatekeeper.server.types import ActionKind, Decision, Verdict, eastern_now, new_id

CHECKPOINT_KINDS = {ActionKind.RUN_COMMAND, ActionKind.WRITE_FILE}
SUMMARY_TARGET_LIMIT = 80


def save(conn: sqlite3.Connection, decision: Decision, repo_root: Path) -> Decision:
    """Write the decision row and, for actions that will change files, a checkpoint.

    Fills in `summary`, `agent_reason` and `checkpoint_id` and returns the saved copy.
    The checkpoint is taken first, so a git failure raises before anything is written.
    """
    checkpoint_id = new_id()
    checkpoint_sha = None
    if decision.verdict != Verdict.DENY and decision.action.kind in CHECKPOINT_KINDS:
        checkpoint_sha = create_checkpoint(repo_root, checkpoint_id)

    saved = decision.model_copy(
        update={
            "summary": summarize(decision),
            "agent_reason": agent_reason(decision),
            "checkpoint_id": checkpoint_id if checkpoint_sha else None,
        }
    )
    with conn:
        conn.execute(
            "INSERT INTO decisions (decision_id, session_id, action_id, sequence, kind,"
            " verdict, summary, decision_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                saved.decision_id,
                saved.session_id,
                saved.action.action_id,
                saved.action.sequence,
                saved.action.kind.value,
                saved.verdict.value,
                saved.summary,
                saved.model_dump_json(),
                saved.created_at.isoformat(),
            ),
        )
        if checkpoint_sha:
            conn.execute(
                "INSERT INTO checkpoints (checkpoint_id, session_id, decision_id, repo_path,"
                " git_ref, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    checkpoint_id,
                    saved.session_id,
                    saved.decision_id,
                    str(repo_root),
                    checkpoint_sha,
                    eastern_now().isoformat(),
                ),
            )
    return saved


def remember_approval(conn: sqlite3.Connection, session_id: str, action_id: str) -> None:
    """Record that the user approved this action id with "remember"."""
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO remembered_approvals (action_id, session_id, created_at)"
            " VALUES (?, ?, ?)",
            (action_id, session_id, eastern_now().isoformat()),
        )


def record_approval(
    conn: sqlite3.Connection, decision_id: str, *, remember: bool = False
) -> Decision:
    """Turn a pending ask into a user-approved allow, and remember it if they chose to."""
    row = conn.execute(
        "SELECT decision_json FROM decisions WHERE decision_id = ?", (decision_id,)
    ).fetchone()
    if row is None:
        raise KeyError(f"No decision {decision_id}")
    decision = Decision.model_validate_json(row["decision_json"])
    if decision.verdict != Verdict.ASK:
        raise ValueError(f"Decision {decision_id} was {decision.verdict.value}, not ask")
    approved = decision.model_copy(
        update={
            "verdict": Verdict.ALLOW,
            "approved_by": "user",
            "reasons": ["Approved by you", *decision.reasons],
            "agent_reason": "",
        }
    )
    approved = approved.model_copy(update={"summary": summarize(approved)})
    with conn:
        conn.execute(
            "UPDATE decisions SET verdict = ?, summary = ?, decision_json = ? WHERE decision_id = ?",
            (approved.verdict.value, approved.summary, approved.model_dump_json(), decision_id),
        )
        if remember:
            conn.execute(
                "INSERT OR IGNORE INTO remembered_approvals (action_id, session_id, created_at)"
                " VALUES (?, ?, ?)",
                (approved.action.action_id, approved.session_id, eastern_now().isoformat()),
            )
    return approved


def find_by_action(conn: sqlite3.Connection, action_id: str) -> Decision | None:
    """The saved decision for this action id, or None. Action ids are saved only once."""
    row = conn.execute(
        "SELECT decision_json FROM decisions WHERE action_id = ?", (action_id,)
    ).fetchone()
    return Decision.model_validate_json(row["decision_json"]) if row else None


def is_remembered(conn: sqlite3.Connection, action_id: str) -> bool:
    """Whether this action id was approved with "remember" (so the prompt can be skipped)."""
    row = conn.execute(
        "SELECT 1 FROM remembered_approvals WHERE action_id = ?", (action_id,)
    ).fetchone()
    return row is not None


def summarize(decision: Decision) -> str:
    """One line for `gatekeeper log`: verdict, what the action was, and the main reason."""
    action = decision.action
    target = action.command or action.path or action.url or action.tool_name
    target = " ".join(target.split())
    if len(target) > SUMMARY_TARGET_LIMIT:
        target = target[: SUMMARY_TARGET_LIMIT - 1] + "…"
    reason = decision.reasons[0] if decision.reasons else "no reason recorded"
    return f"{decision.verdict.value.upper()} {action.kind.value} `{target}`: {reason}"


def agent_reason(decision: Decision) -> str:
    """What the agent is told. Empty when allowed; never repeats sandbox or fake-secret details."""
    if decision.verdict == Verdict.ALLOW:
        return ""
    if decision.verdict == Verdict.ASK:
        return "Gatekeeper is waiting for the user to approve this action. Do not retry it."
    if decision.rules is not None and decision.rules.forced_verdict == Verdict.DENY:
        why = "; ".join(decision.rules.reasons)
        return f"Gatekeeper blocked this action: {why}. Choose a different approach."
    return "Gatekeeper blocked this action as unsafe. Choose a different approach or ask the user."
