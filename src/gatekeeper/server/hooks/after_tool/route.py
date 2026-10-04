import sqlite3
from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core import decision_store
from gatekeeper.core.sessions import count_action
from gatekeeper.server.hooks.actions import action_id_for
from gatekeeper.server.hooks.after_tool.payload import AfterToolPayload
from gatekeeper.server.hooks.after_tool.scan import scan_tool_output
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.types import Verdict

router = APIRouter()


# async so handlers run one at a time on the event loop and share the one SQLite connection safely.
@router.post("/after-tool")
async def after_tool(
    client: HookClient, payload: AfterToolPayload, request: Request
) -> dict[str, Any]:
    """Count the finished tool call, record a Claude approval, and scan the tool's output.

    Replies a block with a warning when the output looks like instructions to the agent.
    """
    connection = request.app.state.conn
    session, sequence = count_action(connection, payload.session_id, payload.cwd, client.source)
    if client == HookClient.CLAUDE:
        _record_approval_if_asked(connection, payload)
    return await scan_tool_output(
        connection, request.app.state.gemini, payload, session.repo_root, sequence
    )


def _record_approval_if_asked(connection: sqlite3.Connection, payload: AfterToolPayload) -> None:
    """Claude Code runs a tool only after the user approves an ask, so a PostToolUse means yes.

    Codex has no such step: its approval is recorded during the before-tool request itself.
    """
    action_id = action_id_for(payload.session_id, payload.tool_use_id)
    decision = decision_store.find_by_action(connection, action_id)
    if decision is not None and decision.verdict == Verdict.ASK:
        decision_store.record_approval(connection, decision.decision_id, remember=False)
