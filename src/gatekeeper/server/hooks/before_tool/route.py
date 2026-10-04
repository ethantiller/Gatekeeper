from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core.sessions import count_action
from gatekeeper.pipeline import decide as decide_module
from gatekeeper.server.hooks.actions import ToolPayload, to_actions
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.types import Decision, Verdict

router = APIRouter()

STRICTNESS = {Verdict.ALLOW: 0, Verdict.ASK: 1, Verdict.DENY: 2}
DEFAULT_ASK_REASON = "Gatekeeper wants your approval before this runs."
DEFAULT_DENY_REASON = "Gatekeeper blocked this action as unsafe. Choose a different approach."
# Codex parses "ask" but ignores it, which would run the tool. Until `gatekeeper approve` exists
# (GK-7b), an ask has to be a deny.
CODEX_ASK_REASON = (
    "Gatekeeper needs the user's approval for this action, and approving from Codex is not"
    " available yet. Do not retry it; tell the user what you were trying to do."
)


# async so handlers run one at a time on the event loop and share the one SQLite connection safely.
@router.post("/before-tool")
async def before_tool(
    client: HookClient, payload: ToolPayload, request: Request
) -> dict[str, Any]:
    """Decide on a tool call before it runs and answer in the client's hook format."""
    connection = request.app.state.conn
    session, sequence = count_action(connection, payload.session_id, payload.cwd, client.source)
    decisions = [
        await decide_module.decide(action, session, connection, request.app.state.gemini)
        for action in to_actions(client, payload, sequence)
    ]
    strictest = max(decisions, key=lambda decision: STRICTNESS[decision.verdict])
    return _hook_reply(client, strictest)


def _hook_reply(client: HookClient, decision: Decision) -> dict[str, Any]:
    """Allow replies {} so the client's own permission rules still apply."""
    if decision.verdict == Verdict.ALLOW:
        return {}
    if decision.verdict == Verdict.ASK and client == HookClient.CLAUDE:
        return _permission_reply("ask", decision.summary or DEFAULT_ASK_REASON)
    if decision.verdict == Verdict.ASK:
        return _permission_reply("deny", CODEX_ASK_REASON)
    # agent_reason never repeats sandbox output or fake-secret details, unlike summary.
    return _permission_reply("deny", decision.agent_reason or DEFAULT_DENY_REASON)


def _permission_reply(permission_decision: str, reason: str) -> dict[str, Any]:
    return {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": permission_decision,
            "permissionDecisionReason": reason,
        }
    }
