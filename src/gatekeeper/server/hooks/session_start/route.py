from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core.sessions import ensure_session
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.hooks.payload import HookPayload

router = APIRouter()

CONTEXT = (
    "Gatekeeper is active for this session. Commands, file writes and web fetches are checked"
    " before they run. If an action is denied, do not try to get around it; tell the user."
)


# async so handlers run one at a time on the event loop and share the one SQLite connection safely.
@router.post("/session-start")
async def session_start(
    client: HookClient, payload: HookPayload, request: Request
) -> dict[str, Any]:
    """Create or refresh the session. Every source (startup, resume, compact, clear) is the same."""
    ensure_session(request.app.state.conn, payload.session_id, payload.cwd, client.source)
    return {
        "hookSpecificOutput": 
        {
            "hookEventName": "SessionStart", 
            "additionalContext": CONTEXT
        }
    }
