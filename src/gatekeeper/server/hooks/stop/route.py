from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core import sounds
from gatekeeper.server.hooks.payload import HookPayload

router = APIRouter()


class StopPayload(HookPayload):
    """The agent finished a reply. Claude Code names the transcript; newer versions send the text."""

    transcript_path: str | None = None
    last_assistant_message: str | None = None


@router.post("/stop")
async def stop(payload: StopPayload, request: Request) -> dict[str, Any]:
    """Play a sound for the reply when useless mode is on. Always lets the agent stop."""
    conn = request.app.state.conn
    response = payload.last_assistant_message or sounds.last_assistant_text(payload.transcript_path)
    sounds.react_in_background(
        conn,
        request.app.state.gemini,
        payload.session_id,
        prompt=sounds.latest_prompt(conn, payload.session_id),
        response=response,
    )
    return {}
