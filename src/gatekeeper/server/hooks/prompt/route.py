from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core import sounds
from gatekeeper.core.sessions import record_prompt
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.hooks.payload import HookPayload

router = APIRouter()


class PromptPayload(HookPayload):
    prompt: str


@router.post("/prompt")
async def prompt(client: HookClient, payload: PromptPayload, request: Request) -> dict[str, Any]:
    """Count and save the user's prompt, and play a sound for it when useless mode is on."""
    conn = request.app.state.conn
    record_prompt(conn, payload.session_id, payload.cwd, payload.prompt, client.source)
    sounds.react_in_background(
        conn, request.app.state.gemini, payload.session_id, prompt=payload.prompt
    )
    return {}
