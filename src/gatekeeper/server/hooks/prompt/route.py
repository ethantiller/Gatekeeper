from typing import Any

from fastapi import APIRouter, Request

from gatekeeper.core.sessions import record_prompt
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.hooks.payload import HookPayload

router = APIRouter()


class PromptPayload(HookPayload):
    prompt: str


@router.post("/prompt")
async def prompt(client: HookClient, payload: PromptPayload, request: Request) -> dict[str, Any]:
    """Count and save the user's prompt."""
    record_prompt(
        request.app.state.conn, payload.session_id, payload.cwd, payload.prompt, client.source
    )
    return {}
