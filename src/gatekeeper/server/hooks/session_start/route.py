import logging
import threading
from pathlib import Path
from typing import Any

from docker.errors import DockerException
from fastapi import APIRouter, Request

from gatekeeper.core import sounds
from gatekeeper.core.sessions import ensure_session
from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.repo_images import start_repo_image_build
from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.hooks.payload import HookPayload

logger = logging.getLogger(__name__)

router = APIRouter()

CONTEXT = (
    "Gatekeeper is active for this session. Commands, file writes and web fetches are checked"
    " before they run. If an action is denied, do not try to get around it; tell the user."
)


def _start_image_build(repo_root: Path) -> None:
    """Build the repo's sandbox image in the background; without it, runs use the base image."""
    try:
        start_repo_image_build(repo_root)
    except (SandboxEnvironmentError, DockerException) as error:
        logger.warning("Could not start the repo image build for %s: %s", repo_root, error)


# async so handlers run one at a time on the event loop and share the one SQLite connection safely.
@router.post("/session-start")
async def session_start(
    client: HookClient, payload: HookPayload, request: Request
) -> dict[str, Any]:
    """Create or refresh the session. Every source (startup, resume, compact, clear) is the same."""
    conn = request.app.state.conn
    is_new = (
        conn.execute("SELECT 1 FROM sessions WHERE session_id = ?", (payload.session_id,)).fetchone()
        is None
    )
    repo_root = ensure_session(conn, payload.session_id, payload.cwd, client.source)
    if is_new and client == HookClient.CLAUDE:  # resumed and compacted chats already exist
        sounds.announce_new_session(conn, payload.session_id)
    # On a thread: finding the build plan asks git and Docker, which must not delay the reply.
    threading.Thread(target=_start_image_build, args=(Path(repo_root),), daemon=True).start()
    return {
        "hookSpecificOutput": 
        {
            "hookEventName": "SessionStart", 
            "additionalContext": CONTEXT
        }
    }
