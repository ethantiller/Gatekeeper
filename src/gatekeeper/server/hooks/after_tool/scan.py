import sqlite3
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from google import genai

from gatekeeper.core import decision_store
from gatekeeper.pipeline import untrusted
from gatekeeper.server.hooks.actions import action_id_for
from gatekeeper.server.hooks.after_tool.payload import AfterToolPayload

# Gatekeeper's own MCP tools scan what they return themselves (GK-7a), so the hook skips them.
OWN_MCP_PREFIX = "mcp__gatekeeper__"
MCP_PREFIX = "mcp__"
NETWORK_TAG = "network"


async def scan_tool_output(
    connection: sqlite3.Connection,
    gemini: genai.Client | None,
    payload: AfterToolPayload,
    repo_root: Path,
    sequence: int,
) -> dict[str, Any]:
    """Scan what a tool returned; reply with a hook block when it looks like an injection.

    Only the real tool's output is scanned here, never a sandbox run's.
    """
    action_id = action_id_for(payload.session_id, payload.tool_use_id)
    origin = _origin(connection, payload, repo_root, action_id)
    content = "\n".join(_strings(payload.tool_response))
    if origin is None or not content:
        return {}
    source, external = origin
    warning = await untrusted.scan_and_record(
        connection,
        gemini,
        session_id=payload.session_id,
        action_id=action_id,
        sequence=sequence,
        source=source,
        content=content,
        external=external,
    )
    return {"decision": "block", "reason": warning} if warning else {}


def _origin(
    connection: sqlite3.Connection, payload: AfterToolPayload, repo_root: Path, action_id: str
) -> tuple[str, bool] | None:
    """(source, is_external) for a tool whose output is read as content, else None.

    A file inside the repo is not external, so it is recorded only if it is suspicious. A file
    outside the repo, a URL, an MCP tool and the output of a network command always are.
    """
    tool_name, tool_input = payload.tool_name, payload.tool_input
    if tool_name == "Read" and isinstance(tool_input.get("file_path"), str):
        path = (Path(payload.cwd) / tool_input["file_path"]).resolve()
        if path.is_relative_to(repo_root.resolve()):
            return str(path.relative_to(repo_root.resolve())), False
        return str(path), True
    if tool_name == "WebFetch" and isinstance(tool_input.get("url"), str):
        return tool_input["url"], True
    if tool_name == "Bash":
        decision = decision_store.find_by_action(connection, action_id)
        command = decision.action.command if decision is not None else None
        tags = decision.rules.tags if decision is not None and decision.rules is not None else []
        return untrusted.display_source(f"output of: {command or 'a command'}"), NETWORK_TAG in tags
    if tool_name.startswith(MCP_PREFIX) and not tool_name.startswith(OWN_MCP_PREFIX):
        return tool_name, True
    return None


def _strings(value: Any) -> Iterator[str]:
    """Every string in a tool_response, whatever its shape (Claude Code and Codex differ)."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)
