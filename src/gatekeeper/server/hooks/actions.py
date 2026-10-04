"""Tool call in a hook payload to StandardAction. The only place that reads client tool fields."""

import difflib
import shlex
from pathlib import Path
from typing import Any
from uuid import UUID, uuid5

from gatekeeper.server.hooks.client import HookClient
from gatekeeper.server.hooks.codex_patch import patch_text, split_patch
from gatekeeper.server.hooks.payload import HookPayload
from gatekeeper.server.types import ActionKind, StandardAction

# Fixed so the same session and tool_use_id always give the same action id.
ACTION_ID_NAMESPACE = UUID("6f1d3c52-8a0e-4b8e-9d55-2f4c1a7e9b30")
MAX_DIFF_CHARACTERS = 200_000  # difflib is slow on huge inputs, and the judge reads 2,000
SHELL_PROGRAMS = {"bash", "sh", "zsh"}
SHELL_SCRIPT_FLAGS = {"-c", "-lc"}


class ToolPayload(HookPayload):
    """A before-tool or after-tool hook body."""

    tool_name: str
    tool_input: dict[str, Any]
    tool_use_id: str


def action_id_for(session_id: str, tool_use_id: str, file_path: str = "") -> str:
    """The action id for one tool call, so a hook retry and the after-tool hook find its decision.

    A patch that touches several files has one action per file, told apart by the path.
    """
    return str(uuid5(ACTION_ID_NAMESPACE, f"{session_id}:{tool_use_id}:{file_path}"))


def to_actions(client: HookClient, payload: ToolPayload, sequence: int) -> list[StandardAction]:
    """The actions one tool call performs. A Codex patch has one write per file it touches."""
    if payload.tool_name == "apply_patch":
        return _patch_actions(client, payload, sequence)
    return [_action(client, payload, sequence, **_action_fields(payload.tool_name, payload.tool_input, payload.cwd))]


def _action(
    client: HookClient, payload: ToolPayload, sequence: int, file_path: str = "", **fields: Any
) -> StandardAction:
    for name in ("command", "path", "content", "url"):
        if fields.get(name) is not None and not isinstance(fields[name], str):
            fields[name] = str(fields[name])
    return StandardAction(
        action_id=action_id_for(payload.session_id, payload.tool_use_id, file_path),
        session_id=payload.session_id,
        sequence=sequence,
        source=client.source,
        tool_name=payload.tool_name,
        cwd=payload.cwd,
        raw=payload.model_dump(),
        **fields,
    )


def _patch_actions(client: HookClient, payload: ToolPayload, sequence: int) -> list[StandardAction]:
    """One write_file action per file in the patch, each with only its own diff."""
    text = patch_text(payload.tool_input)
    files = split_patch(text) if text else []
    if not files:
        # Unreadable patch: kind `other` with the raw text, so the judge still sees what it is.
        return [_action(client, payload, sequence, kind=ActionKind.OTHER, content=text)]
    actions = []
    for file_patch in files:
        # A move also writes the destination, so both paths are checked.
        for path in (file_patch.path, file_patch.moved_to):
            if path:
                actions.append(
                    _action(
                        client, payload, sequence, path,
                        kind=ActionKind.WRITE_FILE, path=path, content=file_patch.diff,
                    )
                )
    return actions


def _action_fields(tool_name: str, tool_input: dict[str, Any], cwd: str) -> dict[str, Any]:
    """The StandardAction kind and target for one tool. Unknown tools are kind `other`."""
    if tool_name == "Bash":
        return {"kind": ActionKind.RUN_COMMAND, "command": _command_text(tool_input.get("command"))}
    if tool_name == "Write":
        path = _target_path(cwd, tool_input.get("file_path"))
        return {
            "kind": ActionKind.WRITE_FILE,
            "path": tool_input.get("file_path"),
            "content": _unified_diff(_current_text(path), tool_input.get("content") or "", path),
        }
    if tool_name in ("Edit", "MultiEdit"):
        path = _target_path(cwd, tool_input.get("file_path"))
        return {
            "kind": ActionKind.WRITE_FILE,
            "path": tool_input.get("file_path"),
            "content": _edit_diff(path, tool_input.get("edits") or [tool_input]),
        }
    if tool_name == "NotebookEdit":
        return {
            "kind": ActionKind.WRITE_FILE,
            "path": tool_input.get("notebook_path"),
            "content": tool_input.get("new_source"),
        }
    if tool_name == "Read":
        return {"kind": ActionKind.READ_FILE, "path": tool_input.get("file_path")}
    if tool_name == "WebFetch":
        return {"kind": ActionKind.FETCH_URL, "url": tool_input.get("url")}
    return {"kind": ActionKind.OTHER}


def _command_text(command: Any) -> str | None:
    """The shell command as one string. Codex may send an argv list such as bash -lc <script>."""
    if not isinstance(command, list):
        return command
    if (
        len(command) == 3
        and Path(command[0]).name in SHELL_PROGRAMS
        and command[1] in SHELL_SCRIPT_FLAGS
    ):
        return command[2]
    return shlex.join(command)


def _target_path(cwd: str, file_path: str | None) -> Path | None:
    return Path(cwd) / file_path if file_path else None


def _current_text(path: Path | None) -> str:
    """The file as it is now, or "" for a new file."""
    if path is None:
        return ""
    try:
        # A FIFO or device such as /dev/zero would block or fill memory when read.
        if not path.is_file():
            return ""
        with path.open(encoding="utf-8", errors="replace") as file:
            return file.read(MAX_DIFF_CHARACTERS)
    except OSError:
        # Missing or unreadable: the whole new text shows as added, which hides nothing.
        return ""


def _edit_diff(path: Path | None, edits: list[dict[str, Any]]) -> str:
    """The diff that applying Claude's Edit (or MultiEdit) edits to the file would make."""
    before = _current_text(path)
    after = before
    for edit in edits:
        old_text, new_text = edit.get("old_string", ""), edit.get("new_string", "")
        if not old_text or old_text not in after:
            # Claude Code rejects such an edit (or it creates a file); show what was asked for.
            return "".join(
                _unified_diff(requested.get("old_string", ""), requested.get("new_string", ""), path)
                for requested in edits
            )
        after = after.replace(old_text, new_text, -1 if edit.get("replace_all") else 1)
    return _unified_diff(before, after, path)


def _unified_diff(before: str, after: str, path: Path | None) -> str:
    name = str(path) if path else "file"
    return "".join(
        difflib.unified_diff(
            before[:MAX_DIFF_CHARACTERS].splitlines(keepends=True),
            after[:MAX_DIFF_CHARACTERS].splitlines(keepends=True),
            fromfile=f"a/{name}",
            tofile=f"b/{name}",
        )
    )
