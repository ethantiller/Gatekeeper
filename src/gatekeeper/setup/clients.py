"""Install, remove, pause and inspect Gatekeeper's entries in each client's config.

Existing files are merged into, never replaced; a `.bak` copy is written before the first
change. Gatekeeper's hook entries are recognised by their URL, so they can be found again.
"""

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from gatekeeper.server.auth import TOKEN_HEADER_NAME
from gatekeeper.setup import home, paths

CLAUDE = "claude"
CODEX = "codex"
VSCODE = "vscode"
CLIENTS = (CLAUDE, CODEX, VSCODE)

MCP_SERVER_NAME = "gatekeeper"
MCP_TOOL_NAMES = ("run_command", "write_file", "read_file", "fetch_url")
CONFIG_FILE_MODE = 0o600
QUICK_HOOK_SECONDS = 8
CLAUDE_TOOL_MATCHER = "^(Bash|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*)$"
CODEX_TOOL_MATCHER = "^(Bash|apply_patch|Edit|Write|mcp__.*)$"
CODEX_SESSION_MATCHER = "^(startup|resume|clear|compact)$"
CLAUDE_BEFORE_TOOL_SECONDS = 85
CODEX_BEFORE_TOOL_SECONDS = 325
HOOK_TIMEOUT_MARGIN_SECONDS = 5
SERVER_DOWN_MESSAGE = (
    "Gatekeeper server is not reachable, so this action was blocked. "
    "Ask the user to start it with: gatekeeper server start"
)

CODEX_TRUST_MESSAGE = (
    "Open Codex, run /hooks and trust the Gatekeeper hooks. Until you do, Codex is not protected."
)


class ClientConfigError(Exception):
    """Raised with a plain-language message when a client's config cannot be changed."""


@dataclass(frozen=True)
class Status:
    """What a client's config looks like: `ok`, `stale` (differs from what init writes), `missing`."""

    state: str
    paused: bool


def install(client: str) -> list[str]:
    """Add or repair Gatekeeper's entries for one client; return what changed."""
    changes = _INSTALLERS[client]()
    _clear_paused(client)
    return changes


def remove(client: str) -> list[str]:
    """Take Gatekeeper's entries out of one client's config; user entries stay."""
    _clear_paused(client)
    return _REMOVERS[client]()


def pause(client: str) -> list[str]:
    """Remove the entries but remember that Gatekeeper was paused, so `resume` and doctor know."""
    changes = remove(client)
    paths.paused_dir().mkdir(parents=True, exist_ok=True)
    (paths.paused_dir() / client).touch()
    return changes


def is_paused(client: str) -> bool:
    return (paths.paused_dir() / client).exists()


def status(client: str) -> Status:
    return Status(state=_STATUS_CHECKS[client](), paused=is_paused(client))


def config_path(client: str) -> Path:
    return {
        CLAUDE: paths.claude_settings_path(),
        CODEX: paths.codex_hooks_path(),
        VSCODE: paths.vscode_mcp_path(),
    }[client]


# --- hooks (Claude Code and Codex) ---------------------------------------------------------


def _curl_command(route: str, max_seconds: int, block_when_down: bool) -> str:
    base = (
        f"curl --silent --show-error --fail --max-time {max_seconds} --request POST"
        ' --header "Content-Type: application/json"'
        f' --header "{TOKEN_HEADER_NAME}: $(cat ~/.gatekeeper/token)"'
        f" --data-binary @- {paths.SERVER_URL}/hooks/{route}"
    )
    if not block_when_down:
        return f"{base} || true"
    denial = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": SERVER_DOWN_MESSAGE,
        }
    }
    return f"{base} || echo '{json.dumps(denial, separators=(',', ':'))}'"


def _hook_group(
    command: str, seconds: int, matcher: str | None = None
) -> dict[str, Any]:
    group: dict[str, Any] = {}
    if matcher:
        group["matcher"] = matcher
    group["hooks"] = [
        {"type": "command", "command": command, "timeout": seconds + HOOK_TIMEOUT_MARGIN_SECONDS}
    ]
    return group


def hooks_for(client: str) -> dict[str, list[dict[str, Any]]]:
    """The four Gatekeeper hooks for Claude Code or Codex, keyed by event name."""
    is_codex = client == CODEX
    tool_matcher = CODEX_TOOL_MATCHER if is_codex else CLAUDE_TOOL_MATCHER
    before_seconds = CODEX_BEFORE_TOOL_SECONDS if is_codex else CLAUDE_BEFORE_TOOL_SECONDS
    route = client
    quick = QUICK_HOOK_SECONDS
    return {
        "SessionStart": [
            _hook_group(
                _curl_command(f"{route}/session-start", quick, False),
                quick,
                CODEX_SESSION_MATCHER if is_codex else None,
            )
        ],
        "UserPromptSubmit": [_hook_group(_curl_command(f"{route}/prompt", quick, False), quick)],
        "PreToolUse": [
            _hook_group(
                _curl_command(f"{route}/before-tool", before_seconds, True),
                before_seconds,
                tool_matcher,
            )
        ],
        "PostToolUse": [
            _hook_group(_curl_command(f"{route}/after-tool", quick, False), quick, tool_matcher)
        ],
    }


def _is_ours(hook: dict[str, Any]) -> bool:
    return f"{paths.SERVER_URL}/hooks/" in str(hook.get("command", ""))


def _without_our_hooks(config: dict[str, Any]) -> dict[str, Any]:
    """A copy of `config` with Gatekeeper's hook entries removed (and empty groups dropped)."""
    hooks = config.get("hooks")
    if not isinstance(hooks, dict):
        return config
    kept: dict[str, Any] = {}
    for event, groups in hooks.items():
        remaining = []
        for group in groups if isinstance(groups, list) else []:
            inner = [hook for hook in group.get("hooks", []) if not _is_ours(hook)]
            if inner:
                remaining.append({**group, "hooks": inner})
        if remaining:
            kept[event] = remaining
    result = {key: value for key, value in config.items() if key != "hooks"}
    if kept:
        result["hooks"] = kept
    return result


def _with_our_hooks(config: dict[str, Any], client: str) -> dict[str, Any]:
    cleaned = _without_our_hooks(config)
    hooks = dict(cleaned.get("hooks", {}))
    for event, groups in hooks_for(client).items():
        hooks[event] = [*hooks.get(event, []), *groups]
    return {**cleaned, "hooks": hooks}


def _install_hooks(client: str) -> list[str]:
    path = config_path(client)
    config = _read_json(path)
    updated = _with_our_hooks(config, client)
    return [f"wrote hooks to {path}"] if _write_json(path, config, updated) else []


def _remove_hooks(client: str) -> list[str]:
    return _remove_hooks_at(config_path(client))


def _remove_hooks_at(path: Path, backup: bool = True) -> list[str]:
    if not path.exists():
        return []
    config = _read_json(path)
    updated = _without_our_hooks(config)
    if updated == config:
        return []
    _write_json(path, config, updated, backup)
    return [f"removed hooks from {path}"]


def _hooks_status(client: str) -> str:
    path = config_path(client)
    if not path.exists():
        return "missing"
    config = _read_json(path)
    if _without_our_hooks(config) == config:
        return "missing"
    return "ok" if _with_our_hooks(config, client) == config else "stale"


# --- VS Code (MCP server entry and custom agent) -------------------------------------------


def _mcp_entry() -> dict[str, Any]:
    return {
        "type": "http",
        "url": f"{paths.SERVER_URL}/mcp",
        "headers": {TOKEN_HEADER_NAME: home.read_token()},
    }


def agent_file_text() -> str:
    """The VS Code custom agent: it may use only Gatekeeper's MCP tools."""
    tools = ", ".join(f"'{MCP_SERVER_NAME}/{name}'" for name in MCP_TOOL_NAMES)
    return (
        "---\n"
        "description: Works only through Gatekeeper, which checks every command, file write and "
        "fetch before it runs.\n"
        f"tools: [{tools}]\n"
        "---\n"
        "You are protected by Gatekeeper. Use only the Gatekeeper tools to run commands, read and "
        "write files and fetch URLs. If a tool call is denied or needs approval, tell the user "
        "and do not look for another way around it.\n"
    )


def _install_vscode() -> list[str]:
    changes: list[str] = []
    path = paths.vscode_mcp_path()
    config = _read_json(path)
    servers = dict(config.get("servers", {}))
    servers[MCP_SERVER_NAME] = _mcp_entry()
    if _write_json(path, config, {**config, "servers": servers}):
        changes.append(f"added the MCP server to {path}")
    agent = paths.vscode_agent_path()
    if not agent.exists() or agent.read_text() != agent_file_text():
        agent.parent.mkdir(parents=True, exist_ok=True)
        agent.write_text(agent_file_text())
        changes.append(f"wrote the Gatekeeper agent to {agent}")
    return changes


def _remove_mcp_entry_at(path: Path, backup: bool = True) -> list[str]:
    """Remove only the `gatekeeper` server from an MCP file (`servers` or `mcpServers`)."""
    if not path.exists():
        return []
    config = _read_json(path)
    updated = dict(config)
    for key in ("servers", "mcpServers"):
        servers = config.get(key)
        if isinstance(servers, dict) and MCP_SERVER_NAME in servers:
            updated[key] = {name: value for name, value in servers.items() if name != MCP_SERVER_NAME}
    if updated == config:
        return []
    _write_json(path, config, updated, backup)
    return [f"removed the gatekeeper MCP server from {path}"]


def _remove_vscode() -> list[str]:
    changes = _remove_mcp_entry_at(paths.vscode_mcp_path())
    agent = paths.vscode_agent_path()
    if agent.exists():
        agent.unlink()
        changes.append(f"deleted {agent}")
    return changes


def remove_project(client: str, repo_root: Path) -> list[str]:
    """Remove Gatekeeper's entries from this repo's own config files for one client.

    Only the Gatekeeper hooks or MCP server are taken out; every other key stays, and the
    files are never deleted. No `.bak` copies: the repo's git history has the originals.
    """
    if client == CLAUDE:
        hook_files = [repo_root / ".claude" / "settings.json", repo_root / ".claude" / "settings.local.json"]
        mcp_files: list[Path] = []
    elif client == CODEX:
        hook_files, mcp_files = [repo_root / ".codex" / "hooks.json"], []
    else:
        hook_files, mcp_files = [], [repo_root / ".mcp.json", repo_root / ".vscode" / "mcp.json"]
    changes: list[str] = []
    for path in hook_files:
        changes += _remove_hooks_at(path, backup=False)
    for path in mcp_files:
        changes += _remove_mcp_entry_at(path, backup=False)
    return changes


def _vscode_status() -> str:
    path = paths.vscode_mcp_path()
    entry = _read_json(path).get("servers", {}).get(MCP_SERVER_NAME) if path.exists() else None
    agent = paths.vscode_agent_path()
    if entry is None and not agent.exists():
        return "missing"
    agent_ok = agent.exists() and agent.read_text() == agent_file_text()
    return "ok" if entry == _mcp_entry() and agent_ok else "stale"


# --- file helpers --------------------------------------------------------------------------


def _read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text() or "{}")
    except (OSError, json.JSONDecodeError) as error:
        raise ClientConfigError(
            f"{path} is not valid JSON ({error}). Comments are not supported; fix or remove the "
            "file and try again. Nothing was changed."
        ) from error
    if not isinstance(data, dict):
        raise ClientConfigError(f"{path} must contain a JSON object. Nothing was changed.")
    return data


def _write_json(
    path: Path, before: dict[str, Any], after: dict[str, Any], backup: bool = True
) -> bool:
    """Write `after` if it differs from `before`, backing up the original once; True if written.

    The file's own indentation is kept so only Gatekeeper's entries show up in a diff.
    """
    if path.exists() and before == after:
        return False
    if not path.exists() and not after:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    indent: str | int = 2
    mode = CONFIG_FILE_MODE
    if path.exists():
        original = path.read_text()
        indent = "\t" if "\n\t" in original else 2
        mode = path.stat().st_mode & 0o777
        backup_path = path.with_name(path.name + ".bak")
        if backup and not backup_path.exists():
            backup_path.write_text(original)
            backup_path.chmod(CONFIG_FILE_MODE)
    if path == paths.vscode_mcp_path():
        mode = CONFIG_FILE_MODE  # holds the token
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(after, indent=indent) + "\n")
    temporary.chmod(mode)
    os.replace(temporary, path)
    return True


def _clear_paused(client: str) -> None:
    (paths.paused_dir() / client).unlink(missing_ok=True)


_INSTALLERS = {
    CLAUDE: lambda: _install_hooks(CLAUDE),
    CODEX: lambda: _install_hooks(CODEX),
    VSCODE: _install_vscode,
}
_REMOVERS = {
    CLAUDE: lambda: _remove_hooks(CLAUDE),
    CODEX: lambda: _remove_hooks(CODEX),
    VSCODE: _remove_vscode,
}
_STATUS_CHECKS = {
    CLAUDE: lambda: _hooks_status(CLAUDE),
    CODEX: lambda: _hooks_status(CODEX),
    VSCODE: _vscode_status,
}
