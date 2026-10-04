"""Where Gatekeeper and the clients it configures keep their files.

Everything is computed from `Path.home()` at call time so a temporary HOME works in tests.
"""

import sys
from pathlib import Path

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8787
SERVER_URL = f"http://{SERVER_HOST}:{SERVER_PORT}"
SERVICE_LABEL = "com.gatekeeper.server"
SYSTEMD_UNIT_NAME = "gatekeeper.service"


def is_macos() -> bool:
    return sys.platform == "darwin"


def gatekeeper_home() -> Path:
    return Path.home() / ".gatekeeper"


def token_path() -> Path:
    return gatekeeper_home() / "token"


def rules_path() -> Path:
    return gatekeeper_home() / "rules.yaml"


def env_path() -> Path:
    return gatekeeper_home() / ".env"


def log_path() -> Path:
    return gatekeeper_home() / "server.log"


def pid_path() -> Path:
    return gatekeeper_home() / "server.pid"


def paused_dir() -> Path:
    return gatekeeper_home() / "paused"


def launchd_plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{SERVICE_LABEL}.plist"


def systemd_unit_path() -> Path:
    return Path.home() / ".config" / "systemd" / "user" / SYSTEMD_UNIT_NAME


def claude_settings_path() -> Path:
    return Path.home() / ".claude" / "settings.json"


def codex_hooks_path() -> Path:
    return Path.home() / ".codex" / "hooks.json"


def vscode_user_dir() -> Path:
    if is_macos():
        return Path.home() / "Library" / "Application Support" / "Code" / "User"
    return Path.home() / ".config" / "Code" / "User"


def vscode_mcp_path() -> Path:
    return vscode_user_dir() / "mcp.json"


def vscode_agent_path() -> Path:
    return vscode_user_dir() / "prompts" / "gatekeeper.agent.md"
