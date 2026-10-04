"""`gatekeeper doctor`: checks that Gatekeeper is set up and working, with a fix for each failure."""

import os
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from dotenv import dotenv_values
from google import genai
from google.genai import types

from gatekeeper import database
from gatekeeper.client.gemini_client import DEFAULT_MODEL, TIMEOUT_MS
from gatekeeper.pipeline.rules import UserRulesError, load_user_rules
from gatekeeper.sandbox.environment import SandboxEnvironmentError, get_status
from gatekeeper.server.types import ActionSource
from gatekeeper.setup import clients, home, paths, service


class Level(StrEnum):
    OK = "ok"
    WARNING = "warning"
    FAILED = "failed"


ICONS = {Level.OK: "✅", Level.WARNING: "⚠️ ", Level.FAILED: "❌"}


@dataclass(frozen=True)
class Check:
    name: str
    level: Level
    message: str

    def line(self) -> str:
        return f"{ICONS[self.level]} {self.name}: {self.message}"


def run_checks() -> list[Check]:
    """Run every check. A check that raises is reported as failed instead of stopping the rest."""
    checks: list[Callable[[], Check]] = [
        check_server,
        check_rules,
        check_docker,
        check_llm_key,
        lambda: check_hooks(clients.CLAUDE, "Claude Code hooks"),
        check_codex,
        check_vscode,
    ]
    results = []
    for check in checks:
        try:
            results.append(check())
        except Exception as error:  # noqa: BLE001
            results.append(Check("doctor", Level.FAILED, f"a check crashed: {error}"))
    return results


def has_failure(checks: list[Check]) -> bool:
    return any(check.level == Level.FAILED for check in checks)


def check_server() -> Check:
    if service.server_is_up():
        return Check("Server", Level.OK, f"answering on {paths.SERVER_URL}")
    return Check(
        "Server",
        Level.FAILED,
        f"not answering on {paths.SERVER_URL}. Start it with `gatekeeper server start`; "
        f"its log is {paths.log_path()}",
    )


def check_rules() -> Check:
    try:
        load_user_rules()
    except UserRulesError as error:
        return Check("Rules", Level.FAILED, f"{error}. Fix the file or delete it and rerun init")
    return Check("Rules", Level.OK, "defaults and your rules.yaml load")


def check_docker() -> Check:
    try:
        status = get_status()
    except SandboxEnvironmentError as error:
        return Check(
            "Docker", Level.FAILED, f"{error}. Start Docker, then rerun `gatekeeper init`"
        )
    if not status.ok:
        return Check(
            "Docker",
            Level.FAILED,
            "the sandbox environment is not ready "
            f"(image {status.base_image_present}, network {status.network_present}, "
            f"logger {status.logger_state}). Start Docker and rerun `gatekeeper init`",
        )
    return Check("Docker", Level.OK, "sandbox image, network and logger are ready")


def _api_key() -> str | None:
    return os.environ.get(home.API_KEY_NAME) or dotenv_values(paths.env_path()).get(
        home.API_KEY_NAME
    )


def check_llm_key() -> Check:
    api_key = _api_key()
    if not api_key:
        return Check(
            "LLM key",
            Level.WARNING,
            f"{home.API_KEY_NAME} is not set. Gatekeeper still works, but every action the judge "
            "would rate is asked instead. Add the key to ~/.gatekeeper/.env",
        )
    model = os.environ.get(home.MODEL_NAME) or dotenv_values(paths.env_path()).get(
        home.MODEL_NAME, DEFAULT_MODEL
    )
    try:
        client = genai.Client(api_key=api_key, http_options=types.HttpOptions(timeout=TIMEOUT_MS))
        client.models.generate_content(
            model=model,
            contents="Reply with one word.",
            config=types.GenerateContentConfig(
                max_output_tokens=1,
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            ),
        )
    except Exception as error:  # noqa: BLE001
        return Check(
            "LLM key",
            Level.WARNING,
            f"the test call failed ({type(error).__name__}). Actions the judge would rate are "
            "asked instead. Check the key in ~/.gatekeeper/.env",
        )
    return Check("LLM key", Level.OK, f"{model} answered")


def check_hooks(client: str, name: str) -> Check:
    state = clients.status(client)
    if state.paused:
        return Check(name, Level.WARNING, "paused. Run `gatekeeper resume` to turn them back on")
    if state.state == "ok":
        return Check(name, Level.OK, f"installed in {clients.config_path(client)}")
    problem = "are not installed" if state.state == "missing" else "are out of date"
    return Check(name, Level.FAILED, f"{problem}. Rerun `gatekeeper init`")


def _codex_event_seen() -> bool:
    try:
        conn = database.connect()
    except (OSError, sqlite3.Error):
        return False
    try:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE source = ? LIMIT 1", (ActionSource.CODEX_HOOK.value,)
        ).fetchone()
    finally:
        conn.close()
    return row is not None


def check_codex() -> Check:
    installed = check_hooks(clients.CODEX, "Codex hooks")
    if installed.level != Level.OK:
        return installed
    if _codex_event_seen():
        return Check("Codex hooks", Level.OK, "the server has received Codex hook events")
    return Check(
        "Codex hooks",
        Level.FAILED,
        "Codex hooks are installed but have never run. Open Codex, run /hooks, trust them, "
        "then start a session.",
    )


def check_vscode() -> Check:
    state = clients.status(clients.VSCODE)
    if state.paused:
        return Check("VS Code", Level.WARNING, "paused. Run `gatekeeper resume` to turn it back on")
    if state.state == "ok":
        return Check(
            "VS Code",
            Level.OK,
            "MCP server and the Gatekeeper agent exist. In VS Code's chat, pick the "
            "Gatekeeper agent",
        )
    problem = "is not set up" if state.state == "missing" else "is out of date"
    return Check("VS Code", Level.FAILED, f"{problem}. Rerun `gatekeeper init`")
