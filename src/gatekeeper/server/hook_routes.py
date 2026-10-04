import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeoutError
from pathlib import Path

import requests
import yaml
from docker.errors import DockerException
from fastapi import APIRouter, Request

from gatekeeper.core.sessions import record_prompt, start_session
from gatekeeper.database import CONNECTION_LOCK
from gatekeeper.pipeline.rules import (
    REPOSITORY_OVERRIDE_KEYS,
    REPOSITORY_RULES_NAME,
    load_rules,
)
from gatekeeper.sandbox.environment import SandboxEnvironmentError
from gatekeeper.sandbox.repo_images import RepoImageState, start_repo_image_build
from gatekeeper.server.types import (
    GatekeeperModel,
    PromptPayload,
    SessionStartHookOutput,
    SessionStartPayload,
    SessionStartResponse,
    SessionStartSource,
    Verdict,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/hooks")

# The hook has a 5 second limit, and starting the build first asks git and Docker, which can
# be slow. Past this many seconds the reply goes out and the build keeps starting without us.
IMAGE_BUILD_START_WAIT_SECONDS = 2
image_build_starter = ThreadPoolExecutor(max_workers=2, thread_name_prefix="repo-image-start")

IMAGE_STATE_DESCRIPTIONS = {
    RepoImageState.NONE: "none (no lockfile or commit, so the base image is used)",
    RepoImageState.BUILDING: "building in the background",
    RepoImageState.READY: "ready",
    RepoImageState.FAILED: "failed to build",
}


class HookResponse(GatekeeperModel):
    verdict: Verdict


def _database_connection(request: Request) -> sqlite3.Connection:
    """The connection opened once at server startup (see create_app)."""
    return request.app.state.conn


def _repo_rules_file_applies(repo_root: Path) -> bool:
    """Whether the repo's .gatekeeper.yaml sets anything Gatekeeper accepts from a repo."""
    repo_rules_path = repo_root / REPOSITORY_RULES_NAME
    if not repo_rules_path.exists():
        return False
    with repo_rules_path.open(encoding="utf-8") as repo_rules_file:
        repo_rules = yaml.safe_load(repo_rules_file)  # load_rules already proved it is a mapping
    return bool(REPOSITORY_OVERRIDE_KEYS & repo_rules.keys())


def _describe_rules(repo_root: Path) -> tuple[str, bool]:
    """A one-line note on the loaded rules, and whether useless mode is on."""
    try:
        loaded_rules = load_rules(repo_root)
        repo_rules_apply = _repo_rules_file_applies(repo_root)
    except (RuntimeError, TypeError, ValueError, OSError, yaml.YAMLError) as rules_error:
        logger.warning("Could not load rules for %s: %s", repo_root, rules_error)
        return f"Rules could not be loaded ({rules_error}).", False

    if repo_rules_apply:
        rules_source = f"default rules plus {REPOSITORY_RULES_NAME}"
    elif (repo_root / REPOSITORY_RULES_NAME).exists():
        rules_source = f"default rules ({REPOSITORY_RULES_NAME} sets nothing a repo is allowed to set)"
    else:
        rules_source = "default rules"

    useless_mode_settings = loaded_rules.get("useless_mode")
    useless_mode_enabled = (
        isinstance(useless_mode_settings, dict) and bool(useless_mode_settings.get("enabled", False))
    )
    return f"Rules loaded: {rules_source}.", useless_mode_enabled


def _start_image_build(repo_root: Path) -> RepoImageState | None:
    """Start the repo image build in the background; None if Docker or git was unavailable."""
    try:
        return start_repo_image_build(repo_root).state
    except (SandboxEnvironmentError, DockerException, requests.exceptions.RequestException) as build_error:
        logger.warning("Could not start the repo image build for %s: %s", repo_root, build_error)
        return None


def _describe_image_build(repo_root: Path) -> str:
    """Start the build and say where it stands, without holding the reply past the hook's limit."""
    image_build_start = image_build_starter.submit(_start_image_build, repo_root)
    try:
        image_state = image_build_start.result(timeout=IMAGE_BUILD_START_WAIT_SECONDS)
    except FutureTimeoutError:
        return "still being checked (the build starts in the background)"
    return IMAGE_STATE_DESCRIPTIONS[image_state] if image_state is not None else "unavailable"


def _session_start_context(
    source: SessionStartSource,
    repo_root: Path,
    rules_description: str,
    useless_mode_enabled: bool,
    image_description: str,
) -> str:
    """The text Claude gets at session start. Never includes the tripwire seed."""
    started_again = source in (SessionStartSource.RESUME, SessionStartSource.COMPACT)
    opening = "Gatekeeper is still active" if started_again else "Gatekeeper is active"
    return "\n".join(
        [
            f"{opening} for this session. Commands, file writes and web fetches are checked"
            " before they run; a risky one can be denied or held for the user's approval.",
            "If an action is denied, do not try to get around it. Tell the user what was blocked.",
            f"Repository: {repo_root}. {rules_description}",
            f"Sandbox image: {image_description}.",
            f"Useless mode: {'on' if useless_mode_enabled else 'off'}.",
        ]
    )


@router.post("/session-start")
def session_start(hook_payload: SessionStartPayload, request: Request) -> dict:
    with CONNECTION_LOCK:
        session = start_session(_database_connection(request), hook_payload)
    rules_description, useless_mode_enabled = _describe_rules(session.repo_root)
    image_description = _describe_image_build(session.repo_root)

    response = SessionStartResponse(
        hook_specific_output=SessionStartHookOutput(
            additional_context=_session_start_context(
                hook_payload.source,
                session.repo_root,
                rules_description,
                useless_mode_enabled,
                image_description,
            )
        )
    )
    return response.model_dump(by_alias=True)


@router.post("/prompt")
def prompt(hook_payload: PromptPayload, request: Request) -> dict:
    with CONNECTION_LOCK:
        record_prompt(_database_connection(request), hook_payload)
    return {}  # nothing to add to the prompt


@router.post("/before-tool")
def before_tool() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)


@router.post("/after-tool")
def after_tool() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)
