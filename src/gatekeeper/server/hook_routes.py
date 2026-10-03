from fastapi import APIRouter

from gatekeeper.server.types import GatekeeperModel, Verdict

router = APIRouter(prefix="/hooks")


class HookResponse(GatekeeperModel):
    verdict: Verdict


#To be implemented fully in GK-6
@router.post("/session-start")
def session_start() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)


@router.post("/prompt")
def prompt() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)


@router.post("/before-tool")
def before_tool() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)


@router.post("/after-tool")
def after_tool() -> HookResponse:
    return HookResponse(verdict=Verdict.ALLOW)
