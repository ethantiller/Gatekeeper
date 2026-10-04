"""The /hooks/{client}/<event> routes, one folder per event."""

from fastapi import APIRouter

from gatekeeper.server.hooks.after_tool import route as after_tool
from gatekeeper.server.hooks.before_tool import route as before_tool
from gatekeeper.server.hooks.prompt import route as prompt
from gatekeeper.server.hooks.session_start import route as session_start

router = APIRouter(prefix="/hooks/{client}")
for event in (session_start, prompt, before_tool, after_tool):
    router.include_router(event.router)
