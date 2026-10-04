from typing import Any

from gatekeeper.server.hooks.actions import ToolPayload


class AfterToolPayload(ToolPayload):
    tool_response: Any = None
