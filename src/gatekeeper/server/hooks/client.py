from enum import StrEnum

from gatekeeper.server.types import ActionSource


class HookClient(StrEnum):
    """The `{client}` in /hooks/{client}/<event>."""

    CLAUDE = "claude"
    CODEX = "codex"

    @property
    def source(self) -> ActionSource:
        return ActionSource(f"{self.value}_hook")
