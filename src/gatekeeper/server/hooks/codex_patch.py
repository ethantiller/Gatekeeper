"""Splits a Codex `apply_patch` patch into the files it touches."""

from dataclasses import dataclass, field
from typing import Any

PATCH_KEYS = ("command", "input", "patch")
FILE_HEADERS = ("*** Add File: ", "*** Update File: ", "*** Delete File: ")
MOVE_HEADER = "*** Move to: "


@dataclass
class FilePatch:
    """One file's part of a patch."""

    path: str
    moved_to: str | None = None
    diff_lines: list[str] = field(default_factory=list)

    @property
    def diff(self) -> str:
        return "\n".join(self.diff_lines)


def patch_text(tool_input: dict[str, Any]) -> str | None:
    """The patch text in an apply_patch tool_input, whether it is a string or an argv list."""
    for key in PATCH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, list):
            value = value[-1] if value else None
        if isinstance(value, str):
            return value
    return None


def split_patch(text: str) -> list[FilePatch]:
    """One FilePatch per `*** Add/Update/Delete File:` section, in order."""
    files: list[FilePatch] = []
    for line in text.splitlines():
        header = next((header for header in FILE_HEADERS if line.startswith(header)), None)
        if header is not None:
            files.append(FilePatch(path=line.removeprefix(header).strip(), diff_lines=[line]))
        elif files and line.startswith(MOVE_HEADER):
            files[-1].moved_to = line.removeprefix(MOVE_HEADER).strip()
            files[-1].diff_lines.append(line)
        elif files and line != "*** End Patch":
            files[-1].diff_lines.append(line)
    return files
