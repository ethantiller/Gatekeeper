"""Finds the script files a command runs, so the judge reads what the script does too.

`sh scripts/bootstrap.sh` says nothing about its contents. A repo's own script is as
untrusted as any file the agent reads, and the agent often runs it without opening it.
"""

import os
import re
from dataclasses import dataclass
from pathlib import Path

from gatekeeper.pipeline.parser import TRANSPARENT_WRAPPERS
from gatekeeper.server.types import ParsedCommand

SCRIPT_CHARS_SHOWN = 2000
MAX_SCRIPTS = 3
_READ_BYTES = SCRIPT_CHARS_SHOWN * 4  # enough bytes for that many characters

_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh"}
_INTERPRETER = re.compile(r"^(sh|bash|zsh|dash|ksh|source|\.|node|ruby|perl|python[\d.]*)$")
# Flags that make the interpreter run code from the command line instead of a file.
_SHELL_INLINE = re.compile(r"^-[A-Za-z]*c[A-Za-z]*$")
_INLINE_FLAGS = {"-c", "-m", "-e", "-p", "--eval", "--print"}


@dataclass(frozen=True)
class Script:
    path: str  # relative to the repo
    text: str  # the first SCRIPT_CHARS_SHOWN characters
    size_bytes: int
    binary: bool = False


def find_scripts(parsed: ParsedCommand, cwd: str, repo_root: Path) -> list[Script]:
    """The repo files this command runs as scripts, such as `sh x.sh`, `./x.sh` or `python x.py`.

    Files outside the repo are left out: they are not the repo's untrusted code.
    """
    boundary = Path(os.path.realpath(repo_root))
    found: list[Script] = []
    for command in parsed.argv:
        for candidate in _script_arguments(command):
            script = _read(candidate, cwd, boundary)
            if script is not None and all(script.path != seen.path for seen in found):
                found.append(script)
            if len(found) == MAX_SCRIPTS:
                return found
    return found


def _script_arguments(argv: list[str]) -> list[str]:
    words = list(argv)
    while words and (_ASSIGNMENT.match(words[0]) or words[0].rsplit("/", 1)[-1] in TRANSPARENT_WRAPPERS):
        words.pop(0)
    if not words:
        return []
    program = words[0].rsplit("/", 1)[-1]
    if not _INTERPRETER.match(program):
        return [words[0]] if "/" in words[0] else []  # ./scripts/setup.sh runs the file itself
    arguments = words[1:]
    if _runs_inline_code(program, arguments):
        return []
    return [argument for argument in arguments if not argument.startswith("-")]


def _runs_inline_code(program: str, arguments: list[str]) -> bool:
    if program in _SHELLS:
        return any(_SHELL_INLINE.match(argument) for argument in arguments)
    return any(argument in _INLINE_FLAGS for argument in arguments)


def _read(candidate: str, cwd: str, boundary: Path) -> Script | None:
    path = Path(os.path.realpath(Path(cwd) / os.path.expanduser(candidate)))
    if not path.is_relative_to(boundary) or not path.is_file():
        return None
    try:
        with path.open("rb") as handle:
            data = handle.read(_READ_BYTES)
        size = path.stat().st_size
    except OSError:
        return None
    relative = path.relative_to(boundary).as_posix()
    if b"\x00" in data:
        return Script(relative, "", size, binary=True)
    return Script(relative, data.decode(errors="replace")[:SCRIPT_CHARS_SHOWN], size)
