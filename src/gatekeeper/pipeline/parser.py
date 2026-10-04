from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import bashlex

from gatekeeper.server.types import ParsedCommand, StandardAction

_REDIRECT_OUTPUT_TYPES = {">", ">>", ">|", "&>", "&>>"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass
class _ParseState:
    programs: list[str] = field(default_factory=list)
    argv: list[list[str]] = field(default_factory=list)
    redirect_targets: list[str] = field(default_factory=list)
    has_pipe: bool = False
    has_subshell: bool = False
    has_command_substitution: bool = False


def parse(action: StandardAction) -> ParsedCommand:
    """Parse a shell command from an action into the shared ParsedCommand type."""
    raw = action.command or ""
    result = ParsedCommand(raw=raw)
    if not raw.strip():
        return result

    try:
        roots = bashlex.parse(raw)
    except (bashlex.errors.ParsingError, bashlex.tokenizer.MatchedPairError) as error:
        return result.model_copy(update={"parse_error": str(error)})

    state = _ParseState()
    for node in _walk(roots):
        kind = getattr(node, "kind", None)
        if kind == "command":
            _handle_command(node, state)
        elif kind == "pipe":
            _handle_pipe(state)
        elif kind == "compound":
            _handle_compound(node, state)
        elif kind == "commandsubstitution":
            _handle_command_substitution(state)
        elif kind == "redirect":
            _handle_redirect(node, state)

    return ParsedCommand(
        raw=raw,
        programs=state.programs,
        argv=state.argv,
        redirect_targets=state.redirect_targets,
        has_pipe=state.has_pipe,
        has_subshell=state.has_subshell,
        has_command_substitution=state.has_command_substitution,
    )


def _handle_command(node: Any, state: _ParseState) -> None:
    words = [part for part in getattr(node, "parts", ()) if getattr(part, "kind", None) == "word"]
    command_argv = [str(word.word) for word in words]
    if not command_argv:
        return

    state.argv.append(command_argv)
    program_index = 0
    while program_index < len(command_argv) and _ASSIGNMENT.match(command_argv[program_index]):
        program_index += 1
    if program_index < len(command_argv):
        state.programs.append(_normalize_program(command_argv[program_index]))


def _handle_pipe(state: _ParseState) -> None:
    state.has_pipe = True


def _handle_compound(node: Any, state: _ParseState) -> None:
    parts = list(getattr(node, "parts", ())) + list(getattr(node, "list", ()))
    reserved_words = {
        getattr(part, "word", None)
        for part in parts
        if getattr(part, "kind", None) == "reservedword"
    }
    if "(" in reserved_words and ")" in reserved_words:
        state.has_subshell = True


def _handle_command_substitution(state: _ParseState) -> None:
    state.has_command_substitution = True


def _handle_redirect(node: Any, state: _ParseState) -> None:
    if getattr(node, "type", None) not in _REDIRECT_OUTPUT_TYPES:
        return
    target = getattr(node, "output", None)
    if getattr(target, "kind", None) == "word":
        state.redirect_targets.append(str(target.word))


def extract_hosts(parsed: ParsedCommand, url: str | None = None) -> list[str]:
    """Extract HTTP(S) hostnames from a parsed command or a direct URL action."""
    hosts: list[str] = []
    candidates = [url] if url else []
    candidates.extend(argument for command in parsed.argv for argument in command)

    for candidate in candidates:
        if not candidate:
            continue
        value = candidate.split("=", 1)[1] if candidate.startswith("--url=") else candidate
        if not value.lower().startswith(("http://", "https://")):
            continue
        hostname = urlsplit(value).hostname
        if hostname:
            normalized = hostname.rstrip(".").lower()
            if normalized not in hosts:
                hosts.append(normalized)

    return hosts


def _normalize_program(value: str) -> str:
    program = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    suffix = PurePosixPath(program).suffix
    if suffix in {".exe", ".cmd", ".bat"}:
        return program[: -len(suffix)]

    return program
def _walk(roots: list[Any]) -> Iterator[Any]:
    stack = list(reversed(roots))
    visited: set[int] = set()
    child_fields = ("parts", "list", "command", "redirects", "input", "output", "heredoc")

    while stack:
        node = stack.pop()
        if not hasattr(node, "kind") or id(node) in visited:
            continue
        visited.add(id(node))
        yield node

        children: list[Any] = []
        for field_name in child_fields:
            value = getattr(node, field_name, None)
            if hasattr(value, "kind"):
                children.append(value)
            elif isinstance(value, list):
                children.extend(item for item in value if hasattr(item, "kind"))
        stack.extend(reversed(children))