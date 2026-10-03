from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

import bashlex

from gatekeeper.server.types import ParsedCommand, StandardAction

_REDIRECT_OUTPUT_TYPES = {">", ">>", ">|", "&>", "&>>"}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


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

    programs: list[str] = []
    argv: list[list[str]] = []
    redirect_targets: list[str] = []
    has_pipe = False
    has_subshell = False
    has_command_substitution = False

    for node in _walk(roots):
        kind = getattr(node, "kind", None)
        if kind == "command":
            words = [part for part in getattr(node, "parts", ()) if getattr(part, "kind", None) == "word"]
            command_argv = [str(word.word) for word in words]
            if command_argv:
                argv.append(command_argv)
                program_index = 0
                while program_index < len(command_argv) and _ASSIGNMENT.match(command_argv[program_index]):
                    program_index += 1
                if program_index < len(command_argv):
                    programs.append(_normalize_program(command_argv[program_index]))
        elif kind == "pipe":
            has_pipe = True
        elif kind == "compound":
            reserved_words = {
                getattr(part, "word", None)
                for part in (
                    list(getattr(node, "parts", ()))
                    + list(getattr(node, "list", ()))
                )
                if getattr(part, "kind", None) == "reservedword"
            }
            if "(" in reserved_words and ")" in reserved_words:
                has_subshell = True
        elif kind == "commandsubstitution":
            has_command_substitution = True
        elif kind == "redirect" and getattr(node, "type", None) in _REDIRECT_OUTPUT_TYPES:
            target = getattr(node, "output", None)
            if getattr(target, "kind", None) == "word":
                redirect_targets.append(str(target.word))

    return ParsedCommand(
        raw=raw,
        programs=programs,
        argv=argv,
        redirect_targets=redirect_targets,
        has_pipe=has_pipe,
        has_subshell=has_subshell,
        has_command_substitution=has_command_substitution,
    )


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
        for field in child_fields:
            value = getattr(node, field, None)
            if hasattr(value, "kind"):
                children.append(value)
            elif isinstance(value, list):
                children.extend(item for item in value if hasattr(item, "kind"))
        stack.extend(reversed(children))
