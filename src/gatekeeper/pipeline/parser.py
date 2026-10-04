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
_FILE_REDIRECT_TYPES = {"<", "<>", *_REDIRECT_OUTPUT_TYPES}
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Programs that only run the command after them, so the rules must look at that command instead.
# `rtk` is the user's output-condensing proxy, which prefixes every command (and `rtk proxy`).
TRANSPARENT_WRAPPERS = {"rtk", "env", "time", "nohup", "command", "exec"}

# What bashlex raises on bad or hostile input. Besides its own errors it can fail with
# RecursionError, IndexError, AttributeError and TypeError (a bug in ParsingError itself).
BASHLEX_FAILURES = (
    bashlex.errors.ParsingError,
    bashlex.tokenizer.MatchedPairError,
    NotImplementedError,
    RecursionError,
    IndexError,
    AttributeError,
    TypeError,
    ValueError,
)


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

    state = _ParseState()
    try:
        for node in _walk_ast_nodes(bashlex.parse(raw)):
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
    except BASHLEX_FAILURES as error:
        return result.model_copy(update={"parse_error": f"{type(error).__name__}: {error}"})

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
    command_argv = _command_arguments(node)
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


# Return command argv grouped by the actual pipeline each belongs to.
def extract_pipeline_commands(raw: str) -> list[list[list[str]]]:
    if not raw.strip():
        return []

    try:
        roots = bashlex.parse(raw)
    except BASHLEX_FAILURES:
        return []

    pipelines: list[list[list[str]]] = []
    for node in _walk_ast_nodes(roots):
        if getattr(node, "kind", None) != "pipeline":
            continue
        stages = [
            _command_arguments(part)
            for part in getattr(node, "parts", ())
            if getattr(part, "kind", None) == "command"
        ]
        if len(stages) > 1:
            pipelines.append(stages)
    return pipelines


# Return the file path used by input or output redirections.
def extract_redirect_paths(raw: str) -> list[str]:
    if not raw.strip():
        return []

    try:
        roots = bashlex.parse(raw)
    except BASHLEX_FAILURES:
        return []

    paths: list[str] = []
    for node in _walk_ast_nodes(roots):
        if getattr(node, "kind", None) != "redirect":
            continue
        if getattr(node, "type", None) not in _FILE_REDIRECT_TYPES:
            continue
        target = getattr(node, "output", None)
        if getattr(target, "kind", None) == "word":
            paths.append(str(target.word))
    return paths


def _command_arguments(node: Any) -> list[str]:
    words = [part for part in getattr(node, "parts", ()) if getattr(part, "kind", None) == "word"]
    return _unwrap_wrappers([str(word.word) for word in words])


def _unwrap_wrappers(argv: list[str]) -> list[str]:
    """`rtk git status` -> `git status`, so tags and the safe list see the real program.

    Without this, `rtk rm -rf x` is just the program `rtk`: no tag, no sandbox run, and
    `rtk git status` never matches the safe list. argv is returned unchanged if no wrapper leads it.
    """
    index = 0
    unwrapped = False
    while True:
        while index < len(argv) and _ASSIGNMENT.match(argv[index]):
            index += 1
        if index >= len(argv) or _normalize_program(argv[index]) not in TRANSPARENT_WRAPPERS:
            break
        wrapper = _normalize_program(argv[index])
        index += 1
        if wrapper == "rtk" and index < len(argv) and argv[index] == "proxy":
            index += 1
        while index < len(argv) and argv[index].startswith("-"):
            index += 1  # the wrapper's own flags, such as env -i
        unwrapped = True
    return argv[index:] if unwrapped and index < len(argv) else argv


# Extract HTTP(S) hostnames from a parsed command or a direct URL action.
def extract_hosts(parsed: ParsedCommand, url: str | None = None) -> list[str]:
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

# Walk the AST nodes in a depth-first manner, yielding each node exactly once.
def _walk_ast_nodes(roots: list[Any]) -> Iterator[Any]:
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