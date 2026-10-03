from __future__ import annotations

import re
import shlex
from copy import deepcopy
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from gatekeeper.server.types import (
    ActionKind,
    ParsedCommand,
    RuleResult,
    StandardAction,
    Verdict,
)

from .parser import extract_hosts, parse

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "rules.yaml"
REPOSITORY_RULES_NAME = ".gatekeeper.yaml"


def load_rules(repo_path: str | Path | None = None) -> dict[str, Any]:
    """Load default rules and overlay a repository's optional rule file."""
    defaults = _read_rules(DEFAULT_RULES_PATH)
    repository = Path.cwd() if repo_path is None else Path(repo_path)
    override_path = repository / REPOSITORY_RULES_NAME

    if not override_path.exists():
        return defaults

    return _merge(defaults, _read_rules(override_path))


def _read_rules(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as rules_file:
            rules = yaml.safe_load(rules_file)
    except (OSError, yaml.YAMLError) as e:
        raise RuntimeError(f"Failed to read rules from {path}") from e

    if not rules:
        raise ValueError(f"Rules file cannot be empty: {path}")
    if not isinstance(rules, dict):
        raise TypeError(f"Rules file must contain a YAML mapping: {path}")

    return rules


def _merge(defaults: Any, overrides: Any) -> Any:
    if isinstance(defaults, dict) and isinstance(overrides, dict):
        merged = deepcopy(defaults)
        for key, value in overrides.items():
            if key in merged:
                merged[key] = _merge(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    if isinstance(defaults, list) and isinstance(overrides, list):
        return deepcopy(defaults) + deepcopy(overrides)

    return deepcopy(overrides)


def check(
    action: StandardAction,
    parsed: ParsedCommand | None = None,
    rules: dict[str, Any] | None = None,
) -> RuleResult:
    """Check an action against hard denies, risk tags, then the safe command list."""
    parsed = parsed or parse(action)
    config = load_rules(action.cwd) if rules is None else rules

    matched_rules = [
        rule for rule in config.get("never_allowed", []) if _matches_never_allowed(rule, action, parsed)
    ]
    if matched_rules:
        return RuleResult(
            matched_rule_ids=[str(rule.get("id", "never-allowed")) for rule in matched_rules],
            forced_verdict=Verdict.DENY,
            reasons=[str(rule.get("reason", "Matched a never-allowed rule")) for rule in matched_rules],
        )

    tags: set[str] = set()
    reasons: list[str] = []
    configured_tags = config.get("tags", {})
    for tag_name, tag_rules in configured_tags.items():
        if _matches_tag(tag_rules, parsed.argv):
            tags.add(str(tag_name))
            reasons.append(f"Matched configured {tag_name} tag")

    programs = {_normalize_program(program) for program in parsed.programs}
    if parsed.parse_error:
        tags.add("unparseable")
        reasons.append("The command could not be parsed safely")

    if "eval" in programs or _is_base64_to_shell(parsed) or _is_download_to_shell(parsed):
        tags.add("obfuscated")
        reasons.append("The command evaluates or pipes dynamically obtained code to a shell")
    if _is_download_to_shell(parsed):
        tags.add("runs_new_code")
        reasons.append("The command pipes downloaded content to a shell")

    touched_paths = _touched_paths(action, parsed)
    if any(_matches_any_path(path, config.get("protected_files", []), action.cwd) for path in touched_paths):
        tags.add("touches_secrets")
        reasons.append("The action touches a protected file")

    if _writes_files(action, parsed) and any(
        _matches_any_path(path, config.get("agent_config_paths", []), action.cwd)
        for path in touched_paths
    ):
        tags.add("edits_agent_config")
        reasons.append("The action writes to agent configuration")

    hosts = extract_hosts(parsed, action.url)
    if hosts:
        tags.add("network")
        allowed_hosts = [str(host).lower() for host in config.get("allowed_hosts", [])]
        unknown_hosts = [host for host in hosts if not _host_is_allowed(host, allowed_hosts)]
        if unknown_hosts:
            reasons.append(f"Network host is not in allowed_hosts: {', '.join(unknown_hosts)}")

    if action.kind == ActionKind.FETCH_URL:
        tags.add("network")
        if "network" not in reasons:
            reasons.append("The action fetches a URL")

    if tags:
        return RuleResult(tags=sorted(tags), reasons=reasons)

    safe_commands = config.get("safe_commands", [])
    if parsed.argv and not parsed.parse_error and all(
        any(_command_matches(entry, command) for entry in safe_commands)
        for command in parsed.argv
    ):
        return RuleResult(
            forced_verdict=Verdict.ALLOW,
            reasons=["Every command matches the safe command list"],
        )

    return RuleResult()


def _matches_never_allowed(
    rule: dict[str, Any], action: StandardAction, parsed: ParsedCommand
) -> bool:
    text = "\n".join(value for value in (parsed.raw, action.path, action.url) if value)
    pattern = rule.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, text, flags=re.IGNORECASE):
        return True

    entries = [*rule.get("programs", []), *rule.get("commands", [])]
    return any(_command_matches(entry, command) for entry in entries for command in parsed.argv)


def _matches_tag(tag_rules: Any, argv: list[list[str]]) -> bool:
    if not isinstance(tag_rules, dict):
        return False

    for program in tag_rules.get("programs", []):
        normalized = _normalize_program(str(program))
        if any(_program_of(command) == normalized for command in argv):
            return True

    for entry in tag_rules.get("commands", []):
        if any(_command_matches(str(entry), command) for command in argv):
            return True

    flags = tag_rules.get("flags", {})
    if isinstance(flags, dict):
        for program, program_flags in flags.items():
            normalized = _normalize_program(str(program))
            if any(
                _program_of(command) == normalized
                and any(flag in command[1:] for flag in program_flags)
                for command in argv
            ):
                return True

    return False


def _program_of(argv: list[str]) -> str | None:
    for argument in argv:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argument):
            return _normalize_program(argument)
    return None


def _normalize_program(program: str) -> str:
    normalized = program.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".exe", ".cmd", ".bat"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized


def _command_matches(entry: Any, argv: list[str]) -> bool:
    if not isinstance(entry, str):
        return False
    try:
        expected = shlex.split(entry)
    except ValueError:
        return False
    if not expected:
        return False

    actual = list(argv)
    while actual and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", actual[0]):
        actual.pop(0)
    if len(actual) < len(expected):
        return False
    actual[0] = _normalize_program(actual[0])
    expected[0] = _normalize_program(expected[0])
    return [part.casefold() for part in actual[: len(expected)]] == [
        part.casefold() for part in expected
    ]


def _is_base64_to_shell(parsed: ParsedCommand) -> bool:
    if not parsed.has_pipe:
        return False
    decoder_index = None
    for index, command in enumerate(parsed.argv):
        if _program_of(command) == "base64" and any(
            argument in {"-d", "--decode", "-D"} for argument in command[1:]
        ):
            decoder_index = index
        elif decoder_index is not None and _program_of(command) in {"sh", "bash", "zsh", "dash"}:
            return True
    return False


def _is_download_to_shell(parsed: ParsedCommand) -> bool:
    if not parsed.has_pipe:
        return False
    download_index = None
    for index, command in enumerate(parsed.argv):
        if _program_of(command) in {"curl", "wget"}:
            download_index = index
        elif download_index is not None and _program_of(command) in {"sh", "bash", "zsh", "dash"}:
            return True
    return False


def _touched_paths(action: StandardAction, parsed: ParsedCommand) -> list[str]:
    paths: list[str] = []
    if action.path:
        paths.append(action.path)
    paths.extend(parsed.redirect_targets)
    paths.extend(argument for command in parsed.argv for argument in command[1:])
    return paths


def _writes_files(action: StandardAction, parsed: ParsedCommand) -> bool:
    tool_name = action.tool_name.casefold()
    return (
        action.kind == ActionKind.WRITE_FILE
        or tool_name in {"write", "edit", "apply_patch", "notebookedit"}
        or bool(parsed.redirect_targets)
    )


def _matches_any_path(path: str, patterns: Any, cwd: str) -> bool:
    normalized_path = _normalize_path(path)
    candidates = {normalized_path}
    normalized_cwd = _normalize_path(cwd).rstrip("/")
    if normalized_path.casefold().startswith(normalized_cwd.casefold() + "/"):
        candidates.add(normalized_path[len(normalized_cwd) + 1 :])

    for pattern in patterns if isinstance(patterns, list) else []:
        normalized_pattern = _normalize_path(str(pattern))
        if any(fnmatchcase(candidate.casefold(), normalized_pattern.casefold()) for candidate in candidates):
            return True
    return False


def _normalize_path(path: str) -> str:
    home = str(Path.home()).replace("\\", "/")
    expanded = path.replace("${HOME}", home).replace("$HOME", home)
    if expanded.startswith("~"):
        expanded = str(Path(expanded).expanduser())
    return expanded.replace("\\", "/")


def _host_is_allowed(host: str, allowed_hosts: list[str]) -> bool:
    return any(fnmatchcase(host.casefold(), allowed.casefold()) for allowed in allowed_hosts)