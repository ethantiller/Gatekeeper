from __future__ import annotations

import ipaddress
import os
import re
import shlex
from copy import deepcopy
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

import yaml

from gatekeeper.pipeline.parser import (
    extract_hosts,
    extract_pipeline_commands,
    extract_redirect_paths,
    parse,
)
from gatekeeper.server.types import (
    ActionKind,
    ParsedCommand,
    RuleResult,
    StandardAction,
    Verdict,
)

DEFAULT_RULES_PATH = Path(__file__).resolve().parents[3] / "rules" / "rules.yaml"
REPOSITORY_RULES_NAME = ".gatekeeper.yaml"
# A cloned repo is untrusted, so its rules file may only add checks. Lists are appended, so
# these keys can only make Gatekeeper stricter; safe_commands, allowed_hosts, auto_allow_tags,
# judge_failure_verdict and the limits come from the user's own rules only.
REPOSITORY_OVERRIDE_KEYS = {
    "never_allowed",
    "tags",
    "protected_files",
    "agent_config_paths",
    "sandbox_tags",
}


def load_rules(repo_path: str | Path | None = None) -> dict[str, Any]:
    """Load default rules and overlay a repository's optional rule file."""
    defaults = _read_rule_config(DEFAULT_RULES_PATH)
    repository = Path.cwd() if repo_path is None else Path(repo_path)
    override_path = repository / REPOSITORY_RULES_NAME

    if not override_path.exists():
        return defaults

    overrides = _read_rule_config(override_path)
    allowed = {key: value for key, value in overrides.items() if key in REPOSITORY_OVERRIDE_KEYS}
    _check_override_shape(defaults, allowed, override_path.name)
    return _merge_rule_values(defaults, allowed)


def _check_override_shape(defaults: Any, overrides: Any, where: str) -> None:
    """Reject overrides whose types differ from the defaults, since a merge would replace them.

    Without this a repo could set `protected_files: null` and wipe the default protections.
    """
    if type(overrides) is not type(defaults):
        raise TypeError(
            f"{REPOSITORY_RULES_NAME}: '{where}' must be a {type(defaults).__name__}, "
            f"not {type(overrides).__name__}"
        )
    if isinstance(defaults, dict):
        sample = next(iter(defaults.values()), None)
        for key, value in overrides.items():
            reference = defaults.get(key, sample)
            if reference is not None:
                _check_override_shape(reference, value, f"{where}.{key}")
    elif isinstance(defaults, list) and defaults:
        for item in overrides:
            _check_override_shape(defaults[0], item, f"{where}[]")
            if isinstance(item, dict) and isinstance(item.get("pattern"), str):
                _check_regex(item["pattern"], where)


def _check_regex(pattern: str, where: str) -> None:
    try:
        re.compile(pattern)
    except re.error as error:
        raise ValueError(f"{REPOSITORY_RULES_NAME}: '{where}' has an invalid pattern: {error}") from error


def _read_rule_config(path: Path) -> dict[str, Any]:
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


def _merge_rule_values(defaults: Any, overrides: Any) -> Any:
    if isinstance(defaults, dict) and isinstance(overrides, dict):
        merged = deepcopy(defaults)
        for key, value in overrides.items():
            if key in merged:
                merged[key] = _merge_rule_values(merged[key], value)
            else:
                merged[key] = deepcopy(value)
        return merged

    if isinstance(defaults, list) and isinstance(overrides, list):
        return deepcopy(defaults) + deepcopy(overrides)

    return deepcopy(overrides)


def check_action_against_rules(
    action: StandardAction,
    parsed: ParsedCommand | None = None,
    rules: dict[str, Any] | None = None,
    repo_root: Path | None = None,
) -> RuleResult:
    """Check an action against hard denies, risk tags, then the safe command list.

    `repo_root` is the boundary for the outside-repo check; it defaults to `action.cwd`.
    """
    parsed = parsed or parse(action)
    config = load_rules(action.cwd) if rules is None else rules

    empty = _empty_action_result(action)
    if empty is not None:
        return empty

    denial = _never_allowed_result(config, action, parsed)
    if denial is not None:
        return denial

    tags, reasons = _collect_action_risk_tags(config, action, parsed, repo_root)
    if tags:
        return RuleResult(tags=sorted(tags), reasons=reasons)

    return _safe_command_allow_result(config, parsed) or RuleResult()


def _empty_action_result(action: StandardAction) -> RuleResult | None:
    """Deny an action that has nothing to act on, instead of passing it to the judge."""
    target = {
        ActionKind.RUN_COMMAND: action.command,
        ActionKind.WRITE_FILE: action.path,
        ActionKind.READ_FILE: action.path,
        ActionKind.FETCH_URL: action.url,
    }
    if action.kind not in target or (target[action.kind] or "").strip():
        return None
    return RuleResult(
        matched_rule_ids=["empty-action"],
        forced_verdict=Verdict.DENY,
        reasons=[f"The {action.kind.value} action has nothing to act on"],
    )


def _never_allowed_result(
    config: dict[str, Any], action: StandardAction, parsed: ParsedCommand
) -> RuleResult | None:
    matched_rules = [
        rule
        for rule in config.get("never_allowed", [])
        if _matches_never_allowed_rule(rule, action, parsed)
    ]
    if not matched_rules:
        return None

    return RuleResult(
        matched_rule_ids=[str(rule.get("id", "never-allowed")) for rule in matched_rules],
        forced_verdict=Verdict.DENY,
        reasons=[str(rule.get("reason", "Matched a never-allowed rule")) for rule in matched_rules],
    )


# Collect risk tags for an action based on the configuration and the parsed command
def _collect_action_risk_tags(
    config: dict[str, Any],
    action: StandardAction,
    parsed: ParsedCommand,
    repo_root: Path | None = None,
) -> tuple[set[str], list[str]]:
    tags: set[str] = set()
    reasons: list[str] = []
    configured_tags = config.get("tags", {})
    for tag_name, tag_rules in configured_tags.items():
        if _matches_configured_tag(tag_rules, parsed.argv):
            tags.add(str(tag_name))
            reasons.append(f"Matched configured {tag_name} tag")

    programs = {_normalize_executable_name(program) for program in parsed.programs}
    if parsed.parse_error:
        tags.add("unparseable")
        reasons.append("The command could not be parsed safely")

    if "eval" in programs or _is_base64_decode_piped_to_shell(parsed) or _is_download_piped_to_shell(parsed):
        tags.add("obfuscated")
        reasons.append("The command evaluates or pipes dynamically obtained code to a shell")
    if _is_download_piped_to_shell(parsed):
        tags.add("runs_new_code")
        reasons.append("The command pipes downloaded content to a shell")

    touched_paths = _collect_action_paths(action, parsed)
    if any(path_matches_pattern(path, config.get("protected_files", []), action.cwd) for path in touched_paths):
        tags.add("touches_secrets")
        reasons.append("The action touches a protected file")

    if _action_writes_files(action, parsed) and any(
        path_matches_pattern(path, config.get("agent_config_paths", []), action.cwd)
        for path in touched_paths
    ):
        tags.add("edits_agent_config")
        reasons.append("The action writes to agent configuration")

    outside = _paths_outside_repo(action, parsed, repo_root)
    if outside:
        tags.add("outside_repo")
        reasons.append(f"The action touches paths outside the repository: {', '.join(outside)}")

    hosts = extract_hosts(parsed, action.url)
    private_hosts = [host for host in hosts if _is_private_host(host)]
    if private_hosts:
        tags.add("private_network")
        reasons.append(f"The action reaches a local or private network host: {', '.join(private_hosts)}")
    if hosts:
        tags.add("network")
        allowed_hosts = [str(host).lower() for host in config.get("allowed_hosts", [])]
        unknown_hosts = [host for host in hosts if not _host_matches_allowlist(host, allowed_hosts)]
        if unknown_hosts:
            reasons.append(f"Network host is not in allowed_hosts: {', '.join(unknown_hosts)}")

    if action.kind == ActionKind.FETCH_URL:
        tags.add("network")
        if "network" not in reasons:
            reasons.append("The action fetches a URL")

    return tags, reasons


# Paths the action names (path field, redirects and command arguments) that leave the repo.
def _paths_outside_repo(
    action: StandardAction, parsed: ParsedCommand, repo_root: Path | None
) -> list[str]:
    boundary = Path(os.path.realpath(repo_root or action.cwd))
    outside: list[str] = []
    for candidate in _collect_action_paths(action, parsed):
        if candidate not in outside and _leaves_boundary(candidate, action.cwd, boundary):
            outside.append(candidate)
    return outside


def _leaves_boundary(candidate: str, cwd: str, boundary: Path) -> bool:
    if "\x00" in candidate:
        return True
    resolved = Path(os.path.realpath(Path(cwd) / _normalize_path(candidate)))
    return not resolved.is_relative_to(boundary)


# Loopback, private, link-local and similar addresses, plus the names that point at them.
def _is_private_host(host: str) -> bool:
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        return True
    try:
        address = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return not address.is_global


# Determine if a command should be allowed based on the safe commands configuration
def _safe_command_allow_result(
    config: dict[str, Any], parsed: ParsedCommand
) -> RuleResult | None:
    safe_commands = config.get("safe_commands", [])
    if parsed.argv and not parsed.parse_error and all(
        any(_command_matches_prefix(entry, command) for entry in safe_commands)
        for command in parsed.argv
    ):
        return RuleResult(
            forced_verdict=Verdict.ALLOW,
            reasons=["Every command matches the safe command list"],
        )

    return None


# Check for never allowed rules
def _matches_never_allowed_rule(
    rule: dict[str, Any], action: StandardAction, parsed: ParsedCommand
) -> bool:
    text = "\n".join(value for value in (parsed.raw, action.path, action.url) if value)
    pattern = rule.get("pattern")
    if isinstance(pattern, str) and re.search(pattern, text, flags=re.IGNORECASE):
        return True

    entries = [*rule.get("programs", []), *rule.get("commands", [])]
    return any(_command_matches_prefix(entry, command) for entry in entries for command in parsed.argv)


# Check for configured tag rules
def _matches_configured_tag(tag_rules: Any, argv: list[list[str]]) -> bool:
    if not isinstance(tag_rules, dict):
        return False

    for program in tag_rules.get("programs", []):
        normalized = _normalize_executable_name(str(program))
        if any(_program_name_from_argv(command) == normalized for command in argv):
            return True

    for entry in tag_rules.get("commands", []):
        if any(_command_matches_prefix(str(entry), command) for command in argv):
            return True

    flags = tag_rules.get("flags", {})
    if isinstance(flags, dict):
        for program, program_flags in flags.items():
            normalized = _normalize_executable_name(str(program))
            if any(
                _program_name_from_argv(command) == normalized
                and any(flag in command[1:] for flag in program_flags)
                for command in argv
            ):
                return True

    return False


# Get the program name from the argv list
def _program_name_from_argv(argv: list[str]) -> str | None:
    for argument in argv:
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argument):
            return _normalize_executable_name(argument)
    return None


# Get the normalized executable name from the program string
def _normalize_executable_name(program: str) -> str:
    normalized = program.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    for suffix in (".exe", ".cmd", ".bat"):
        if normalized.endswith(suffix):
            return normalized[: -len(suffix)]
    return normalized


# Check if the command matches the given prefix
def _command_matches_prefix(entry: Any, argv: list[str]) -> bool:
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
    actual[0] = _normalize_executable_name(actual[0])
    expected[0] = _normalize_executable_name(expected[0])
    return [part.casefold() for part in actual[: len(expected)]] == [
        part.casefold() for part in expected
    ]


# Check if a base64 decode command is piped to a shell command
def _is_base64_decode_piped_to_shell(parsed: ParsedCommand) -> bool:
    for pipeline in extract_pipeline_commands(parsed.raw):
        decoder_seen = False
        for command in pipeline:
            program = _program_name_from_argv(command)
            if program == "base64" and any(
                argument in {"-d", "--decode", "-D"} for argument in command[1:]
            ):
                decoder_seen = True
            elif decoder_seen and program in {"sh", "bash", "zsh", "dash"}:
                return True
    return False


# Check if a download command is piped to a shell command
def _is_download_piped_to_shell(parsed: ParsedCommand) -> bool:
    for pipeline in extract_pipeline_commands(parsed.raw):
        download_seen = False
        for command in pipeline:
            program = _program_name_from_argv(command)
            if program in {"curl", "wget"}:
                download_seen = True
            elif download_seen and program in {"sh", "bash", "zsh", "dash"}:
                return True
    return False


# Collect all relevant file paths from the action and parsed command
def _collect_action_paths(action: StandardAction, parsed: ParsedCommand) -> list[str]:
    paths: list[str] = []
    if action.path:
        paths.append(action.path)
    paths.extend(parsed.redirect_targets)
    paths.extend(extract_redirect_paths(parsed.raw))
    paths.extend(argument for command in parsed.argv for argument in command[1:])
    paths.extend(
        path
        for command in parsed.argv
        for path in _curl_upload_file_paths(command)
    )
    return paths


def _curl_upload_file_paths(argv: list[str]) -> list[str]:
    if _program_name_from_argv(argv) != "curl":
        return []

    file_options = {
        "-d",
        "--data",
        "--data-ascii",
        "--data-binary",
        "--data-raw",
        "--data-urlencode",
        "-F",
        "--form",
    }
    form_options = {"-F", "--form"}
    paths: list[str] = []
    index = 1
    while index < len(argv):
        argument = argv[index]
        option = next(
            (
                candidate
                for candidate in file_options
                if argument == candidate or argument.startswith(f"{candidate}=")
            ),
            None,
        )
        if option is None:
            index += 1
            continue

        if argument == option:
            index += 1
            if index >= len(argv):
                break
            value = argv[index]
        else:
            value = argument[len(option) + 1 :]

        if option in form_options:
            _, separator, value = value.partition("=@")
            if separator:
                value = value.split(";", 1)[0]
                if value:
                    paths.append(value)
        elif value.startswith("@"):
            if value[1:]:
                paths.append(value[1:])
        elif option == "--data-urlencode" and "@" in value:
            path = value.split("@", 1)[1]
            if path:
                paths.append(path)

        index += 1
    return paths


# Check if the action writes to files
def _action_writes_files(action: StandardAction, parsed: ParsedCommand) -> bool:
    tool_name = action.tool_name.casefold()
    return (
        action.kind == ActionKind.WRITE_FILE
        or tool_name in {"write", "edit", "apply_patch", "notebookedit"}
        or bool(parsed.redirect_targets)
    )


# Check if a given path matches any of the specified patterns
def path_matches_pattern(path: str, patterns: Any, cwd: str) -> bool:
    normalized_path = _normalize_path(path)
    candidates = {normalized_path}
    normalized_cwd = _normalize_path(cwd).rstrip("/")
    if not Path(normalized_path).is_absolute():
        candidates.add(_normalize_path(str(Path(cwd) / normalized_path)))
    for candidate in tuple(candidates):
        if candidate.casefold().startswith(normalized_cwd.casefold() + "/"):
            candidates.add(candidate[len(normalized_cwd) + 1 :])

    for pattern in patterns if isinstance(patterns, list) else []:
        normalized_pattern = _normalize_path(str(pattern))
        if any(fnmatchcase(candidate.casefold(), normalized_pattern.casefold()) for candidate in candidates):
            return True
    return False


# Normalize a file path, expanding home directory and environment variables
def _normalize_path(path: str) -> str:
    home = str(Path.home()).replace("\\", "/")
    expanded = path.replace("${HOME}", home).replace("$HOME", home)
    if expanded.startswith("~"):
        expanded = str(Path(expanded).expanduser())
    return expanded.replace("\\", "/")



# Check if a host matches the allowed hosts list
def _host_matches_allowlist(host: str, allowed_hosts: list[str]) -> bool:
    return any(fnmatchcase(host.casefold(), allowed.casefold()) for allowed in allowed_hosts)