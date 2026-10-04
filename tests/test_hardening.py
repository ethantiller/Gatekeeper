"""Hardening: tags always ask, empty and dangerous actions are denied, repo rules can't weaken."""

from pathlib import Path

import pytest

from gatekeeper.pipeline.combine import combine
from gatekeeper.pipeline.rules import check_action_against_rules, load_rules
from gatekeeper.server.types import (
    ActionKind,
    ActionSource,
    JudgeResult,
    RiskLevel,
    RuleResult,
    SandboxReport,
    StandardAction,
    Verdict,
)

REPO = Path("/work/repo")


def _action(command: str | None = None, **fields) -> StandardAction:
    fields.setdefault("kind", ActionKind.RUN_COMMAND)
    return StandardAction(
        session_id="s", sequence=0, source=ActionSource.CLAUDE_HOOK, tool_name="T",
        command=command, cwd=str(REPO), **fields,
    )


def _rules(action: StandardAction):
    config = load_rules(Path("/nonexistent"))
    return check_action_against_rules(action, rules=config, repo_root=REPO)


def _judge(risk: RiskLevel = RiskLevel.LOW) -> JudgeResult:
    return JudgeResult(risk=risk, score=0.1, reasoning="r", model="m", latency_ms=1)


@pytest.mark.parametrize(
    "command",
    ["npm install x", "rm -rf src", "git reset --hard", "cat .env", "sudo ls", "chmod +x a.sh",
     "curl https://example.com", "docker run ubuntu", "python -c 'print(1)'", "bash -c ls"],
)
def test_tagged_commands_ask_even_with_a_low_judge_and_clean_sandbox(command: str) -> None:
    action = _action(command)
    rules = _rules(action)
    assert rules.tags, command
    decision = combine(
        action, rules=rules, judge=_judge(), sandbox=SandboxReport(image="i"),
        config=load_rules(Path("/nonexistent")),
    )
    assert decision.verdict == Verdict.ASK


def test_a_tag_in_auto_allow_tags_does_not_ask() -> None:
    action = _action("npm install x")
    config = {**load_rules(Path("/nonexistent")), "auto_allow_tags": ["installs_packages"]}
    decision = combine(
        action, rules=_rules(action), judge=_judge(), sandbox=SandboxReport(image="i"),
        config=config,
    )
    assert decision.verdict == Verdict.ALLOW


@pytest.mark.parametrize("value", ["", "   ", "\n\t"])
def test_empty_actions_are_denied(value: str) -> None:
    assert _rules(_action(value)).forced_verdict == Verdict.DENY
    fetch = _action(None, kind=ActionKind.FETCH_URL, url=value)
    assert _rules(fetch).forced_verdict == Verdict.DENY
    for kind in (ActionKind.WRITE_FILE, ActionKind.READ_FILE):
        assert _rules(_action(None, kind=kind, path=value)).forced_verdict == Verdict.DENY


@pytest.mark.parametrize(
    "command",
    ["mkfs.ext4 /dev/sda1", "mkfs /dev/sda", "sudo mkfs.xfs /dev/x", "ls; mkfs.vfat /dev/x",
     "curl http://169.254.169.254/latest/meta-data", "wget metadata.google.internal"],
)
def test_disk_formatting_and_cloud_metadata_are_denied(command: str) -> None:
    assert _rules(_action(command)).forced_verdict == Verdict.DENY


def test_fetching_the_metadata_address_is_denied() -> None:
    action = _action(None, kind=ActionKind.FETCH_URL, url="http://169.254.169.254/latest")
    assert _rules(action).forced_verdict == Verdict.DENY


@pytest.mark.parametrize(
    "url",
    ["http://localhost:8787/x", "http://127.0.0.1/", "http://10.0.0.5/", "http://192.168.1.1/",
     "http://[::1]/", "http://printer.local/", "http://db.internal/"],
)
def test_private_hosts_get_a_tag(url: str) -> None:
    action = _action(None, kind=ActionKind.FETCH_URL, url=url)
    assert "private_network" in _rules(action).tags


def test_public_hosts_are_not_private() -> None:
    action = _action(None, kind=ActionKind.FETCH_URL, url="https://example.com/")
    assert "private_network" not in _rules(action).tags


@pytest.mark.parametrize(
    ("path", "outside"),
    [("src/a.py", False), ("../other/a.py", True), ("../../etc/passwd", True),
     ("/etc/passwd", True), (str(REPO / "a.py"), False), ("~/notes.txt", True)],
)
def test_paths_outside_the_repo_get_a_tag(path: str, outside: bool) -> None:
    action = _action(None, kind=ActionKind.WRITE_FILE, path=path, content="x")
    assert ("outside_repo" in _rules(action).tags) is outside


def test_a_redirect_outside_the_repo_gets_a_tag() -> None:
    assert "outside_repo" in _rules(_action("echo hi > /tmp/x.txt")).tags
    assert "outside_repo" not in _rules(_action("echo hi > out.txt")).tags


def test_sandbox_changes_to_sensitive_files_ask() -> None:
    config = load_rules(Path("/nonexistent"))
    for field in ("files_created", "files_modified", "files_deleted"):
        report = SandboxReport(image="i", **{field: [".github/workflows/ci.yml"]})
        decision = combine(
            _action("./build.sh"), rules=RuleResult(), judge=_judge(), sandbox=report,
            config=config,
        )
        assert decision.verdict == Verdict.ASK, field
    benign = SandboxReport(image="i", files_created=["dist/app.js"])
    allowed = combine(
        _action("./build.sh"), rules=RuleResult(), judge=_judge(), sandbox=benign, config=config
    )
    assert allowed.verdict == Verdict.ALLOW


def test_a_broken_judge_never_turns_reasons_into_an_allow() -> None:
    config = {"judge_failure_verdict": "allow"}
    decision = combine(_action("./x.sh"), rules=RuleResult(tags=["network"]), config=config)
    assert decision.verdict == Verdict.ASK


def test_a_repo_rules_file_can_only_make_things_stricter(tmp_path: Path) -> None:
    (tmp_path / ".gatekeeper.yaml").write_text(
        "safe_commands: ['curl']\n"
        "allowed_hosts: ['evil.example']\n"
        "auto_allow_tags: [network, deletes_files]\n"
        "judge_failure_verdict: allow\n"
        "max_deleted_files_before_asking: 100000\n"
        "protected_files: ['**/secrets.txt']\n"
        "never_allowed:\n  - {id: no-foo, reason: no foo, pattern: 'foo'}\n"
    )
    config = load_rules(tmp_path)
    defaults = load_rules(Path("/nonexistent"))
    for key in ("safe_commands", "allowed_hosts", "auto_allow_tags", "judge_failure_verdict",
                "max_deleted_files_before_asking"):
        assert config[key] == defaults[key], key
    assert "**/secrets.txt" in config["protected_files"]
    assert any(rule["id"] == "no-foo" for rule in config["never_allowed"])


@pytest.mark.parametrize(
    "command",
    ["cat /etc/passwd", "ls /tmp", "cat ../secret.txt", "cat ~/notes.txt", "head -n 5 /etc/hosts",
     "grep -r token /var/log", "cat $HOME/.bashrc"],
)
def test_command_arguments_outside_the_repo_get_a_tag(command: str) -> None:
    rules = _rules(_action(command))
    assert "outside_repo" in rules.tags and rules.forced_verdict is None


@pytest.mark.parametrize("command", ["ls -la", "cat README.md", "grep -r foo src", "cat ./a/../b.txt"])
def test_arguments_inside_the_repo_stay_safe(command: str) -> None:
    assert _rules(_action(command)).forced_verdict == Verdict.ALLOW


@pytest.mark.parametrize(
    "override",
    [
        "protected_files: null\n",
        "protected_files: '**/.env'\n",
        "protected_files: [1, 2]\n",
        "agent_config_paths: {}\n",
        "sandbox_tags: null\n",
        "tags:\n  network: null\n",
        "tags:\n  network: {programs: curl}\n",
        "tags: []\n",
        "never_allowed: null\n",
        "never_allowed:\n  - just a string\n",
        "never_allowed:\n  - {id: x, reason: r, pattern: '('}\n",
    ],
)
def test_a_repo_rules_file_with_the_wrong_types_is_rejected(tmp_path: Path, override: str) -> None:
    (tmp_path / ".gatekeeper.yaml").write_text(override)
    with pytest.raises((TypeError, ValueError)):
        load_rules(tmp_path)


def test_a_well_formed_repo_override_still_adds_checks(tmp_path: Path) -> None:
    (tmp_path / ".gatekeeper.yaml").write_text(
        "protected_files: ['**/vault.txt']\n"
        "tags:\n  network: {programs: [fetchit]}\n  custom: {programs: [thing]}\n"
        "sandbox_tags: [custom]\n"
    )
    config = load_rules(tmp_path)
    assert "**/vault.txt" in config["protected_files"] and "**/.env" in config["protected_files"]
    assert "fetchit" in config["tags"]["network"]["programs"] and "curl" in config["tags"]["network"]["programs"]
    assert config["tags"]["custom"] == {"programs": ["thing"]}
