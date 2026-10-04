"""combine rules, decision saving, git checkpoints and approval memory (no Docker)."""

import subprocess
from pathlib import Path

import pytest

from gatekeeper import database
from gatekeeper.core import decision_store
from gatekeeper.core.checkpoints import CHECKPOINT_REF_PREFIX
from gatekeeper.pipeline.combine import combine
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


def _action(command: str = "npm test", kind: ActionKind = ActionKind.RUN_COMMAND) -> StandardAction:
    return StandardAction(
        session_id="s1", sequence=0, source=ActionSource.CLAUDE_HOOK, kind=kind,
        tool_name="Bash", command=command, cwd="/repo",
    )


def _judge(risk: RiskLevel, error: str | None = None) -> JudgeResult:
    return JudgeResult(
        risk=risk, score=0.5, reasoning="because", model="m", latency_ms=1, error=error
    )


def _sandbox(**fields: object) -> SandboxReport:
    return SandboxReport(image="img", **fields)


def test_forced_deny_wins_over_everything() -> None:
    rules = RuleResult(forced_verdict=Verdict.DENY, reasons=["never"])
    decision = combine(_action(), rules=rules, judge=_judge(RiskLevel.LOW))
    assert decision.verdict == Verdict.DENY and decision.reasons == ["never"]


def test_forced_allow_is_auto_approved() -> None:
    rules = RuleResult(forced_verdict=Verdict.ALLOW)
    decision = combine(_action("ls"), rules=rules)
    assert decision.verdict == Verdict.ALLOW and decision.approved_by == "auto"


def test_tripwire_hit_denies_even_with_a_low_judge() -> None:
    decision = combine(
        _action(), judge=_judge(RiskLevel.LOW), sandbox=_sandbox(tripwires_triggered=["aws"])
    )
    assert decision.verdict == Verdict.DENY


def test_critical_judge_denies_and_high_asks() -> None:
    assert combine(_action(), judge=_judge(RiskLevel.CRITICAL)).verdict == Verdict.DENY
    assert combine(_action(), judge=_judge(RiskLevel.HIGH)).verdict == Verdict.ASK


def test_medium_asks_only_with_a_tag_or_taint() -> None:
    assert combine(_action(), judge=_judge(RiskLevel.MEDIUM)).verdict == Verdict.ALLOW
    tagged = combine(_action(), rules=RuleResult(tags=["network"]), judge=_judge(RiskLevel.MEDIUM))
    assert tagged.verdict == Verdict.ASK
    tainted = combine(_action(), judge=_judge(RiskLevel.MEDIUM), tainted_by=["r1"])
    assert tainted.verdict == Verdict.ASK


def test_tagged_action_after_untrusted_read_asks_even_when_low() -> None:
    decision = combine(
        _action(), rules=RuleResult(tags=["network"]), judge=_judge(RiskLevel.LOW), tainted_by=["r"]
    )
    assert decision.verdict == Verdict.ASK and decision.tainted_by == ["r"]


def test_judge_failure_uses_the_configured_verdict() -> None:
    rules = RuleResult(tags=["network"])
    failed = _judge(RiskLevel.LOW, error="timeout")
    assert combine(_action(), rules=rules, judge=failed).verdict == Verdict.ASK
    config = {"judge_failure_verdict": "deny"}
    assert combine(_action(), rules=rules, judge=None, config=config).verdict == Verdict.DENY


def test_unknown_action_without_a_judge_result_is_not_allowed() -> None:
    assert combine(_action("./deploy.sh")).verdict == Verdict.ASK
    safe = RuleResult(forced_verdict=Verdict.ALLOW)
    assert combine(_action("ls"), rules=safe).verdict == Verdict.ALLOW


def test_sandbox_concerns_ask() -> None:
    config = {"allowed_hosts": ["pypi.org"], "max_deleted_files_before_asking": 2}
    low = _judge(RiskLevel.LOW)
    cases = [
        _sandbox(error="docker down"),
        _sandbox(timed_out=True),
        _sandbox(files_deleted=["a", "b", "c"]),
        _sandbox(network_attempts=["evil.example:443"]),
        _sandbox(notes=["connection log unavailable"]),
    ]
    for report in cases:
        assert combine(_action(), judge=low, sandbox=report, config=config).verdict == Verdict.ASK
    clean = _sandbox(network_attempts=["pypi.org:443"], files_deleted=["a"])
    assert combine(_action(), judge=low, sandbox=clean, config=config).verdict == Verdict.ALLOW


def test_remembered_approval_skips_ask_but_not_deny() -> None:
    asked = combine(_action(), judge=_judge(RiskLevel.HIGH), remembered=True)
    assert asked.verdict == Verdict.ALLOW and asked.approved_by == "user"
    denied = combine(_action(), judge=_judge(RiskLevel.CRITICAL), remembered=True)
    assert denied.verdict == Verdict.DENY


@pytest.fixture
def conn(tmp_path: Path):
    connection = database.connect(tmp_path / "db.sqlite")
    connection.execute(
        "INSERT INTO sessions (session_id, source, cwd, started_at) VALUES ('s1','claude_hook','/','t')"
    )
    connection.commit()
    return connection


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "t@example.com")
    _git(root, "config", "user.name", "T")
    (root / "a.txt").write_text("one")
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", "first")
    return root


def test_save_takes_a_checkpoint_without_touching_the_worktree(conn, repo: Path) -> None:
    (repo / "a.txt").write_text("edited")
    (repo / "new.txt").write_text("untracked")
    status_before = _git(repo, "status", "--porcelain")
    head_before = _git(repo, "rev-parse", "HEAD")

    saved = decision_store.save(conn, combine(_action()), repo)

    assert _git(repo, "status", "--porcelain") == status_before
    assert _git(repo, "rev-parse", "HEAD") == head_before
    assert saved.checkpoint_id is not None
    sha = conn.execute("SELECT git_ref FROM checkpoints").fetchone()["git_ref"]
    assert _git(repo, "show", f"{sha}:a.txt") == "edited"
    assert _git(repo, "show", f"{sha}:new.txt") == "untracked"
    assert _git(repo, "rev-parse", CHECKPOINT_REF_PREFIX + saved.checkpoint_id) == sha
    row = conn.execute("SELECT summary, decision_json FROM decisions").fetchone()
    assert row["summary"] == saved.summary and saved.checkpoint_id in row["decision_json"]


def test_save_skips_checkpoint_for_denied_and_non_git(conn, repo: Path, tmp_path: Path) -> None:
    denied = combine(_action(), rules=RuleResult(forced_verdict=Verdict.DENY, reasons=["no"]))
    saved = decision_store.save(conn, denied, repo)
    assert saved.checkpoint_id is None and "different approach" in saved.agent_reason

    plain = tmp_path / "plain"
    plain.mkdir()
    assert decision_store.save(conn, combine(_action("ls")), plain).checkpoint_id is None
    assert conn.execute("SELECT COUNT(*) FROM checkpoints").fetchone()[0] == 0


def test_checkpoint_in_a_repo_without_commits(conn, tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    _git(root, "init", "-q")
    (root / "f.txt").write_text("x")
    saved = decision_store.save(conn, combine(_action("touch f")), root)
    assert saved.checkpoint_id is not None


def test_summary_is_one_short_line_and_allow_has_no_agent_reason(conn, repo: Path) -> None:
    clean = combine(_action("echo " + "x\n" * 100), judge=_judge(RiskLevel.LOW))
    saved = decision_store.save(conn, clean, repo)
    assert "\n" not in saved.summary and len(saved.summary) < 200
    assert saved.agent_reason == ""


def test_approval_memory(conn) -> None:
    assert not decision_store.is_remembered(conn, "act-1")
    decision_store.remember_approval(conn, "s1", "act-1")
    decision_store.remember_approval(conn, "s1", "act-1")
    assert decision_store.is_remembered(conn, "act-1")
    assert not decision_store.is_remembered(conn, "act-2")
