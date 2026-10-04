"""Turns every stage's output into one Decision with plain if/else rules."""

from typing import Any

from gatekeeper.pipeline.rules import path_matches_pattern
from gatekeeper.server.types import (
    Decision,
    JudgeResult,
    ParsedCommand,
    RiskLevel,
    RuleResult,
    SandboxReport,
    StandardAction,
    Verdict,
)

DEFAULT_MAX_DELETED_FILES = 20
DEFAULT_JUDGE_FAILURE_VERDICT = Verdict.ASK


def combine(
    action: StandardAction,
    *,
    parsed: ParsedCommand | None = None,
    rules: RuleResult | None = None,
    judge: JudgeResult | None = None,
    sandbox: SandboxReport | None = None,
    tainted_by: list[str] | None = None,
    config: dict[str, Any] | None = None,
    remembered: bool = False,
) -> Decision:
    """Pick the final verdict. The first rule that matches wins, strictest first.

    `remembered` is True when the user already approved this action id with "remember":
    it turns an ASK into an ALLOW but never overrides a DENY.
    """
    tainted_by = tainted_by or []
    config = config or {}
    verdict, reasons = _choose_verdict(action, rules, judge, sandbox, tainted_by, config)

    approved_by = "auto" if verdict == Verdict.ALLOW else None
    if verdict == Verdict.ASK and remembered:
        verdict = Verdict.ALLOW
        approved_by = "user"
        reasons.append("You approved this action earlier and chose to remember it")

    return Decision(
        session_id=action.session_id,
        action=action,
        verdict=verdict,
        reasons=reasons,
        parsed=parsed,
        rules=rules,
        judge=judge,
        sandbox=sandbox,
        tainted_by=tainted_by,
        approved_by=approved_by,
    )


def _choose_verdict(
    action: StandardAction,
    rules: RuleResult | None,
    judge: JudgeResult | None,
    sandbox: SandboxReport | None,
    tainted_by: list[str],
    config: dict[str, Any],
) -> tuple[Verdict, list[str]]:
    if rules is not None and rules.forced_verdict == Verdict.DENY:
        return Verdict.DENY, rules.reasons or ["A rule always blocks this"]

    if sandbox is not None and sandbox.tripwires_triggered:
        names = ", ".join(sandbox.tripwires_triggered)
        return Verdict.DENY, [f"The sandbox run touched fake secrets: {names}"]

    if rules is not None and rules.forced_verdict == Verdict.ALLOW:
        return Verdict.ALLOW, rules.reasons or ["A rule always allows this"]

    if judge is not None and judge.error is None and judge.risk == RiskLevel.CRITICAL:
        return Verdict.DENY, [f"The judge rated this critical: {judge.reasoning}"]

    reasons = _reasons_to_ask(action, rules, judge, sandbox, tainted_by, config)
    if reasons:
        return _ask_or_judge_failure(judge, config), reasons

    return Verdict.ALLOW, ["Nothing risky found"]


def _ask_or_judge_failure(judge: JudgeResult | None, config: dict[str, Any]) -> Verdict:
    """The verdict for a non-empty reasons list. A judge failure uses the configured verdict."""
    if judge is None or judge.error is not None:
        configured = Verdict(config.get("judge_failure_verdict", DEFAULT_JUDGE_FAILURE_VERDICT))
        # Reasons were found, so a broken judge may tighten the verdict to deny but never allow.
        return Verdict.ASK if configured == Verdict.ALLOW else configured
    return Verdict.ASK


def _reasons_to_ask(
    action: StandardAction,
    rules: RuleResult | None,
    judge: JudgeResult | None,
    sandbox: SandboxReport | None,
    tainted_by: list[str],
    config: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    tags = rules.tags if rules is not None else []

    if judge is None or judge.error is not None:
        detail = judge.error if judge is not None else "no judge result"
        reasons.append(f"The judge was unavailable ({detail})")
    elif judge.risk == RiskLevel.HIGH:
        reasons.append(f"The judge rated this high risk: {judge.reasoning}")
    elif judge.risk == RiskLevel.MEDIUM and (tags or tainted_by):
        reasons.append(f"The judge rated this medium risk: {judge.reasoning}")

    review_tags = sorted(set(tags) - set(config.get("auto_allow_tags", [])))
    if review_tags:
        reasons.append(f"Flagged by rules: {', '.join(review_tags)}")
    if tainted_by and review_tags:
        reasons.append("The agent read untrusted content earlier, and this action is tagged risky")

    if sandbox is not None:
        reasons.extend(_sandbox_concerns(action, sandbox, config))
    return reasons


def _sandbox_concerns(
    action: StandardAction, sandbox: SandboxReport, config: dict[str, Any]
) -> list[str]:
    if sandbox.error is not None:
        return [f"The sandbox could not run this: {sandbox.error}"]

    concerns: list[str] = []
    if sandbox.timed_out:
        concerns.append("The command timed out in the sandbox")

    max_deleted = config.get("max_deleted_files_before_asking", DEFAULT_MAX_DELETED_FILES)
    if len(sandbox.files_deleted) > max_deleted:
        concerns.append(f"It deletes {len(sandbox.files_deleted)} files")

    allowed_hosts = set(config.get("allowed_hosts", []))
    unknown_hosts = sorted(
        {host for host in sandbox.network_attempts if host.split(":")[0] not in allowed_hosts}
    )
    if unknown_hosts:
        concerns.append(f"It contacts hosts not on the allowed list: {', '.join(unknown_hosts)}")

    sensitive_patterns = [*config.get("protected_files", []), *config.get("agent_config_paths", [])]
    changed = [*sandbox.files_created, *sandbox.files_modified, *sandbox.files_deleted]
    sensitive = [p for p in changed if path_matches_pattern(p, sensitive_patterns, action.cwd)]
    if sensitive:
        concerns.append(f"It changes protected or agent config files: {', '.join(sensitive[:5])}")

    if sandbox.notes:
        concerns.append(f"The sandbox report has limits: {'; '.join(sandbox.notes)}")
    return concerns
