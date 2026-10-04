"""Turns every stage's output into one Decision with plain if/else rules."""

from typing import Any

from gatekeeper.pipeline.rules import path_matches_pattern
from gatekeeper.pipeline.scanner import SUSPICIOUS_SCORE
from gatekeeper.pipeline.untrusted import display_source
from gatekeeper.server.types import (
    Decision,
    JudgeResult,
    ParsedCommand,
    RiskLevel,
    RuleResult,
    SandboxReport,
    StandardAction,
    UntrustedRead,
    Verdict,
)

DEFAULT_MAX_DELETED_FILES = 20
DEFAULT_JUDGE_FAILURE_VERDICT = Verdict.ASK
# After a suspicious read, an action with all of these tags (secrets on their way out) is denied.
# Either tag alone, or any other tag, asks: the user can approve a real `git pull` or `.env` read.
EXFILTRATION_TAGS = {"network", "touches_secrets"}


def combine(
    action: StandardAction,
    *,
    parsed: ParsedCommand | None = None,
    rules: RuleResult | None = None,
    judge: JudgeResult | None = None,
    sandbox: SandboxReport | None = None,
    untrusted_reads: list[UntrustedRead] | None = None,
    config: dict[str, Any] | None = None,
    remembered: bool = False,
) -> Decision:
    """Pick the final verdict. The first rule that matches wins, strictest first.

    `remembered` is True when the user already approved this action id with "remember":
    it turns an ASK into an ALLOW but never overrides a DENY.
    """
    suspicious_reads = [r for r in untrusted_reads or [] if r.score >= SUSPICIOUS_SCORE]
    tainted_by = [read.read_id for read in suspicious_reads]
    config = config or {}
    verdict, reasons = _choose_verdict(action, rules, judge, sandbox, suspicious_reads, config)

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
    suspicious_reads: list[UntrustedRead],
    config: dict[str, Any],
) -> tuple[Verdict, list[str]]:
    if rules is not None and rules.forced_verdict == Verdict.DENY:
        return Verdict.DENY, rules.reasons or ["A rule always blocks this"]

    if sandbox is not None and sandbox.tripwires_triggered:
        names = ", ".join(sandbox.tripwires_triggered)
        return Verdict.DENY, [f"The sandbox run touched fake secrets: {names}"]

    blocking_reads = suspicious_reads_blocking(rules.tags if rules else [], suspicious_reads)
    if blocking_reads:
        return Verdict.DENY, [_follows_suspicious_read_reason(blocking_reads)]

    if rules is not None and rules.forced_verdict == Verdict.ALLOW:
        return Verdict.ALLOW, rules.reasons or ["A rule always allows this"]

    if judge is not None and judge.error is None and judge.risk == RiskLevel.CRITICAL:
        return Verdict.DENY, [f"The judge rated this critical: {judge.reasoning}"]

    reasons = _reasons_to_ask(action, rules, judge, sandbox, suspicious_reads, config)
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
    suspicious_reads: list[UntrustedRead],
    config: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    tags = rules.tags if rules is not None else []

    serious = serious_tags(tags, config)

    # The judge only runs when needed, so no result is fine unless a serious tag needs one.
    if judge is None:
        if serious:
            reasons.append(f"Needs a judge review ({', '.join(serious)}) but none ran")
    elif judge.error is not None:
        reasons.append(f"The judge was unavailable ({judge.error})")
    elif judge.risk == RiskLevel.HIGH:
        reasons.append(f"The judge rated this high risk: {judge.reasoning}")
    elif judge.risk == RiskLevel.MEDIUM and suspicious_reads:
        reasons.append(f"The judge rated this medium risk: {judge.reasoning}")

    if suspicious_reads and tags:
        reasons.append(
            f"The agent read suspicious content earlier ({_read_sources(suspicious_reads)}),"
            f" and this action is tagged risky ({', '.join(tags)})"
        )

    if sandbox is not None:
        reasons.extend(_sandbox_concerns(action, sandbox, config))
    return reasons


def _sandbox_concerns(
    action: StandardAction, sandbox: SandboxReport, config: dict[str, Any]
) -> list[str]:
    """What the sandbox found. `sandbox.notes` (no repo image, host paths it could not copy, ...)
    are left to the judge, which reads them in `describe_sandbox`; they say the evidence is
    incomplete, not that the action did anything."""
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

    return concerns


def serious_tags(tags: list[str], config: dict[str, Any]) -> list[str]:
    """The tags that need the judge: configured serious tags the user has not auto-allowed."""
    wanted = set(config.get("serious_tags", [])) - set(config.get("auto_allow_tags", []))
    return sorted(set(tags) & wanted)


def suspicious_reads_blocking(tags: list[str], reads: list[UntrustedRead]) -> list[UntrustedRead]:
    """The suspicious reads that make this action a deny: secrets plus network after one (GK-8)."""
    if not EXFILTRATION_TAGS <= set(tags):
        return []
    return [read for read in reads if read.score >= SUSPICIOUS_SCORE]


def _follows_suspicious_read_reason(reads: list[UntrustedRead]) -> str:
    return (
        f"This looks like it follows instructions from {_read_sources(reads)},"
        " which Gatekeeper flagged as suspicious."
    )


def _read_sources(reads: list[UntrustedRead]) -> str:
    return ", ".join(dict.fromkeys(display_source(read.source) for read in reads))
