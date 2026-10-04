"""Runs every pipeline step for one action and returns the saved Decision."""

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from google import genai

from gatekeeper.core import decision_store
from gatekeeper.pipeline import judge
from gatekeeper.pipeline.combine import combine, serious_tags
from gatekeeper.pipeline.parser import parse
from gatekeeper.pipeline.rules import check_action_against_rules, load_default_rules, load_rules
from gatekeeper.sandbox import runner
from gatekeeper.server.types import (
    ActionKind,
    Decision,
    JudgeResult,
    RiskLevel,
    RuleResult,
    SandboxSession,
    StandardAction,
    UntrustedRead,
    Verdict,
)

logger = logging.getLogger(__name__)

# An untagged command with one of these judge ratings is sandboxed before it is decided.
SANDBOX_ESCALATION_RISKS = {RiskLevel.MEDIUM, RiskLevel.HIGH}


# Untagged reads and writes inside the repo are allowed without the judge.
JUDGED_UNTAGGED_KINDS = {ActionKind.RUN_COMMAND, ActionKind.FETCH_URL, ActionKind.OTHER}


class SessionRecord(Protocol):
    """The parts of the GK-6 session record that `decide` needs."""

    session_id: str
    repo_root: Path
    tripwire_seed: str


def recent_untrusted_reads(session_id: str, sequence: int) -> list[UntrustedRead]:
    """Stand-in for `untrusted.recent` until GK-8 lands."""
    return []


async def decide(
    action: StandardAction,
    session: SessionRecord,
    conn: sqlite3.Connection,
    gemini: genai.Client | None = None,
) -> Decision:
    """Parse, check rules, sandbox and judge as needed, combine and save.

    The judge and sandbox can only make a verdict stricter. Tagged commands are
    sandboxed first so the judge sees what they did; untagged commands go to the judge
    first and are sandboxed only if it rates them medium or high.
    """
    # A hook retry reuses the action id; return what was decided instead of deciding twice.
    existing = decision_store.find_by_action(conn, action.action_id)
    if existing is not None:
        if existing.verdict == Verdict.ASK and decision_store.is_remembered(conn, action.action_id):
            return decision_store.record_approval(conn, existing.decision_id)
        return existing

    try:
        config = load_rules(session.repo_root)
    except (RuntimeError, TypeError, ValueError) as error:
        # A repo's .gatekeeper.yaml is untrusted and can only add checks, so a broken one is
        # ignored rather than failing every tool call in that repo.
        logger.warning("Ignoring the rules file in %s: %s", session.repo_root, error)
        config = load_default_rules()
    parsed = parse(action)
    rules = check_action_against_rules(action, parsed, config, session.repo_root)
    reads = recent_untrusted_reads(session.session_id, action.sequence)

    judge_result = None
    sandbox_report = None
    # A rule that forces a verdict means the judge and sandbox would not change it.
    if rules.forced_verdict is None:
        snippets = [read.source for read in reads]
        prompt = _latest_prompt(conn, session.session_id)
        sandbox_session = SandboxSession(
            session_id=session.session_id,
            repo_root=session.repo_root,
            tripwire_seed=session.tripwire_seed,
        )

        if _needs_sandbox(action, rules, config):
            sandbox_report = await asyncio.to_thread(runner.run, action, sandbox_session)
            # A fake secret was touched: combine denies whatever the judge would say.
            if _needs_judge(action, rules, config) and not sandbox_report.tripwires_triggered:
                judge_result = await judge.rate(
                    action, rules, snippets, prompt, sandbox_report, client=gemini
                )
        elif _needs_judge(action, rules, config):
            judge_result = await judge.rate(action, rules, snippets, prompt, client=gemini)
            if _should_escalate(action, judge_result):
                sandbox_report = await asyncio.to_thread(runner.run, action, sandbox_session)

    decision = combine(
        action,
        parsed=parsed,
        rules=rules,
        judge=judge_result,
        sandbox=sandbox_report,
        tainted_by=[read.read_id for read in reads],
        config=config,
        remembered=decision_store.is_remembered(conn, action.action_id),
    )
    return decision_store.save(conn, decision, session.repo_root)


def _needs_sandbox(action: StandardAction, rules: RuleResult, config: dict[str, Any]) -> bool:
    sandbox_tags = set(config.get("sandbox_tags", []))
    return action.kind == ActionKind.RUN_COMMAND and bool(sandbox_tags & set(rules.tags))


def _needs_judge(action: StandardAction, rules: RuleResult, config: dict[str, Any]) -> bool:
    """Whether the judge is worth its cost: serious tags, or an untagged action of unknown effect."""
    if serious_tags(rules.tags, config):
        return True
    if rules.tags:
        return False  # soft tags: the sandbox (if any) is enough
    return action.kind in JUDGED_UNTAGGED_KINDS


def _should_escalate(action: StandardAction, judge_result: JudgeResult) -> bool:
    return (
        action.kind == ActionKind.RUN_COMMAND
        and judge_result.error is None
        and judge_result.risk in SANDBOX_ESCALATION_RISKS
    )


def _latest_prompt(conn: sqlite3.Connection, session_id: str) -> str | None:
    row = conn.execute(
        "SELECT text FROM prompts WHERE session_id = ? ORDER BY created_at DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    return row["text"] if row else None
