"""Runs every pipeline step for one action and returns the saved Decision."""

import asyncio
import logging
import sqlite3
from pathlib import Path
from typing import Any, Protocol

from google import genai

from gatekeeper.core import decision_store
from gatekeeper.pipeline import judge, untrusted, useless_mode
from gatekeeper.pipeline.combine import combine, serious_tags, suspicious_reads_blocking
from gatekeeper.pipeline.parser import parse
from gatekeeper.pipeline.rules import (
    check_action_against_rules,
    load_default_rules,
    load_rules,
)
from gatekeeper.pipeline.scanner import SUSPICIOUS_SCORE
from gatekeeper.sandbox import runner
from gatekeeper.server.types import (
    ActionKind,
    Decision,
    JudgeResult,
    RiskLevel,
    RuleResult,
    SandboxSession,
    StandardAction,
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
    reads = untrusted.recent(
        conn,
        session.session_id,
        action.sequence,
        config.get("untrusted_lookback_actions", untrusted.DEFAULT_LOOKBACK_ACTIONS),
    )

    tainted = any(read.score >= SUSPICIOUS_SCORE for read in reads)
    judge_result = None
    sandbox_report = None
    # A rule that forces a verdict, or a network or secrets action after a suspicious read
    # (always denied), means the judge and sandbox would not change it.
    if rules.forced_verdict is None and not suspicious_reads_blocking(rules.tags, reads):
        snippets = [read.snippet for read in reads]
        prompt = _latest_prompt(conn, session.session_id)
        sandbox_session = SandboxSession(
            session_id=session.session_id,
            repo_root=session.repo_root,
            tripwire_seed=session.tripwire_seed,
        )

        if _needs_sandbox(action, rules, config):
            sandbox_report = await asyncio.to_thread(runner.run, action, sandbox_session)
            # A fake secret was touched: combine denies whatever the judge would say.
            if _needs_judge(action, rules, config, tainted) and not sandbox_report.tripwires_triggered:
                judge_result = await judge.rate(
                    action, rules, snippets, prompt, sandbox_report, client=gemini
                )
        elif _needs_judge(action, rules, config, tainted):
            judge_result = await judge.rate(action, rules, snippets, prompt, client=gemini)
            if _should_escalate(action, judge_result):
                sandbox_report = await asyncio.to_thread(runner.run, action, sandbox_session)

    decision = combine(
        action,
        parsed=parsed,
        rules=rules,
        judge=judge_result,
        sandbox=sandbox_report,
        untrusted_reads=reads,
        config=config,
        remembered=decision_store.is_remembered(conn, action.action_id),
    )
    # After combine and before save, so the saved row is already the final deny.
    decision = await useless_mode.intercept(decision, conn, config, gemini)
    return decision_store.save(conn, decision, session.repo_root)


def _needs_sandbox(action: StandardAction, rules: RuleResult, config: dict[str, Any]) -> bool:
    sandbox_tags = set(config.get("sandbox_tags", []))
    return action.kind == ActionKind.RUN_COMMAND and bool(sandbox_tags & set(rules.tags))


def _needs_judge(
    action: StandardAction, rules: RuleResult, config: dict[str, Any], tainted: bool
) -> bool:
    """Whether the judge is worth its cost: serious tags, or an untagged action of unknown effect."""
    if serious_tags(rules.tags, config):
        return True
    if rules.tags:
        return tainted  # soft tags: the sandbox is enough, unless a suspicious read came first
    return action.kind in JUDGED_UNTAGGED_KINDS


def _should_escalate(action: StandardAction, judge_result: JudgeResult) -> bool:
    return (
        action.kind == ActionKind.RUN_COMMAND
        and judge_result.error is None
        and judge_result.risk in SANDBOX_ESCALATION_RISKS
    )


def _latest_prompt(conn: sqlite3.Connection, session_id: str) -> str | None:
    """The latest user prompt; labelled when it answered one of Gatekeeper's useless questions."""
    row = conn.execute(
        "SELECT prompts.text AS text, useless_questions.question AS question FROM prompts"
        " LEFT JOIN useless_questions ON useless_questions.answer_prompt_id = prompts.prompt_id"
        " WHERE prompts.session_id = ? ORDER BY prompts.created_at DESC LIMIT 1",
        (session_id,),
    ).fetchone()
    if row is None:
        return None
    if row["question"]:
        return f"The user's answer to Gatekeeper's question \"{row['question']}\": {row['text']}"
    return row["text"]
