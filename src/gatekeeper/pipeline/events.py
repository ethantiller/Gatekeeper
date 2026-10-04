"""Progress events that `decide` reports while it works, so a UI can show each stage."""

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from gatekeeper.pipeline.untrusted import display_source
from gatekeeper.server.types import (
    Decision,
    JudgeResult,
    ParsedCommand,
    RuleResult,
    SandboxReport,
    StandardAction,
    UntrustedRead,
)

EVENT_PATH_LIMIT = 40


class Stage(StrEnum):
    """The steps of the pipeline, in the order they can happen."""

    ACTION = "action"
    PARSE = "parse"
    RULES = "rules"
    CONTEXT = "context"
    JUDGE = "judge"
    SANDBOX = "sandbox"
    COMBINE = "combine"


class StageStatus(StrEnum):
    STARTED = "started"
    DONE = "done"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class PipelineEvent:
    """One stage starting, finishing or being skipped, with a small JSON-safe summary."""

    stage: Stage
    status: StageStatus
    detail: dict[str, Any] = field(default_factory=dict)


EventSink = Callable[[PipelineEvent], None]


def describe_action_event(action: StandardAction) -> dict[str, Any]:
    return {
        "kind": action.kind.value,
        "tool": action.tool_name,
        "command": action.command,
        "path": action.path,
        "url": action.url,
        "cwd": action.cwd,
    }


def describe_parse_event(parsed: ParsedCommand) -> dict[str, Any]:
    return {
        "programs": parsed.programs,
        "has_pipe": parsed.has_pipe,
        "has_subshell": parsed.has_subshell,
        "parse_error": parsed.parse_error,
    }


def describe_rules_event(rules: RuleResult) -> dict[str, Any]:
    return {
        "tags": rules.tags,
        "matched_rule_ids": rules.matched_rule_ids,
        "forced_verdict": rules.forced_verdict.value if rules.forced_verdict else None,
        "reasons": rules.reasons,
    }


def describe_context_event(reads: list[UntrustedRead], tainted: bool) -> dict[str, Any]:
    return {
        "tainted": tainted,
        "reads": [
            {"source": display_source(read.source), "score": read.score, "flags": read.scanner_flags}
            for read in reads
        ],
    }


def describe_judge_event(result: JudgeResult) -> dict[str, Any]:
    return {
        "risk": result.risk.value,
        "score": result.score,
        "reasoning": result.reasoning,
        "model": result.model,
        "latency_ms": result.latency_ms,
        "error": result.error,
    }


def describe_sandbox_event(report: SandboxReport) -> dict[str, Any]:
    """What the run did. Never stdout or stderr, which the command controls."""
    return {
        "exit_code": report.exit_code,
        "timed_out": report.timed_out,
        "duration_ms": report.duration_ms,
        "files_created": report.files_created[:EVENT_PATH_LIMIT],
        "files_created_count": len(report.files_created),
        "files_modified": report.files_modified[:EVENT_PATH_LIMIT],
        "files_modified_count": len(report.files_modified),
        "files_deleted": report.files_deleted[:EVENT_PATH_LIMIT],
        "files_deleted_count": len(report.files_deleted),
        "network_attempts": report.network_attempts[:EVENT_PATH_LIMIT],
        "tripwires_triggered": report.tripwires_triggered,
        "saved_changes": report.saved_changes_id is not None,
        "notes": report.notes,
        "error": report.error,
    }


def describe_combine_event(decision: Decision) -> dict[str, Any]:
    return {
        "verdict": decision.verdict.value,
        "reasons": decision.reasons,
        "approved_by": decision.approved_by,
        "decision_id": decision.decision_id,
    }
