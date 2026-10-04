"""Shared Pydantic types used across Gatekeeper."""

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import uuid4
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ConfigDict, Field


class GatekeeperModel(BaseModel):
    """Base for all shared types. Unknown fields raise instead of being dropped."""

    model_config = ConfigDict(extra="forbid")


def new_id() -> str:
    return str(uuid4())


EASTERN = ZoneInfo("America/New_York")


def eastern_now() -> datetime:
    return datetime.now(EASTERN)


class ActionSource(StrEnum):
    """Where an action came from."""

    CLAUDE_HOOK = "claude_hook"
    MCP_VSCODE = "mcp_vscode"
    MCP_CODEX = "mcp_codex"


class ActionKind(StrEnum):
    """What the action does. Mirrors the MCP tools (run_command, write_file, ...)."""

    RUN_COMMAND = "run_command"
    WRITE_FILE = "write_file"
    READ_FILE = "read_file"
    FETCH_URL = "fetch_url"
    OTHER = "other"


class Verdict(StrEnum):
    """The final decision on an action."""

    ALLOW = "allow"
    DENY = "deny"
    ASK = "ask"  # needs human approval


class RiskLevel(StrEnum):
    """How risky the judge thinks an action is."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StandardAction(GatekeeperModel):
    """
    Specifies what a specific tool call from an agent looks like.
    Gives what it is, what its doing, and where its coming from + other details.
    """

    action_id: str = Field(default_factory=new_id)
    session_id: str
    sequence: int = Field(ge=0, description="Per-session action counter")
    source: ActionSource
    kind: ActionKind
    tool_name: str = Field(
        description="Raw tool name from the agent( mcp tool, write, etc. )"
    )

    command: str | None = None
    path: str | None = None
    content: str | None = None
    url: str | None = None
    cwd: str

    raw: dict[str, Any] = Field(default_factory=dict, description="Original payload")
    created_at: datetime = Field(default_factory=eastern_now)


class ParsedCommand(GatekeeperModel):
    """
    Gives a consistent model for what a command looks like for rule enforcement.
    """

    raw: str = Field(description="The original command string")
    programs: list[str] = Field(
        default_factory=list,
        description="Every executable invoked (curl, sh, etc.) includes pipes and subshells",
    )
    argv: list[list[str]] = Field(
        default_factory=list, description="One argument list per simple command"
    )
    redirect_targets: list[str] = Field(
        default_factory=list, description="Files written to via > or >>"
    )
    has_pipe: bool = False
    has_subshell: bool = False
    has_command_substitution: bool = False
    parse_error: str | None = Field(
        default=None,
        description="Set when bashlex could not parse the command; treat as unknown",
    )


class RuleResult(GatekeeperModel):
    """
    Sets a structured output for rules.py. Identifies what rules are being broken.
    Identifies whether the rule will be enforced automatically or if more context will be gathered.
    """

    matched_rule_ids: list[str] = Field(
        default_factory=list, description="IDs of rules that matched this action"
    )
    tags: list[str] = Field(
        default_factory=list,
        description='Tags like "network", "destructive", "secrets", "file-write"',
    )
    forced_verdict: Verdict | None = Field(
        default=None,
        description="Set if a rule forces ALLOW or DENY without consulting the judge",
    )
    reasons: list[str] = Field(
        default_factory=list,
        description="Human-readable explanations for matched rules",
    )


class UntrustedRead(GatekeeperModel):
    """
    Records content the agent read that it did not write itself (a fetched URL, a file
    from a cloned repo). Later risky actions in the same session can be checked
    against these reads to catch prompt injection. (Prompt injection from untrusted sources)
    """

    read_id: str = Field(default_factory=new_id)
    session_id: str
    action_id: str = Field(description="The action that performed the read")
    source: str = Field(description="Where the content came from: a file path or URL")
    content_sha256: str = Field(
        description="Hash of the content, so we can match it later without storing it"
    )
    scanner_flags: list[str] = Field(
        default_factory=list,
        description="Hidden-instruction findings from scanner.py, empty if clean",
    )
    created_at: datetime = Field(default_factory=eastern_now)


class JudgeResult(GatekeeperModel):
    """
    The LLM's risk rating for an action should always come in this structure.
    If the LLM call fails, `error` is set instead of raising, so the final verdict
    logic can treat "judge unavailable" as a signal.
    """

    risk: RiskLevel
    score: float = Field(
        ge=0, le=1, description="0 is harmless, 1 is certainly malicious"
    )
    reasoning: str = Field(
        description="The judge's explanation, shown in gatekeeper show"
    )
    model: str = Field(
        description="Which LLM produced this, e.g. the GEMINI_MODEL value"
    )
    latency_ms: int = Field(ge=0, description="How long the LLM call took")
    error: str | None = Field(
        default=None, description="Set if the judge call failed or timed out"
    )

class SandboxSession(GatekeeperModel):
    model_config = ConfigDict(frozen=True)
    
    session_id: str = Field(description="Unique identifier for the sandbox session")
    repo_root: Path = Field(description="Root directory of the repository being sandboxed")
    tripwire_seed: str = Field(
        repr=False,
        exclude=True,
        description="Seed used for tripwire generation in this session"
    )
    

class SandboxReport(GatekeeperModel):
    """
    What happened when a command ran in a throwaway container.
    The real command only runs on the host after this report looks safe.
    """

    image: str = Field(description="Docker image the command ran in")
    exit_code: int | None = Field(
        default=None,
        description="None if the command never finished (timeout or error)",
    )
    timed_out: bool = False
    duration_ms: int = Field(default=0, ge=0)
    stdout_tail: str = Field(default="", description="Last part of stdout, truncated")
    stderr_tail: str = Field(default="", description="Last part of stderr, truncated")
    files_created: list[str] = Field(default_factory=list)
    files_modified: list[str] = Field(default_factory=list)
    files_deleted: list[str] = Field(default_factory=list)
    network_attempts: list[str] = Field(
        default_factory=list, description="Hosts the command tried to connect to"
    )
    tripwires_triggered: list[str] = Field(
        default_factory=list,
        description="Fake secrets (planted .env, AWS creds) that the command read or sent out",
    )
    saved_changes_id: str | None = Field(
        default=None,
        description="Id of the saved file changes an approval can apply; None if nothing to save",
    )
    notes: list[str] = Field(
        default_factory=list,
        description="Limits on this report (e.g. the connection log was unavailable); "
        "when non-empty, do not treat an empty list above as proof that nothing happened",
    )
    error: str | None = Field(
        default=None,
        description="Set if the sandbox itself failed (e.g. Docker unavailable)",
    )


class Decision(GatekeeperModel):
    """
    The final record for one action, produced by pipeline/combine.py.
    It embeds the output of every stage, so a decision can be explained on its own.
    Stages that were skipped or failed are None.
    """

    decision_id: str = Field(default_factory=new_id)
    session_id: str
    action: StandardAction
    verdict: Verdict
    reasons: list[str] = Field(
        default_factory=list,
        description="Why this verdict was chosen, in plain language",
    )

    parsed: ParsedCommand | None = None
    rules: RuleResult | None = None
    judge: JudgeResult | None = None
    sandbox: SandboxReport | None = None

    tainted_by: list[str] = Field(
        default_factory=list,
        description="read_ids of UntrustedReads that made this action more suspicious",
    )
    approved_by: str | None = Field(
        default=None, description='"auto", "user", or None if denied or still pending'
    )
    checkpoint_id: str | None = Field(
        default=None, description="Git checkpoint taken before running, for rollback"
    )
    summary: str | None = Field(
        default=None, description="One-line summary shown in gatekeeper log"
    )
    created_at: datetime = Field(default_factory=eastern_now)
