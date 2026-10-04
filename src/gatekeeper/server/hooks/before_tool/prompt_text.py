from gatekeeper.server.types import ActionKind, Decision

TARGET_LIMIT = 200
REASON_LIMIT = 220
EXTRA_REASONS_SHOWN = 2

KIND_LABELS = {
    ActionKind.RUN_COMMAND: "Command",
    ActionKind.WRITE_FILE: "Write to",
    ActionKind.READ_FILE: "Read",
    ActionKind.FETCH_URL: "Fetch",
    ActionKind.OTHER: "Tool",
}


def approval_prompt(decision: Decision) -> str:
    """The text of Claude Code's approval prompt: one fact per line, easy to scan.

    The one-line `decision.summary` stays for the log; this is only for the person approving.
    """
    action = decision.action
    target = action.command or action.path or action.url or action.tool_name
    lines = [
        "Gatekeeper needs your OK before this runs",
        f"{KIND_LABELS[action.kind]}: {_shorten(target, TARGET_LIMIT)}",
    ]
    reasons = decision.reasons or ["no reason recorded"]
    lines.append(f"Why: {_shorten(reasons[0], REASON_LIMIT)}")
    lines += [f"     {_shorten(reason, REASON_LIMIT)}" for reason in reasons[1 : 1 + EXTRA_REASONS_SHOWN]]
    if decision.rules and decision.rules.tags:
        lines.append(f"Tags: {', '.join(decision.rules.tags)}")
    if decision.judge and decision.judge.error is None:
        lines.append(f"Judge: {decision.judge.risk.value} risk ({decision.judge.score:.2f})")
    return "\n".join(lines)


def _shorten(text: str, limit: int) -> str:
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"
