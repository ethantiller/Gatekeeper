import base64
import binascii
import re
from urllib.parse import parse_qsl, urlsplit

# A read scoring at least this is suspicious without asking the LLM (`scan` never scores higher).
SUSPICIOUS_SCORE = 0.8

_INSTRUCTION_PATTERNS = (

    # Patterns for detecting manipulative instruction phrases
    re.compile(
        r"\b(?:ignore|disregard|forget|override)\s+(?:(?:all|any|the)\s+)?"
        r"(?:previous|prior|above|earlier)\s+(?:instructions?|rules?|prompts?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:reveal|print|expose|show|output)\s+(?:the\s+)?"
        r"(?:system|developer|hidden)\s+(?:prompt|instructions?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:you are now|act as|pretend to be)\b|"
        r"\b(?:bypass|override|ignore)\s+(?:safety|security|guardrails?)\b",
        re.IGNORECASE,
    ),
)
_HIDDEN_UNICODE_PATTERN = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]")
_HTML_COMMENT_PATTERN = re.compile(r"<!--.*?-->", re.DOTALL)
_BASE64_TOKEN_PATTERN = re.compile(r"(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{80,}={0,2}(?![A-Za-z0-9+/_=-])")
_FAKE_TOOL_CALL_PATTERN = re.compile(
    r"<\|(?:tool_call|function_call)\|>|<tool_call\b|</tool_call\s*>|"
    r"\[\s*(?:TOOL_CALL|FUNCTION_CALL)\s*\]|"
    r"(?:^|\n)\s*assistant\s+to=[\w.-]+\b",
    re.IGNORECASE,
)
_URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_SUSPICIOUS_QUERY_KEYS = {
    "auth",
    "cmd",
    "command",
    "exec",
    "key",
    "password",
    "prompt",
    "redirect",
    "return",
    "script",
    "secret",
    "shell",
    "target",
    "token",
    "url",
}
_SUSPICIOUS_QUERY_VALUE_PATTERN = re.compile(
    r"(?:\$\(|;|&&|\|\||\b(?:bash|curl|powershell|wget)\b)", re.IGNORECASE
)
_FINDING_WEIGHTS = {
    "instruction_phrase": 0.35,
    "hidden_unicode": 0.30,
    "hidden_html_comment": 0.30,
    "base64_blob": 0.25,
    "fake_tool_call": 0.40,
    "suspicious_url_query": 0.30,
}


def scan(text: str) -> tuple[float, list[str]]:
    """Return a bounded heuristic score and names of detected patterns."""
    findings = list(_find_offsets(text))
    score = min(SUSPICIOUS_SCORE, round(sum(_FINDING_WEIGHTS[finding] for finding in findings), 2))
    return score, findings


def finding_offsets(text: str) -> list[int]:
    """Where in the text each finding starts, so a snippet can be centred on them."""
    return list(_find_offsets(text).values())


def _find_offsets(text: str) -> dict[str, int]:
    """The first position of each finding, in the order `scan` reports them."""
    offsets: dict[str, int] = {}
    phrase_starts = [m.start() for p in _INSTRUCTION_PATTERNS if (m := p.search(text))]
    if phrase_starts:
        offsets["instruction_phrase"] = min(phrase_starts)
    for finding, pattern in (
        ("hidden_unicode", _HIDDEN_UNICODE_PATTERN),
        ("hidden_html_comment", _HTML_COMMENT_PATTERN),
        ("fake_tool_call", _FAKE_TOOL_CALL_PATTERN),
    ):
        match = pattern.search(text)
        if match:
            offsets[finding] = match.start()
    for finding, offset in (
        ("base64_blob", _base64_blob_offset(text)),
        ("suspicious_url_query", _suspicious_url_query_offset(text)),
    ):
        if offset is not None:
            offsets[finding] = offset
    return {finding: offsets[finding] for finding in _FINDING_WEIGHTS if finding in offsets}


def _base64_blob_offset(text: str) -> int | None:
    for match in _BASE64_TOKEN_PATTERN.finditer(text):
        token = match.group()
        padded_token = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded_token, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded:
            return match.start()
    return None


def _suspicious_url_query_offset(text: str) -> int | None:
    for match in _URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:!?)]}")
        try:
            query_items = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            continue
        for key, value in query_items:
            if key.casefold() in _SUSPICIOUS_QUERY_KEYS:
                return match.start()
            if _SUSPICIOUS_QUERY_VALUE_PATTERN.search(value):
                return match.start()
    return None
