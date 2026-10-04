"""Heuristic scanning for hidden or manipulative instructions in text."""

import base64
import binascii
import re
from urllib.parse import parse_qsl, urlsplit

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
    findings: list[str] = []

    if any(pattern.search(text) for pattern in _INSTRUCTION_PATTERNS):
        findings.append("instruction_phrase")
    if _HIDDEN_UNICODE_PATTERN.search(text):
        findings.append("hidden_unicode")
    if _HTML_COMMENT_PATTERN.search(text):
        findings.append("hidden_html_comment")
    if _contains_base64_blob(text):
        findings.append("base64_blob")
    if _FAKE_TOOL_CALL_PATTERN.search(text):
        findings.append("fake_tool_call")
    if _contains_suspicious_url_query(text):
        findings.append("suspicious_url_query")

    score = min(0.8, round(sum(_FINDING_WEIGHTS[finding] for finding in findings), 2))
    return score, findings


def _contains_base64_blob(text: str) -> bool:
    for match in _BASE64_TOKEN_PATTERN.finditer(text):
        token = match.group()
        padded_token = token + "=" * (-len(token) % 4)
        try:
            decoded = base64.b64decode(padded_token, altchars=b"-_", validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded:
            return True
    return False


def _contains_suspicious_url_query(text: str) -> bool:
    for match in _URL_PATTERN.finditer(text):
        url = match.group().rstrip(".,;:!?)]}")
        try:
            query_items = parse_qsl(urlsplit(url).query, keep_blank_values=True)
        except ValueError:
            continue
        for key, value in query_items:
            if key.casefold() in _SUSPICIOUS_QUERY_KEYS:
                return True
            if _SUSPICIOUS_QUERY_VALUE_PATTERN.search(value):
                return True
    return False