"""Security scanning rules for shell transcripts and command history."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    message: str
    pattern: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    source: str
    line: int
    column: int
    match: str
    excerpt: str


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags | re.MULTILINE)


RULES: tuple[Rule, ...] = (
    Rule("github-token", "critical", "GitHub token exposed in terminal output.", _compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    Rule("pypi-token", "critical", "PyPI API token exposed in terminal output.", _compile(r"\bpypi-[A-Za-z0-9_\-]{40,}\b")),
    Rule("aws-access-key", "critical", "AWS access key identifier exposed.", _compile(r"\bAKIA[0-9A-Z]{16}\b")),
    Rule("google-api-key", "high", "Google API key-like value exposed.", _compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Rule("slack-token", "high", "Slack token-like value exposed.", _compile(r"\bxox[baprs]-[A-Za-z0-9\-]{20,}\b")),
    Rule(
        "private-key",
        "critical",
        "Private key material appears in the transcript.",
        _compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    Rule("basic-auth-url", "high", "URL contains embedded credentials.", _compile(r"https?://[^\s:/]+:[^\s@]+@[^\s]+")),
    Rule(
        "curl-pipe-shell",
        "high",
        "Remote script is piped directly into a shell.",
        _compile(r"\b(?:curl|wget)\b[^\n|;]*[|]\s*(?:sudo\s+)?(?:sh|bash|zsh)\b", re.IGNORECASE),
    ),
    Rule(
        "dangerous-filesystem",
        "critical",
        "Destructive filesystem command detected.",
        _compile(r"\b(?:rm\s+-[^\n;]*r[^\n;]*f[^\n;]*/|mkfs\.[A-Za-z0-9_]+|chmod\s+-R\s+777\s+/|dd\s+if=[^\n;]+of=/dev/[A-Za-z0-9]+)", re.IGNORECASE),
    ),
    Rule(
        "ssh-key-exfiltration",
        "critical",
        "Command appears to move SSH keys or passwd data over the network.",
        _compile(r"\b(?:nc|netcat|scp|rsync)\b[^\n]*(?:/etc/passwd|\.ssh/id_[A-Za-z0-9_]+)", re.IGNORECASE),
    ),
    Rule("sudo-password-prompt", "medium", "Transcript includes a sudo password prompt.", _compile(r"\[sudo\] password for [^:\n]+:", re.IGNORECASE)),
)


def redact(value: str) -> str:
    compact = value.replace("\n", "\\n")
    if len(compact) <= 12:
        return "[redacted]"
    return f"{compact[:4]}...{compact[-4:]}"


def _line_and_column(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    column = index + 1 if previous_newline == -1 else index - previous_newline
    return line, column


def _excerpt(lines: list[str], line: int) -> str:
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:220]
    return ""


def scan_text(text: str, *, source: str = "stdin", rules: Iterable[Rule] = RULES) -> list[Finding]:
    """Scan text and return security findings."""

    lines = text.splitlines()
    findings: list[Finding] = []
    seen: set[tuple[str, int, int, str]] = set()
    for rule in rules:
        for match in rule.pattern.finditer(text):
            line, column = _line_and_column(text, match.start())
            redacted = redact(match.group(0))
            key = (rule.id, line, column, redacted)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=rule.message,
                    source=source,
                    line=line,
                    column=column,
                    match=redacted,
                    excerpt=_excerpt(lines, line),
                )
            )

    findings.sort(key=lambda item: (-SEVERITY_ORDER.get(item.severity, 0), item.line, item.rule_id))
    return findings

