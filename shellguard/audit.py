"""Audit helpers for Shellguard sessions."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .scanner import Finding, SEVERITY_ORDER, scan_text
from .storage import SessionData, load_session


@dataclass(frozen=True)
class AuditResult:
    session: SessionData
    findings: list[Finding]

    @property
    def max_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(self.findings, key=lambda item: SEVERITY_ORDER.get(item.severity, 0)).severity

    @property
    def failed(self) -> bool:
        return bool(self.session.exit and int(self.session.exit.get("returncode", 0)) != 0)


def audit_session(path: str | Path) -> AuditResult:
    session = load_session(path)
    command = str(session.meta.get("command", ""))
    transcript = f"$ {command}\n{session.output_text}"
    findings = scan_text(transcript, source=str(session.path))
    return AuditResult(session=session, findings=findings)

