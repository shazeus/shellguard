"""HTML reports for Shellguard audits."""

from __future__ import annotations

import html
from pathlib import Path

from .audit import AuditResult, audit_session


def default_report_path(session_path: Path) -> Path:
    return session_path.with_suffix(".html")


def build_report(result: AuditResult) -> str:
    session = result.session
    command = html.escape(str(session.meta.get("command", "")))
    returncode = html.escape(str(session.exit.get("returncode", "unknown")))
    duration = html.escape(str(session.exit.get("duration", "unknown")))
    rows = "\n".join(
        "<tr>"
        f"<td>{html.escape(finding.severity)}</td>"
        f"<td>{html.escape(finding.rule_id)}</td>"
        f"<td>{finding.line}:{finding.column}</td>"
        f"<td>{html.escape(finding.message)}</td>"
        f"<td><code>{html.escape(finding.match)}</code></td>"
        "</tr>"
        for finding in result.findings
    )
    if not rows:
        rows = '<tr><td colspan="5">No security findings.</td></tr>'
    transcript = html.escape(session.output_text[-12000:])
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Shellguard Audit Report</title>
  <style>
    body {{
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f6f7f9;
      color: #16202a;
    }}
    header {{ padding: 28px 36px 18px; background: #ffffff; border-bottom: 1px solid #d9dee7; }}
    main {{ padding: 24px 36px; }}
    .metrics {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 20px; }}
    .metric {{ background: #ffffff; border: 1px solid #d9dee7; border-radius: 8px; padding: 14px; }}
    .label {{ color: #5f6d7c; font-size: 13px; }}
    .value {{ font-size: 24px; font-weight: 700; margin-top: 4px; }}
    table {{ border-collapse: collapse; width: 100%; background: #ffffff; border: 1px solid #d9dee7; }}
    th, td {{ border-bottom: 1px solid #e8ebf0; padding: 10px 12px; text-align: left; vertical-align: top; }}
    th {{ background: #eef2f7; }}
    pre {{ white-space: pre-wrap; background: #101820; color: #e6edf3; padding: 16px; border-radius: 8px; overflow: auto; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  </style>
</head>
<body>
  <header>
    <h1>Shellguard Audit Report</h1>
    <p><code>{command}</code></p>
  </header>
  <main>
    <section class="metrics">
      <div class="metric"><div class="label">Findings</div><div class="value">{len(result.findings)}</div></div>
      <div class="metric"><div class="label">Max severity</div><div class="value">{html.escape(result.max_severity)}</div></div>
      <div class="metric"><div class="label">Exit code</div><div class="value">{returncode}</div></div>
      <div class="metric"><div class="label">Duration</div><div class="value">{duration}s</div></div>
    </section>
    <h2>Findings</h2>
    <table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Location</th><th>Message</th><th>Match</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
    <h2>Transcript tail</h2>
    <pre>{transcript}</pre>
  </main>
</body>
</html>
"""


def write_report(session_path: str | Path, output: str | Path | None = None) -> Path:
    result = audit_session(session_path)
    destination = Path(output) if output else default_report_path(result.session.path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(build_report(result), encoding="utf-8")
    return destination

