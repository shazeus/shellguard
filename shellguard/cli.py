"""Command-line interface for Shellguard."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Callable, TypeVar

import click
from rich.console import Console
from rich.table import Table

from . import __version__
from .audit import audit_session
from .history import scan_history
from .recorder import RecordingError, record_command
from .replay import replay_session
from .report import write_report
from .scanner import RULES, Finding, SEVERITY_ORDER, scan_text
from .storage import SessionError, default_session_path, load_session


console = Console()
F = TypeVar("F", bound=Callable[..., object])


def _friendly_errors(func: F) -> F:
    def wrapper(*args: object, **kwargs: object) -> object:
        try:
            return func(*args, **kwargs)
        except (FileNotFoundError, OSError, RecordingError, SessionError) as exc:
            raise click.ClickException(str(exc)) from exc

    wrapper.__name__ = func.__name__
    wrapper.__doc__ = func.__doc__
    return wrapper  # type: ignore[return-value]


def _render_findings(findings: list[Finding]) -> None:
    if not findings:
        console.print("[green]No security findings.[/]")
        return
    table = Table(title="Security Findings", show_lines=False)
    table.add_column("Severity", style="bold")
    table.add_column("Rule", style="cyan")
    table.add_column("Location", justify="right")
    table.add_column("Message")
    table.add_column("Match", style="yellow", overflow="fold")
    for finding in findings:
        table.add_row(
            finding.severity,
            finding.rule_id,
            f"{finding.line}:{finding.column}",
            finding.message,
            finding.match,
        )
    console.print(table)


def _findings_json(findings: list[Finding]) -> str:
    return json.dumps([asdict(finding) for finding in findings], indent=2)


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(__version__, prog_name="shellguard")
def cli() -> None:
    """Record terminal sessions and audit them for risky shell activity."""


@cli.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Session JSONL output path.")
@click.option("--shell", "use_shell", is_flag=True, help="Run the command through the current shell.")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
@_friendly_errors
def record(output: Path | None, use_shell: bool, command: tuple[str, ...]) -> None:
    """Record a command or interactive shell session."""

    destination = output or default_session_path()
    console.print(f"[bold]Recording to[/] {destination}")
    path, returncode = record_command(command, destination, use_shell=use_shell)
    console.print(f"[green]Session saved:[/] {path}  [bold]exit=[/]{returncode}")
    raise click.exceptions.Exit(returncode)


@cli.command()
@click.argument("session", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--json-output", is_flag=True, help="Print findings as JSON.")
@click.option("--fail-on", type=click.Choice(["low", "medium", "high", "critical"]), help="Exit 2 when this severity or higher is present.")
@_friendly_errors
def audit(session: Path, json_output: bool, fail_on: str | None) -> None:
    """Audit a recorded session for secrets and risky commands."""

    result = audit_session(session)
    console.print(
        f"[bold]Session:[/] {result.session.path}  [bold]exit=[/]{result.session.exit.get('returncode', 'unknown')}  "
        f"[bold]max=[/]{result.max_severity}"
    )
    if json_output:
        console.print(_findings_json(result.findings))
    else:
        _render_findings(result.findings)
    if fail_on and SEVERITY_ORDER.get(result.max_severity, 0) >= SEVERITY_ORDER[fail_on]:
        raise click.exceptions.Exit(2)


@cli.command()
@click.argument("target", required=False, type=click.Path(dir_okay=False, path_type=Path))
@click.option("--json-output", is_flag=True, help="Print findings as JSON.")
@_friendly_errors
def scan(target: Path | None, json_output: bool) -> None:
    """Scan a text file or stdin for secrets and dangerous shell patterns."""

    if target is None or str(target) == "-":
        if sys.stdin.isatty():
            raise click.ClickException("Provide a file or pipe text into stdin.")
        source = "stdin"
        text = sys.stdin.read()
    else:
        source = str(target)
        text = target.read_text(encoding="utf-8", errors="replace")
    findings = scan_text(text, source=source)
    if json_output:
        console.print(_findings_json(findings))
    else:
        console.print(f"[bold]Scanned:[/] {source}")
        _render_findings(findings)


@cli.command()
@click.argument("session", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--speed", default=1.0, show_default=True, type=float, help="Replay speed multiplier.")
@click.option("--no-timing", is_flag=True, help="Print output immediately.")
@_friendly_errors
def replay(session: Path, speed: float, no_timing: bool) -> None:
    """Replay a recorded terminal session."""

    replay_session(session, speed=speed, timing=not no_timing)


@cli.command()
@click.argument("session", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("-o", "--output", type=click.Path(path_type=Path), help="HTML report path.")
@_friendly_errors
def report(session: Path, output: Path | None) -> None:
    """Write a standalone HTML security report."""

    saved = write_report(session, output)
    console.print(f"[green]Report written:[/] {saved}")


@cli.command("history")
@click.option("--path", "history_path", type=click.Path(exists=True, dir_okay=False, path_type=Path), help="Shell history file to scan.")
@click.option("--limit", default=500, show_default=True, type=int, help="Number of recent commands to inspect.")
@click.option("--json-output", is_flag=True, help="Print findings as JSON.")
@_friendly_errors
def history_cmd(history_path: Path | None, limit: int, json_output: bool) -> None:
    """Scan shell history for risky commands and leaked tokens."""

    selected, findings = scan_history(history_path, limit=limit)
    if json_output:
        console.print(_findings_json(findings))
    else:
        console.print(f"[bold]History:[/] {selected}")
        _render_findings(findings)


@cli.command("export")
@click.argument("session", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--format", "export_format", type=click.Choice(["text", "json", "html"]), default="text", show_default=True)
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output path. Defaults beside the session file.")
@_friendly_errors
def export_cmd(session: Path, export_format: str, output: Path | None) -> None:
    """Export a session as text, JSON, or HTML."""

    loaded = load_session(session)
    if export_format == "html":
        saved = write_report(session, output)
        console.print(f"[green]Export written:[/] {saved}")
        return

    suffix = "txt" if export_format == "text" else "json"
    destination = output or session.with_suffix(f".{suffix}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if export_format == "text":
        destination.write_text(loaded.output_text, encoding="utf-8")
    else:
        destination.write_text(json.dumps({"meta": loaded.meta, "exit": loaded.exit, "events": loaded.events}, indent=2), encoding="utf-8")
    console.print(f"[green]Export written:[/] {destination}")


@cli.command()
def rules() -> None:
    """List built-in audit rules."""

    table = Table(title="Shellguard Rules")
    table.add_column("Rule", style="cyan")
    table.add_column("Severity", style="bold")
    table.add_column("Description")
    for rule in RULES:
        table.add_row(rule.id, rule.severity, rule.message)
    console.print(table)

