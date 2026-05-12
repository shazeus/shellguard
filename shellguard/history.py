"""Shell history scanning."""

from __future__ import annotations

import os
from pathlib import Path

from .scanner import Finding, scan_text


def default_history_paths() -> list[Path]:
    candidates: list[Path] = []
    histfile = os.environ.get("HISTFILE")
    if histfile:
        candidates.append(Path(histfile).expanduser())
    home = Path.home()
    candidates.extend([home / ".zsh_history", home / ".bash_history", home / ".history"])

    unique: list[Path] = []
    seen: set[Path] = set()
    for path in candidates:
        resolved = path.expanduser()
        if resolved not in seen and resolved.exists():
            unique.append(resolved)
            seen.add(resolved)
    return unique


def normalize_history_line(line: str) -> str:
    if line.startswith(": ") and ";" in line:
        return line.split(";", 1)[1]
    return line


def read_history(path: Path, *, limit: int | None = None) -> str:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    commands = [normalize_history_line(line) for line in lines if line.strip()]
    if limit and limit > 0:
        commands = commands[-limit:]
    return "\n".join(commands)


def scan_history(path: Path | None = None, *, limit: int | None = None) -> tuple[Path, list[Finding]]:
    selected = path
    if selected is None:
        paths = default_history_paths()
        if not paths:
            raise FileNotFoundError("No shell history file was found.")
        selected = paths[0]
    selected = selected.expanduser()
    text = read_history(selected, limit=limit)
    return selected, scan_text(text, source=str(selected))

