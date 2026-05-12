"""Session file helpers for Shellguard JSONL recordings."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


SESSION_VERSION = 1


class SessionError(RuntimeError):
    """Raised when a Shellguard session cannot be read or written."""


@dataclass(frozen=True)
class SessionData:
    path: Path
    events: list[dict[str, Any]]
    meta: dict[str, Any]
    exit: dict[str, Any]
    output_bytes: bytes

    @property
    def output_text(self) -> str:
        return self.output_bytes.decode("utf-8", errors="replace")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def default_session_path() -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / f"shellguard-session-{stamp}.jsonl"


def encode_bytes(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_bytes(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:  # pragma: no cover - defensive branch
        raise SessionError("Session contains invalid base64 output data.") from exc


def append_event(path: Path, event: dict[str, Any]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    except OSError as exc:
        raise SessionError(f"Could not write session {path}: {exc}") from exc


def iter_events(path: Path) -> Iterator[dict[str, Any]]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    value = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise SessionError(f"Invalid JSON on line {line_number} in {path}.") from exc
                if not isinstance(value, dict):
                    raise SessionError(f"Session line {line_number} is not an object.")
                yield value
    except OSError as exc:
        raise SessionError(f"Could not read session {path}: {exc}") from exc


def load_session(path: str | Path) -> SessionData:
    session_path = Path(path)
    if not session_path.exists():
        raise SessionError(f"Session not found: {session_path}")
    events = list(iter_events(session_path))
    if not events:
        raise SessionError(f"Session is empty: {session_path}")

    meta = next((event for event in events if event.get("type") == "meta"), {})
    exit_event = next((event for event in reversed(events) if event.get("type") == "exit"), {})
    output = bytearray()
    for event in events:
        if event.get("type") == "output":
            output.extend(decode_bytes(str(event.get("data", ""))))

    return SessionData(
        path=session_path,
        events=events,
        meta=meta,
        exit=exit_event,
        output_bytes=bytes(output),
    )

