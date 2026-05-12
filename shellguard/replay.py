"""Replay Shellguard sessions."""

from __future__ import annotations

import sys
import time
from pathlib import Path

from .storage import decode_bytes, iter_events


def replay_session(path: str | Path, *, speed: float = 1.0, timing: bool = True) -> None:
    if speed <= 0:
        speed = 1.0
    previous_offset: float | None = None
    for event in iter_events(Path(path)):
        if event.get("type") != "output":
            continue
        offset = float(event.get("offset", 0.0) or 0.0)
        if timing and previous_offset is not None:
            delay = max(0.0, (offset - previous_offset) / speed)
            if delay:
                time.sleep(min(delay, 5.0))
        previous_offset = offset
        sys.stdout.buffer.write(decode_bytes(str(event.get("data", ""))))
        sys.stdout.buffer.flush()

