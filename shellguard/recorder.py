"""PTY-backed terminal session recording."""

from __future__ import annotations

import os
import pty
import select
import shlex
import signal
import subprocess
import sys
import termios
import time
import tty
from pathlib import Path
from typing import Sequence

from .storage import SESSION_VERSION, append_event, default_session_path, encode_bytes, utc_now


class RecordingError(RuntimeError):
    """Raised when a terminal session cannot be recorded."""


def _normalize_command(command: Sequence[str], use_shell: bool) -> list[str]:
    if use_shell:
        shell = os.environ.get("SHELL") or "/bin/sh"
        script = " ".join(command) if command else shell
        return [shell, "-lc", script]
    if command:
        return list(command)
    return [os.environ.get("SHELL") or "/bin/sh"]


def _display_command(command: Sequence[str], use_shell: bool) -> str:
    if use_shell:
        return " ".join(command) if command else os.environ.get("SHELL", "/bin/sh")
    return " ".join(shlex.quote(part) for part in command) if command else os.environ.get("SHELL", "/bin/sh")


def _drain_master(master_fd: int, output_path: Path, started: float) -> bool:
    wrote = False
    while True:
        ready, _, _ = select.select([master_fd], [], [], 0)
        if master_fd not in ready:
            return wrote
        try:
            chunk = os.read(master_fd, 65536)
        except OSError:
            return wrote
        if not chunk:
            return wrote
        sys.stdout.buffer.write(chunk)
        sys.stdout.buffer.flush()
        append_event(
            output_path,
            {
                "type": "output",
                "time": utc_now(),
                "offset": round(time.monotonic() - started, 6),
                "stream": "pty",
                "data": encode_bytes(chunk),
            },
        )
        wrote = True


def record_command(command: Sequence[str], output: str | Path | None = None, *, use_shell: bool = False) -> tuple[Path, int]:
    """Record a command into a Shellguard JSONL session."""

    output_path = Path(output) if output else default_session_path()
    argv = _normalize_command(command, use_shell)
    display = _display_command(command, use_shell)
    started = time.monotonic()

    append_event(
        output_path,
        {
            "type": "meta",
            "version": SESSION_VERSION,
            "time": utc_now(),
            "command": display,
            "argv": argv,
            "cwd": str(Path.cwd()),
            "pid": os.getpid(),
        },
    )

    master_fd, slave_fd = pty.openpty()
    old_termios = None
    stdin_fd = sys.stdin.fileno()
    interactive = sys.stdin.isatty()

    try:
        if interactive:
            old_termios = termios.tcgetattr(stdin_fd)
            tty.setraw(stdin_fd)

        try:
            proc = subprocess.Popen(argv, stdin=slave_fd, stdout=slave_fd, stderr=slave_fd, close_fds=True)
        except FileNotFoundError as exc:
            raise RecordingError(f"Command not found: {argv[0]}") from exc
        finally:
            os.close(slave_fd)

        def forward_signal(signum: int, _frame: object) -> None:
            if proc.poll() is None:
                proc.send_signal(signum)

        old_sigint = signal.signal(signal.SIGINT, forward_signal)
        old_sigterm = signal.signal(signal.SIGTERM, forward_signal)
        try:
            while True:
                watched = [master_fd]
                if interactive:
                    watched.append(stdin_fd)
                ready, _, _ = select.select(watched, [], [], 0.1)

                if master_fd in ready:
                    try:
                        chunk = os.read(master_fd, 65536)
                    except OSError:
                        break
                    if chunk:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                        append_event(
                            output_path,
                            {
                                "type": "output",
                                "time": utc_now(),
                                "offset": round(time.monotonic() - started, 6),
                                "stream": "pty",
                                "data": encode_bytes(chunk),
                            },
                        )

                if interactive and stdin_fd in ready:
                    data = os.read(stdin_fd, 4096)
                    if data:
                        os.write(master_fd, data)

                if proc.poll() is not None:
                    _drain_master(master_fd, output_path, started)
                    break
        finally:
            signal.signal(signal.SIGINT, old_sigint)
            signal.signal(signal.SIGTERM, old_sigterm)

        returncode = int(proc.wait())
    finally:
        if old_termios is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_termios)
        try:
            os.close(master_fd)
        except OSError:
            pass

    append_event(
        output_path,
        {
            "type": "exit",
            "time": utc_now(),
            "offset": round(time.monotonic() - started, 6),
            "returncode": returncode,
            "duration": round(time.monotonic() - started, 6),
        },
    )
    return output_path, returncode

