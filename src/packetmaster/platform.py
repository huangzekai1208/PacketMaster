"""Cross-platform process and path helpers."""

from __future__ import annotations

import asyncio
import os
import subprocess
from pathlib import Path, PureWindowsPath
from typing import Protocol

import psutil


class TerminableProcess(Protocol):
    returncode: int | None

    def terminate(self) -> None: ...

    def kill(self) -> None: ...

    async def wait(self) -> int: ...


def is_absolute_path(value: str | Path) -> bool:
    """Recognize POSIX and drive-qualified Windows absolute paths everywhere."""
    path_value = str(value)
    return Path(path_value).is_absolute() or PureWindowsPath(path_value).is_absolute()


def subprocess_text_options() -> dict[str, object]:
    """Return portable text-decoding options for parameter-array subprocess calls."""
    return {"text": True, "encoding": "utf-8", "errors": "replace"}


def subprocess_group_options() -> dict[str, object]:
    """Start a child in an isolated process group on Windows and POSIX."""
    if os.name == "nt":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _descendants(pid: int | None) -> list[psutil.Process]:
    if pid is None:
        return []
    try:
        return psutil.Process(pid).children(recursive=True)
    except (psutil.Error, OSError):
        return []


async def terminate_process(
    process: TerminableProcess, grace_seconds: float = 5.0
) -> None:
    """End a subprocess using APIs available on Windows and POSIX platforms."""
    if process.returncode is not None:
        return

    descendants = _descendants(getattr(process, "pid", None))
    for child in descendants:
        try:
            child.terminate()
        except (psutil.Error, OSError):
            pass
    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
    except TimeoutError:
        process.kill()
        await process.wait()
    _, alive = psutil.wait_procs(descendants, timeout=max(0.0, grace_seconds))
    for child in alive:
        try:
            child.kill()
        except (psutil.Error, OSError):
            pass
    if alive:
        psutil.wait_procs(alive, timeout=max(0.0, grace_seconds))
