"""Cross-platform process and path helpers."""

from __future__ import annotations

import asyncio
from pathlib import Path, PureWindowsPath
from typing import Protocol


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


async def terminate_process(
    process: TerminableProcess, grace_seconds: float = 5.0
) -> None:
    """End a subprocess using APIs available on Windows and POSIX platforms."""
    if process.returncode is not None:
        return

    process.terminate()
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
    except TimeoutError:
        process.kill()
        await process.wait()
