from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from packetmaster.platform import (
    is_absolute_path,
    subprocess_text_options,
    terminate_process,
)


@pytest.mark.parametrize(
    "value",
    [
        "/captures/network trace.pcapng",
        "/tmp/测试/流量.pcap",
        r"C:\\captures\\network trace.pcapng",
        r"D:\\分析\\流量.pcap",
        Path("/var/tmp/capture.pcap"),
    ],
)
def test_is_absolute_path_accepts_posix_and_windows_paths(value: str | Path) -> None:
    assert is_absolute_path(value)


@pytest.mark.parametrize(
    "value", ["capture.pcap", "folder/capture.pcap", r"C:capture.pcap"]
)
def test_is_absolute_path_rejects_relative_paths(value: str) -> None:
    assert not is_absolute_path(value)


def test_subprocess_text_options_are_safe_and_utf8() -> None:
    assert subprocess_text_options() == {
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
    }


class RecordingProcess:
    def __init__(self, waits: list[object]) -> None:
        self.returncode: int | None = None
        self.waits = waits
        self.terminate_calls = 0
        self.kill_calls = 0

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1

    async def wait(self) -> int:
        outcome = self.waits.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        self.returncode = int(outcome)
        return self.returncode


def test_terminate_process_waits_after_terminate() -> None:
    process = RecordingProcess([0])

    asyncio.run(terminate_process(process))

    assert process.terminate_calls == 1
    assert process.kill_calls == 0


def test_terminate_process_kills_after_grace_timeout() -> None:
    process = RecordingProcess([TimeoutError(), 1])

    asyncio.run(terminate_process(process, grace_seconds=0.01))

    assert process.terminate_calls == 1
    assert process.kill_calls == 1


def test_terminate_process_does_nothing_when_process_has_exited() -> None:
    process = RecordingProcess([])
    process.returncode = 0

    asyncio.run(terminate_process(process))

    assert process.terminate_calls == 0
    assert process.kill_calls == 0
