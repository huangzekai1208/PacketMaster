from __future__ import annotations

import io
import json
import subprocess
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.helpers import load_script_module


@pytest.fixture
def tshark_module():
    return load_script_module("lib/tshark.py", "task3_tshark")


def test_find_tshark_prefers_configured_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    configured = tmp_path / "configured-tshark"
    configured.write_text("", encoding="utf-8")
    environment_tshark = tmp_path / "environment-tshark"
    environment_tshark.write_text("", encoding="utf-8")
    monkeypatch.setenv("TSHARK_PATH", str(environment_tshark))

    assert tshark_module.find_tshark(str(configured)) == configured.resolve()


def test_find_tshark_prefers_environment_over_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    environment_tshark = tmp_path / "environment-tshark"
    environment_tshark.write_text("", encoding="utf-8")
    path_tshark = tmp_path / "path-tshark"
    path_tshark.write_text("", encoding="utf-8")
    monkeypatch.setenv("TSHARK_PATH", str(environment_tshark))
    monkeypatch.setattr(tshark_module.shutil, "which", lambda name: str(path_tshark))

    assert tshark_module.find_tshark() == environment_tshark.resolve()


def test_find_tshark_uses_windows_program_files_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    program_files = tmp_path / "Program Files"
    candidate = program_files / "Wireshark" / "tshark.exe"
    candidate.parent.mkdir(parents=True)
    candidate.write_text("", encoding="utf-8")
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.setattr(tshark_module.platform, "system", lambda: "Windows")
    monkeypatch.setenv("ProgramFiles", str(program_files))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setattr(tshark_module.shutil, "which", lambda name: None)

    assert tshark_module.find_tshark() == candidate.resolve()


def test_windows_candidates_skip_missing_program_files_environment_variables(
    monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    monkeypatch.setattr(tshark_module.platform, "system", lambda: "Windows")
    monkeypatch.delenv("ProgramFiles", raising=False)
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)

    assert tshark_module._platform_candidates() == [
        Path(r"C:\Program Files\Wireshark\tshark.exe")
    ]


def test_find_tshark_checks_macos_app_bundle(
    monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    expected = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
    checked: list[Path] = []
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.setattr(tshark_module.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(tshark_module.shutil, "which", lambda name: None)

    def is_file(path: Path) -> bool:
        checked.append(path)
        return path == expected

    monkeypatch.setattr(tshark_module.Path, "is_file", is_file)

    assert tshark_module.find_tshark() == expected.resolve()
    assert expected in checked


def test_find_tshark_raises_dependency_error_when_unavailable(
    monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    monkeypatch.delenv("TSHARK_PATH", raising=False)
    monkeypatch.setattr(tshark_module.shutil, "which", lambda name: None)
    monkeypatch.setattr(tshark_module.Path, "is_file", lambda path: False)

    with pytest.raises(RuntimeError, match=r"^DEPENDENCY_UNAVAILABLE"):
        tshark_module.find_tshark()


def test_normalize_capture_returns_resolved_pcapng(
    tmp_path: Path, tshark_module
) -> None:
    capture = tmp_path / "input.pcapng"
    capture.write_bytes(b"pcapng")

    normalized = tshark_module.normalize_capture(
        capture, tmp_path / "output", Path("tshark")
    )

    assert normalized == capture.resolve()


def test_normalize_capture_converts_pcap_with_safe_argument_array(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    capture = tmp_path / "network trace.pcap"
    capture.write_bytes(b"pcap")
    output_dir = tmp_path / "converted"
    calls: list[list[str]] = []

    def run(command: list[str], **kwargs: object):
        calls.append(command)
        assert kwargs["stdout"] is subprocess.DEVNULL
        assert kwargs["stderr"].writable()
        assert kwargs["stderr"].errors == "replace"
        assert {
            key: value
            for key, value in kwargs.items()
            if key not in {"stdout", "stderr"}
        } == {"text": True, "encoding": "utf-8", "errors": "replace"}
        Path(command[-1]).write_bytes(b"pcapng")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(tshark_module.subprocess, "run", run)

    result = tshark_module.normalize_capture(capture, output_dir, Path("tshark"))

    assert result == output_dir / "network trace.pcapng"
    assert calls == [["tshark", "-r", str(capture), "-w", str(result)]]


def test_normalize_capture_rejects_unknown_extension(
    tmp_path: Path, tshark_module
) -> None:
    capture = tmp_path / "input.txt"
    capture.write_text("not a capture", encoding="utf-8")

    with pytest.raises(RuntimeError, match=r"^INVALID_CAPTURE"):
        tshark_module.normalize_capture(capture, tmp_path / "output", Path("tshark"))


def test_normalize_capture_reports_conversion_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    capture = tmp_path / "input.pcap"
    capture.write_bytes(b"pcap")
    stderr = "x" * 501
    def run(command: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        assert kwargs["stdout"] is subprocess.DEVNULL
        kwargs["stderr"].write(stderr)
        kwargs["stderr"].flush()
        return subprocess.CompletedProcess(command, 1)

    monkeypatch.setattr(tshark_module.subprocess, "run", run)

    with pytest.raises(RuntimeError) as exc_info:
        tshark_module.normalize_capture(capture, tmp_path / "output", Path("tshark"))

    assert str(exc_info.value).startswith("INVALID_CAPTURE")
    assert stderr not in str(exc_info.value)
    assert stderr[:500] in str(exc_info.value)


class FakeStreamingProcess:
    def __init__(self, lines: str, returncode: int, stderr: str = "") -> None:
        self.stdout = io.StringIO(lines)
        self.returncode = returncode
        self.stderr = stderr
        self.wait_calls = 0
        self.terminate_calls = 0
        self.kill_calls = 0
        self.finished = False

    def poll(self) -> int | None:
        return self.returncode if self.finished else None

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        self.finished = True
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1
        self.finished = True

    def kill(self) -> None:
        self.kill_calls += 1
        self.finished = True


def test_stream_tshark_fields_reads_every_line_without_packet_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    lines = "".join(f"{index}\tvalue\n" for index in range(5001))
    process = FakeStreamingProcess(lines, 0)
    commands: list[list[str]] = []

    def popen(command: list[str], **kwargs: object) -> FakeStreamingProcess:
        commands.append(command)
        assert kwargs["stdout"] is subprocess.PIPE
        assert kwargs["stderr"].errors == "replace"
        return process

    monkeypatch.setattr(tshark_module.subprocess, "Popen", popen)

    rows = list(
        tshark_module.stream_tshark_fields(
            Path("tshark"), tmp_path / "capture.pcapng", ["number", "value"], "tcp"
        )
    )

    assert len(rows) == 5001
    assert rows[-1] == {"number": "5000", "value": "value"}
    assert commands == [
        [
            "tshark",
            "-r",
            str(tmp_path / "capture.pcapng"),
            "-T",
            "fields",
            "-e",
            "number",
            "-e",
            "value",
            "-Y",
            "tcp",
        ]
    ]
    assert "-" + "c" not in commands[0]


def test_stream_tshark_fields_pads_short_rows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    process = FakeStreamingProcess("first\n", 0)
    monkeypatch.setattr(
        tshark_module.subprocess, "Popen", lambda *args, **kwargs: process
    )

    rows = list(
        tshark_module.stream_tshark_fields(
            Path("tshark"), tmp_path / "capture.pcapng", ["one", "two"], "tcp"
        )
    )

    assert rows == [{"one": "first", "two": ""}]


def test_stream_tshark_fields_raises_analysis_error_on_nonzero_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    process = FakeStreamingProcess("", 1, "failure details")

    def popen(command: list[str], **kwargs: object) -> FakeStreamingProcess:
        stderr = kwargs["stderr"]
        stderr.write(process.stderr)
        stderr.flush()
        return process

    monkeypatch.setattr(tshark_module.subprocess, "Popen", popen)

    with pytest.raises(RuntimeError, match=r"^ANALYSIS_FAILED"):
        list(
            tshark_module.stream_tshark_fields(
                Path("tshark"), tmp_path / "capture.pcapng", ["one"], "tcp"
            )
        )


def test_stream_tshark_fields_terminates_process_when_closed_early(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    process = FakeStreamingProcess("first\nsecond\n", 0)
    monkeypatch.setattr(
        tshark_module.subprocess, "Popen", lambda *args, **kwargs: process
    )
    stream = tshark_module.stream_tshark_fields(
        Path("tshark"), tmp_path / "capture.pcapng", ["one"], "tcp"
    )

    assert next(stream) == {"one": "first"}
    stream.close()

    assert process.terminate_calls == 1
    assert process.wait_calls == 1


def test_stream_tshark_fields_times_out_and_terminates_blocked_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tshark_module
) -> None:
    released = threading.Event()

    class BlockingStdout:
        def __iter__(self):
            released.wait(timeout=1)
            return iter(())

        def close(self) -> None:
            released.set()

    class BlockingProcess:
        def __init__(self) -> None:
            self.stdout = BlockingStdout()
            self.finished = False
            self.terminate_calls = 0

        def poll(self) -> int | None:
            return -15 if self.finished else None

        def wait(self, timeout: float | None = None) -> int:
            released.wait(timeout=timeout or 1)
            self.finished = True
            return -15

        def terminate(self) -> None:
            self.terminate_calls += 1
            self.finished = True
            released.set()

        def kill(self) -> None:
            self.finished = True
            released.set()

    process = BlockingProcess()
    monkeypatch.setattr(
        tshark_module.subprocess, "Popen", lambda *args, **kwargs: process
    )

    with pytest.raises(TimeoutError, match="timed out"):
        list(
            tshark_module.stream_tshark_fields(
                Path("tshark"),
                tmp_path / "capture.pcapng",
                ["frame.number"],
                "tcp",
                timeout_seconds=0.01,
            )
        )

    assert process.terminate_calls == 1


def test_progress_writer_appends_utf8_jsonl_with_utc_timestamps(tmp_path: Path) -> None:
    progress_module = load_script_module("lib/progress.py", "task3_progress")
    progress_path = tmp_path / "nested" / "progress.jsonl"
    writer = progress_module.ProgressWriter(progress_path)

    writer.emit("capture", 1, 2, "正在转换")
    writer.emit("analysis", 2, 2, "完成")

    lines = progress_path.read_text(encoding="utf-8").splitlines()
    events = [json.loads(line) for line in lines]
    assert events[0]["stage"] == "capture"
    assert events[0]["current"] == 1
    assert events[0]["total"] == 2
    assert events[0]["message"] == "正在转换"
    assert events[1]["stage"] == "analysis"
    assert events[1]["message"] == "完成"
    for event in events:
        assert datetime.fromisoformat(event["timestamp"]).tzinfo == UTC
