from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path

import psutil
import pytest

from packetmaster.analyzer.mock import MockAnalyzerAdapter
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    CustomEvidenceQuery,
    EvidenceRequest,
    EvidenceResponse,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server
from packetmaster.platform import subprocess_group_options, terminate_process

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mock_analysis.json"


def _request(**overrides: object) -> AnalyzeRequest:
    values: dict[str, object] = {
        "request_id": "contract-1",
        "pcap_path": str((Path.cwd() / "test capture.pcapng").resolve()),
    }
    values.update(overrides)
    return AnalyzeRequest.model_validate(values)


def test_mock_adapter_returns_deterministic_structured_result() -> None:
    adapter = MockAnalyzerAdapter(FIXTURE)

    response = asyncio.run(adapter.analyze(_request()))

    assert isinstance(response, AnalyzeResponse)
    assert response.target is Target.DOWNLOAD
    assert response.analysis_id == "contract-1"
    assert response.coverage_summary.complete is True
    assert "events" in response.available_evidence


def test_mcp_tools_normalize_default_and_explicit_targets() -> None:
    async def exercise() -> list[dict[str, object]]:
        adapter = MockAnalyzerAdapter(FIXTURE)
        server = create_server(adapter)
        async with SpeedMCPClient(server) as client:
            outputs = []
            for target in (None, "upload", "both"):
                payload = _request(**({} if target is None else {"target": target}))
                result = await client.analyze_speed_capture(payload)
                outputs.append(result.model_dump(mode="json"))
            return outputs

    outputs = asyncio.run(exercise())
    assert [item["target"] for item in outputs] == ["download", "upload", "both"]


def test_evidence_is_structured_and_paginated() -> None:
    async def exercise() -> EvidenceResponse:
        server = create_server(MockAnalyzerAdapter(FIXTURE))
        async with SpeedMCPClient(server) as client:
            return await client.get_tcp_evidence(
                EvidenceRequest(
                    analysis_id="mock-contract",
                    evidence_type="events",
                    offset=0,
                    limit=1,
                )
            )

    response = asyncio.run(exercise())
    assert isinstance(response, EvidenceResponse)
    assert response.total == 2
    assert len(response.items) == 1
    assert response.next_offset == 1
    assert response.source == "mock"
    assert response.coverage_range["complete"] is False


def test_unsafe_evidence_query_is_rejected() -> None:
    adapter = MockAnalyzerAdapter(FIXTURE)
    with pytest.raises(AppError) as error:
        asyncio.run(
            adapter.get_evidence(
                EvidenceRequest(
                    analysis_id="mock-contract",
                    evidence_type="events",
                    fields=["events; DROP TABLE events"],
                )
            )
        )
    assert error.value.code == "UNSAFE_EVIDENCE_QUERY"


def test_fixture_is_payload_free() -> None:
    payload = FIXTURE.read_text(encoding="utf-8")
    assert "payload" not in payload.lower()
    assert "tcp.payload" not in payload.lower()


class FakeProcess:
    def __init__(self, *, returncode: int = 0, never_finishes: bool = False) -> None:
        self.pid = os.getpid()
        self.returncode: int | None = None
        self._final_returncode = returncode
        self.never_finishes = never_finishes
        self.terminated = False
        self.killed = False

    async def wait(self) -> int:
        if self.never_finishes and not self.terminated and not self.killed:
            await asyncio.Future()
        self.returncode = self._final_returncode
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = self._final_returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = self._final_returncode


def _write_real_outputs(
    output: Path, target: str, *, status: str = "completed"
) -> None:
    coverage = {
        "input_size_bytes": 7,
        "total_packets_seen": 3,
        "tcp_packets_seen": 3,
        "speed_packets_analyzed": 2,
        "analyzed_bytes": 1400,
        "analyzed_duration_seconds": 1.0,
        "complete": True,
        "truncated": False,
        "truncation_reason": None,
    }
    summary = {
        "coverage_summary": coverage,
        "tcp_summary": {"retransmissions": 0},
        "flow_summary": {"f-1": {"direction": target}},
        "interval_summary": [],
        "syn_options": {},
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "logs").mkdir(exist_ok=True)
    (output / "filtered").mkdir(exist_ok=True)
    (output / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
    (output / "tcp_analysis.json").write_text(json.dumps(summary), encoding="utf-8")
    (output / "speed_stats.json").write_text("{}", encoding="utf-8")
    (output / "progress.jsonl").write_text("", encoding="utf-8")
    (output / "logs" / "filter.log").write_text("", encoding="utf-8")
    manifest = {
        "analysis_id": "real-contract",
        "status": status,
        "target": target,
        "input_path": str((output / "input.pcapng").resolve()),
        "normalized_capture_path": None,
        "coverage_summary": coverage,
        "available_evidence": ["summary", "flows"],
        "warnings": [],
        "artifact_paths": {
            "manifest": str((output / "manifest.json").resolve()),
            "coverage": str((output / "coverage.json").resolve()),
            "speed_stats": str((output / "speed_stats.json").resolve()),
            "tcp_analysis": str((output / "tcp_analysis.json").resolve()),
            "progress": str((output / "progress.jsonl").resolve()),
            "logs": {"filter": str((output / "logs" / "filter.log").resolve())},
            "filtered_captures": {},
        },
        "error": None,
        "started_at": "2026-07-22T00:00:00+00:00",
        "completed_at": "2026-07-22T00:00:01+00:00",
    }
    (output / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")


def test_real_adapter_uses_argument_array_and_disk_logs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "中文 capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "run pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    calls: list[tuple[tuple[object, ...], dict[str, object]]] = []

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        calls.append((args, kwargs))
        output = Path(str(args[args.index("--output") + 1]))
        target = str(args[args.index("--target") + 1])
        _write_real_outputs(output, target)
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    response = asyncio.run(
        adapter.analyze(
            AnalyzeRequest(
                request_id="real-contract",
                pcap_path=str(capture.resolve()),
                target="upload",
            )
        )
    )

    args, kwargs = calls[0]
    assert "--target" in args
    assert args[args.index("--target") + 1] == "upload"
    assert kwargs["stdout"] is kwargs["stderr"]
    assert "shell" not in kwargs
    assert response.target is Target.UPLOAD
    assert response.artifact_paths["manifest"].endswith("manifest.json")
    pipeline_log = (
        tmp_path / "artifacts" / "real-contract" / "logs" / "pipeline.log"
    )
    assert pipeline_log.is_file()


def test_real_adapter_timeout_terminates_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    process = FakeProcess(never_finishes=True)

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
        timeout_calculator=lambda size: 0.01,
    )

    with pytest.raises(AppError) as error:
        request = _request(request_id="timeout", pcap_path=str(capture))
        asyncio.run(adapter.analyze(request))
    assert error.value.code == "ANALYSIS_TIMEOUT"
    assert process.terminated is True


def test_real_adapter_rejects_unsafe_analysis_id(tmp_path: Path) -> None:
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=tmp_path / "pipeline.py",
    )
    with pytest.raises(AppError) as error:
        asyncio.run(
            adapter.get_evidence(
                EvidenceRequest(analysis_id="../outside", evidence_type="events")
            )
        )
    assert error.value.code == "INVALID_ANALYSIS_ID"


def test_speed_mcp_client_builds_stdio_transport_from_argument_array(
    tmp_path: Path,
) -> None:
    server_script = tmp_path / "mock stdio server.py"
    server_script.write_text(
        "\n".join(
            [
                "import sys",
                f"sys.path.insert(0, {str((Path.cwd() / 'src').resolve())!r})",
                "from pathlib import Path",
                "from packetmaster.analyzer.mock import MockAnalyzerAdapter",
                "from packetmaster.mcp.server import create_server",
                f"fixture = Path({str(FIXTURE.resolve())!r})",
                "create_server(MockAnalyzerAdapter(fixture)).run(",
                "    transport='stdio', show_banner=False",
                ")",
            ]
        ),
        encoding="utf-8",
    )

    async def exercise() -> AnalyzeResponse:
        client = SpeedMCPClient.from_stdio(
            sys.executable,
            [str(server_script)],
            cwd=str(tmp_path),
            log_file=str(tmp_path / "mcp.log"),
        )
        async with client:
            return await client.analyze_speed_capture(_request())

    response = asyncio.run(exercise())
    assert response.analysis_id == "contract-1"
    assert response.target is Target.DOWNLOAD


def test_real_adapter_rejects_manifest_artifact_outside_task_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    outside = tmp_path / "outside.json"
    outside.write_text(
        json.dumps(
            {
                "flows": {},
                "tcp_summary": {},
                "intervals": [],
                "syn_options": {},
            }
        ),
        encoding="utf-8",
    )

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        output = Path(str(args[args.index("--output") + 1]))
        _write_real_outputs(output, "download")
        manifest_path = output / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["analysis_id"] = "outside"
        manifest["artifact_paths"]["logs"]["filter"] = str(outside)
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="outside", pcap_path=str(capture))
    with pytest.raises(AppError) as error:
        asyncio.run(adapter.analyze(request))
    assert error.value.code == "INVALID_ANALYSIS_OUTPUT"


def test_mcp_preserves_structured_app_error() -> None:
    class FailingAdapter(MockAnalyzerAdapter):
        async def analyze(
            self, request: AnalyzeRequest, progress_callback: object | None = None
        ) -> AnalyzeResponse:
            raise AppError(
                code="ANALYSIS_TIMEOUT",
                message="timed out",
                recoverable=True,
                suggested_action="retry later",
                details={"timeout_seconds": 300},
            )

    async def exercise() -> None:
        async with SpeedMCPClient(create_server(FailingAdapter(FIXTURE))) as client:
            with pytest.raises(AppError) as error:
                await client.analyze_speed_capture(_request())
            assert error.value.code == "ANALYSIS_TIMEOUT"
            assert error.value.recoverable is True
            assert error.value.details == {"timeout_seconds": 300}

    asyncio.run(exercise())


def test_mcp_forwards_progress_notifications() -> None:
    class ProgressAdapter(MockAnalyzerAdapter):
        async def analyze(
            self, request: AnalyzeRequest, progress_callback: object | None = None
        ) -> AnalyzeResponse:
            assert callable(progress_callback)
            await progress_callback(1.0, 2.0, "half")
            await progress_callback(2.0, 2.0, "done")
            return await super().analyze(request)

    async def exercise() -> list[tuple[float | None, str | None]]:
        events: list[tuple[float | None, str | None]] = []

        def progress(value: float | None, message: str | None) -> None:
            events.append((value, message))

        async with SpeedMCPClient(
            create_server(ProgressAdapter(FIXTURE)), progress_callback=progress
        ) as client:
            await client.analyze_speed_capture(_request())
        return events

    assert asyncio.run(exercise()) == [(0.5, "half"), (1.0, "done")]


def test_real_custom_query_detects_page_after_limit_500(tmp_path: Path) -> None:
    analysis_root = tmp_path / "artifacts" / "page-500"
    analysis_root.mkdir(parents=True)
    database = analysis_root / "analysis.sqlite"
    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE events (
            evidence_id TEXT PRIMARY KEY,
            event_type TEXT NOT NULL,
            frame_number INTEGER,
            time_relative REAL,
            flow_id TEXT NOT NULL,
            direction TEXT NOT NULL,
            tcp_seq INTEGER,
            tcp_ack INTEGER,
            tcp_window_size INTEGER,
            tcp_len INTEGER,
            ack_rtt REAL
        );
        CREATE TABLE summary (name TEXT PRIMARY KEY, value_json TEXT NOT NULL);
        CREATE TABLE flows (flow_id TEXT PRIMARY KEY, data_json TEXT NOT NULL);
        CREATE TABLE intervals (
            interval_start REAL NOT NULL,
            direction TEXT NOT NULL,
            data_json TEXT NOT NULL,
            PRIMARY KEY (interval_start, direction)
        );
        CREATE TABLE syn_options (name TEXT PRIMARY KEY, value_json TEXT NOT NULL);
        """
    )
    connection.executemany(
        """
        INSERT INTO events (
            evidence_id, event_type, frame_number, time_relative,
            flow_id, direction
        ) VALUES (?, 'retransmission', ?, ?, 'f-1', 'download')
        """,
        ((f"ev-{index}", index, float(index)) for index in range(501)),
    )
    connection.commit()
    connection.close()
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=Path.cwd()
        / "speed-analyze"
        / "scripts"
        / "run_pipeline.py",
    )
    response = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id="page-500",
                evidence_type="events",
                limit=500,
                query=CustomEvidenceQuery(fields=["evidence_id"]),
            )
        )
    )
    assert len(response.items) == 500
    assert response.next_offset == 500
    assert response.truncated is True
    with pytest.raises(AppError) as error:
        asyncio.run(
            adapter.get_evidence(
                EvidenceRequest(
                    analysis_id="page-500",
                    evidence_type="events",
                    query=CustomEvidenceQuery(fields=["events; DROP TABLE events"]),
                )
            )
        )
    assert error.value.code == "UNSAFE_EVIDENCE_QUERY"


def test_terminate_process_cleans_real_descendant(tmp_path: Path) -> None:
    pid_file = tmp_path / "child.pid"
    parent_code = "\n".join(
        [
            "import pathlib, subprocess, sys, time",
            "child = subprocess.Popen([sys.executable, '-c', "
            "'import time; time.sleep(60)'])",
            f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))",
            "time.sleep(60)",
        ]
    )

    async def exercise() -> int:
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            parent_code,
            **subprocess_group_options(),
        )
        for _ in range(100):
            if pid_file.is_file():
                break
            await asyncio.sleep(0.01)
        child_pid = int(pid_file.read_text(encoding="utf-8"))
        await terminate_process(process, grace_seconds=0.2)
        return child_pid

    child_pid = asyncio.run(exercise())
    assert not psutil.pid_exists(child_pid) or (
        psutil.Process(child_pid).status() == psutil.STATUS_ZOMBIE
    )
