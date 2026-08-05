from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import threading
from pathlib import Path

import psutil
import pytest
from fastmcp import Client as FastMCPClient
from pydantic import ValidationError

from packetmaster.analyzer.mock import MockAnalyzerAdapter
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.context import ContextBuilder
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    CustomEvidenceQuery,
    EvidencePredicate,
    EvidenceRequest,
    EvidenceResponse,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server
from packetmaster.platform import subprocess_group_options, terminate_process
from tests.helpers import load_script_module

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
    request = EvidenceRequest(
        analysis_id="mock-contract",
        evidence_type="events",
        fields=["evidence_id"],
    ).model_copy(update={"fields": ["events; DROP TABLE events"]})
    with pytest.raises(AppError) as error:
        asyncio.run(adapter.get_evidence(request))
    assert error.value.code == "UNSAFE_EVIDENCE_QUERY"


def test_oversized_serialized_evidence_query_is_rejected_before_adapter_io() -> None:
    adapter = MockAnalyzerAdapter(FIXTURE)
    request = EvidenceRequest(
        analysis_id="mock-contract",
        evidence_type="events",
        query=CustomEvidenceQuery(
            predicates=[
                EvidencePredicate(
                    field="tcp.len",
                    operator="eq",
                    value={"nested": "x" * 40_000},
                )
            ]
        ),
    )

    with pytest.raises(AppError) as error:
        asyncio.run(adapter.get_evidence(request))

    assert error.value.code == "UNSAFE_EVIDENCE_QUERY"
    assert "size" in error.value.message.lower()


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
    output: Path,
    target: str,
    *,
    input_path: Path,
    analysis_id: str = "real-contract",
    status: str = "completed",
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
    (output / "speed_stats.json").write_text(
        json.dumps(
            {
                "sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
                "original_input_sha256": hashlib.sha256(
                    input_path.read_bytes()
                ).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    (output / "progress.jsonl").write_text("", encoding="utf-8")
    (output / "logs" / "filter.log").write_text("", encoding="utf-8")
    manifest = {
        "analysis_id": analysis_id,
        "status": status,
        "target": target,
        "input_path": str(input_path.resolve()),
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
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(output, target, input_path=input_path)
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
    assert "timeout_seconds" not in response.resource_usage
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


def test_real_adapter_clears_active_marker_when_pipeline_log_open_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    real_open = Path.open

    def fail_pipeline_log(path: Path, *args: object, **kwargs: object):
        if path.name == "pipeline.log":
            raise OSError("disk unavailable")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", fail_pipeline_log)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )

    with pytest.raises(OSError, match="disk unavailable"):
        asyncio.run(
            adapter.analyze(
                _request(request_id="log-open", pcap_path=str(capture.resolve()))
            )
        )

    assert not (tmp_path / "artifacts" / "log-open" / ".active").exists()


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
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(
            output,
            "download",
            input_path=input_path,
        )
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
                evidence_type="retransmission",
                flow_id="ignored-by-query",
                limit=500,
                query=CustomEvidenceQuery(
                    flow_ids=["f-1"], fields=["evidence_id"]
                ),
            )
        )
    )
    assert len(response.items) == 500
    assert response.next_offset == 500
    assert response.truncated is True
    unsafe_query = CustomEvidenceQuery(fields=["evidence_id"]).model_copy(
        update={"fields": ["events; DROP TABLE events"]}
    )
    with pytest.raises(AppError) as error:
        asyncio.run(
            adapter.get_evidence(
                EvidenceRequest(
                    analysis_id="page-500",
                    evidence_type="events",
                    query=unsafe_query,
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


def test_progress_failure_terminates_running_process(tmp_path: Path) -> None:
    process = FakeProcess(never_finishes=True)
    progress_path = tmp_path / "progress.jsonl"
    progress_path.write_text(
        json.dumps({"current": 1, "total": 2, "message": "half"}) + "\n",
        encoding="utf-8",
    )
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=tmp_path / "pipeline.py",
    )

    async def broken_progress(
        current: float, total: float | None, message: str | None
    ) -> None:
        raise ConnectionError("client disconnected")

    with pytest.raises(AppError) as error:
        asyncio.run(
            adapter._wait(
                process,
                timeout=10,
                progress_path=progress_path,
                progress_callback=broken_progress,
            )
        )
    assert error.value.code == "ANALYSIS_PROGRESS_FAILED"
    assert process.terminated is True


def test_real_adapter_rejects_existing_analysis_id(tmp_path: Path) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    existing = tmp_path / "artifacts" / "duplicate"
    existing.mkdir(parents=True)
    (existing / "manifest.json").write_text("{}", encoding="utf-8")
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="duplicate", pcap_path=str(capture))
    with pytest.raises(AppError) as error:
        asyncio.run(adapter.analyze(request))
    assert error.value.code == "ANALYSIS_ID_CONFLICT"


def test_packet_query_uses_global_epoch_directed_filter_timeout_and_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts" / "packet-query"
    filtered = root / "filtered"
    filtered.mkdir(parents=True)
    download = filtered / "download.pcapng"
    upload = filtered / "upload.pcapng"
    download.write_bytes(b"download")
    upload.write_bytes(b"upload")
    (root / "manifest.json").write_text(
        json.dumps(
            {
                "artifact_paths": {
                    "filtered_captures": {
                        "download": str(download.resolve()),
                        "upload": str(upload.resolve()),
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / "tcp_analysis.json").write_text(
        json.dumps(
            {
                "coverage_summary": {},
                "tcp_summary": {},
                "flow_summary": {},
                "interval_summary": [],
                "syn_options": {},
                "timebase_epoch": 100.0,
            }
        ),
        encoding="utf-8",
    )
    rows = {
        download: [
            {
                "frame.number": "1",
                "frame.time_relative": "0",
                "frame.time_epoch": "100",
                "ip.src": "192.0.2.10",
                "ip.dst": "198.51.100.20",
                "tcp.srcport": "50000",
                "tcp.dstport": "443",
                "tcp.len": "1000",
            }
        ],
        upload: [
            {
                "frame.number": str(number),
                "frame.time_relative": str(number - 2),
                "frame.time_epoch": str(108 + number),
                "ip.src": "192.0.2.10",
                "ip.dst": "198.51.100.20",
                "tcp.srcport": "50000",
                "tcp.dstport": "443",
                "tcp.len": "1000",
            }
            for number in (2, 3)
        ],
    }
    calls: list[tuple[Path, list[str], str, float | None]] = []

    class FakeTShark:
        @staticmethod
        def find_tshark(configured: str | None) -> Path:
            return Path(configured or "tshark")

        @staticmethod
        def stream_tshark_fields(
            tshark_path: Path,
            capture: Path,
            fields: list[str],
            display_filter: str,
            timeout_seconds: float | None = None,
            cancel_event: threading.Event | None = None,
        ):
            calls.append((capture, fields, display_filter, timeout_seconds))
            yield from rows[capture]

    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=Path.cwd() / "speed-analyze" / "scripts" / "run_pipeline.py",
        tshark_path="tshark",
        evidence_timeout_seconds=7,
    )
    monkeypatch.setattr(adapter, "_load_tshark_module", lambda: FakeTShark)
    flow_id = "tcp|192.0.2.10:50000|198.51.100.20:443"

    response = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id="packet-query",
                evidence_type="custom_packet_query",
                query=CustomEvidenceQuery(
                    flow_ids=[flow_id],
                    time_start=9,
                    fields=["frame.number", "frame.time_relative", "tcp.len"],
                    predicates=[
                        EvidencePredicate(field="tcp.len", operator="gt", value=0)
                        ,
                        EvidencePredicate(
                            field="frame.time_relative", operator="gte", value=9
                        ),
                    ],
                ),
                limit=1,
            )
        )
    )

    assert response.items[0]["frame.number"] == 2
    assert response.items[0]["frame.time_relative"] == 10.0
    assert response.source == "filtered:upload"
    assert response.total == 2
    assert response.total_exact is False
    assert response.next_offset == 1
    assert calls
    assert all(call[3] == 7 for call in calls)
    assert all("frame.time_epoch >= 109" in call[2] for call in calls)
    assert all("tcp.len > 0" in call[2] for call in calls)
    assert all("frame.time_relative >=" not in call[2] for call in calls)
    assert all("192.0.2.10" in call[2] and "50000" in call[2] for call in calls)
    assert all("frame.time_epoch" in call[1] for call in calls)

    beyond = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id="packet-query",
                evidence_type="custom_packet_query",
                query=CustomEvidenceQuery(
                    flow_ids=[flow_id],
                    fields=["frame.number"],
                    predicates=[
                        EvidencePredicate(field="tcp.len", operator="gt", value=0)
                    ],
                ),
                offset=10,
                limit=1,
            )
        )
    )
    assert beyond.items == []
    assert beyond.total == 3
    assert beyond.total_exact is True


def test_cancelled_packet_evidence_waits_for_background_query_to_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=Path.cwd() / "speed-analyze" / "scripts" / "run_pipeline.py",
        evidence_timeout_seconds=10,
    )
    stopped = threading.Event()

    def blocking_query(root, request, cancel_event):
        assert cancel_event.wait(timeout=2)
        stopped.set()
        raise InterruptedError("cancelled")

    monkeypatch.setattr(adapter, "_query_packet_evidence", blocking_query)

    async def exercise() -> None:
        task = asyncio.create_task(
            adapter.get_evidence(
                EvidenceRequest(
                    analysis_id="cancel-evidence",
                    evidence_type="packet_fields",
                )
            )
        )
        await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(exercise())

    assert stopped.is_set()


def test_custom_event_packet_query_prefers_sqlite_without_starting_tshark(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "artifacts" / "indexed-packet-query"
    root.mkdir(parents=True)
    store_module = load_script_module("lib/store.py", "indexed_packet_query_store")
    with store_module.AnalysisStore(root / "analysis.sqlite") as store:
        store.initialize()
        store.append_event(
            {
                "evidence_id": "ev-indexed",
                "event_type": "retransmission",
                "frame.number": 42,
                "frame.time_relative": 1.5,
                "flow_id": "f-1",
                "direction": "download",
                "tcp.seq": 1,
                "tcp.ack": 2,
                "tcp.window_size": 65535,
                "tcp.len": 1000,
                "tcp.analysis.ack_rtt": 0.01,
            }
        )
        store.flush_events()
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=Path.cwd() / "speed-analyze" / "scripts" / "run_pipeline.py",
    )
    monkeypatch.setattr(
        adapter,
        "_query_packet_evidence",
        lambda *args: pytest.fail("TShark packet scan must not start"),
    )

    response = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id="indexed-packet-query",
                evidence_type="custom_packet_query",
                query=CustomEvidenceQuery(
                    fields=["evidence_id", "event_type", "frame.number"],
                    predicates=[
                        EvidencePredicate(
                            field="event_type",
                            operator="eq",
                            value="retransmission",
                        )
                    ],
                ),
            )
        )
    )

    assert response.items == [
        {
            "evidence_id": "ev-indexed",
            "event_type": "retransmission",
            "frame.number": 42,
        }
    ]
    assert response.total == 1
    assert response.total_exact is True
    assert response.source.endswith("analysis.sqlite")

    default_events = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id="indexed-packet-query",
                evidence_type="events",
            )
        )
    )
    assert default_events.total == 1
    assert default_events.items[0]["evidence_id"] == "ev-indexed"


def test_real_adapter_reuses_completed_identical_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    starts = 0

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        nonlocal starts
        starts += 1
        output = Path(str(args[args.index("--output") + 1]))
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(output, "download", input_path=input_path)
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="real-contract", pcap_path=str(capture))

    first = asyncio.run(adapter.analyze(request))
    second = asyncio.run(adapter.analyze(request))

    assert starts == 1
    assert first.analysis_id == second.analysis_id == "real-contract"
    assert second.resource_usage["reused"] is True


def test_real_adapter_reuses_pcap_using_original_input_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"original-pcap")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    starts = 0

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        nonlocal starts
        starts += 1
        output = Path(str(args[args.index("--output") + 1]))
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(output, "download", input_path=input_path)
        (output / "speed_stats.json").write_text(
            json.dumps(
                {
                    "sha256": hashlib.sha256(b"normalized-pcapng").hexdigest(),
                    "original_input_sha256": hashlib.sha256(
                        input_path.read_bytes()
                    ).hexdigest(),
                }
            ),
            encoding="utf-8",
        )
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="real-contract", pcap_path=str(capture))

    asyncio.run(adapter.analyze(request))
    reused = asyncio.run(adapter.analyze(request))

    assert starts == 1
    assert reused.resource_usage["reused"] is True


def test_real_adapter_does_not_reuse_same_size_mtime_with_different_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture-A")
    original_mtime_ns = capture.stat().st_mtime_ns
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    starts = 0

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        nonlocal starts
        starts += 1
        output = Path(str(args[args.index("--output") + 1]))
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(output, "download", input_path=input_path)
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="real-contract", pcap_path=str(capture))
    asyncio.run(adapter.analyze(request))

    capture.write_bytes(b"capture-B")
    os.utime(capture, ns=(capture.stat().st_atime_ns, original_mtime_ns))

    with pytest.raises(AppError) as error:
        asyncio.run(adapter.analyze(request))

    assert error.value.code == "ANALYSIS_ID_CONFLICT"
    assert starts == 1


def test_concurrent_same_analysis_id_starts_only_one_pipeline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    script = tmp_path / "pipeline.py"
    script.write_text("# fixture", encoding="utf-8")
    starts = 0

    async def create_process(*args: object, **kwargs: object) -> FakeProcess:
        nonlocal starts
        starts += 1
        output = Path(str(args[args.index("--output") + 1]))
        input_path = Path(str(args[args.index("--input") + 1]))
        _write_real_outputs(
            output,
            "download",
            input_path=input_path,
            analysis_id="concurrent",
        )
        await asyncio.sleep(0)
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
    adapter = RealAnalyzerAdapter(
        artifact_root=tmp_path / "artifacts",
        pipeline_script=script,
    )
    request = _request(request_id="concurrent", pcap_path=str(capture))

    async def exercise() -> list[object]:
        return await asyncio.gather(
            adapter.analyze(request),
            adapter.analyze(request),
            return_exceptions=True,
        )

    results = asyncio.run(exercise())
    assert starts == 1
    assert sum(isinstance(item, AnalyzeResponse) for item in results) >= 1
    errors = [item for item in results if isinstance(item, AppError)]
    assert all(error.code == "ANALYSIS_ID_CONFLICT" for error in errors)
    assert len(errors) + sum(
        isinstance(item, AnalyzeResponse) for item in results
    ) == 2


def test_request_id_rejects_pure_dots() -> None:
    with pytest.raises(ValidationError):
        _request(request_id="..")


def test_invalid_mcp_request_does_not_echo_sensitive_input() -> None:
    secret = "SENSITIVE_PAYLOAD_" * 1000

    async def exercise() -> dict[str, object]:
        server = create_server(MockAnalyzerAdapter(FIXTURE))
        async with FastMCPClient(server) as client:
            result = await client.call_tool(
                "analyze_speed_capture",
                {
                    "request": {
                        "request_id": "invalid",
                        "pcap_path": _request().pcap_path,
                        "payload": secret,
                    }
                },
            )
            assert isinstance(result.data, dict)
            return result.data

    envelope = asyncio.run(exercise())
    serialized = json.dumps(envelope)
    assert envelope["ok"] is False
    assert secret not in serialized
    assert len(serialized) < 4096


def test_mcp_analysis_response_recursively_filters_untrusted_summary_fields() -> None:
    class UnsafeSummaryAdapter(MockAnalyzerAdapter):
        async def analyze(self, request, progress_callback=None):
            response = await super().analyze(request, progress_callback)
            response.tcp_summary.update(
                raw_payload="RAW_SECRET",
                log_lines=["FULL_LOG_SECRET"],
                authorization="AUTH_SECRET",
                rtt_histogram=[
                    {
                        "upper_bound_ms": "PAYLOAD_IN_ALLOWED_KEY",
                        "count": "LOG_IN_ALLOWED_KEY",
                    }
                ],
            )
            response.flow_summary["f-1"] = {
                "direction": "download",
                "payload_bytes": 10,
                "nested": {"api_key": "KEY_SECRET"},
            }
            response.flow_summary["authorization=BEARER_SECRET"] = {
                "direction": "download",
                "payload_bytes": 99,
            }
            response.interval_summary.append(
                {
                    "interval_start": 0.0,
                    "direction": "download",
                    "throughput_mbps": 1.0,
                    "raw_packet": "PACKET_SECRET",
                }
            )
            response.syn_options["log_body"] = "SYN_LOG_SECRET"
            response.syn_options["mss_values"] = {
                "1460": 1,
                "raw_payload=PCAP_SECRET": 1,
            }
            response.warnings = ["raw secret warning /private/full.log"]
            response.coverage_summary.truncation_reason = "API_KEY_IN_COVERAGE"
            return response

    async def exercise() -> dict[str, object]:
        server = create_server(UnsafeSummaryAdapter(FIXTURE))
        async with FastMCPClient(server) as client:
            result = await client.call_tool(
                "analyze_speed_capture", {"request": _request().model_dump(mode="json")}
            )
            assert isinstance(result.data, dict)
            return result.data

    envelope = asyncio.run(exercise())
    serialized = json.dumps(envelope)
    assert envelope["ok"] is True
    assert envelope["data"]["tcp_summary"]["retransmissions"] == 2
    assert envelope["data"]["flow_summary"]["f-1"] == {
        "direction": "download",
        "payload_bytes": 10,
    }
    assert envelope["data"]["syn_options"]["mss_values"] == {"1460": 1}
    assert envelope["data"]["interval_summary"][-1] == {
        "interval_start": 0.0,
        "direction": "download",
        "throughput_mbps": 1.0,
    }
    assert envelope["data"]["warnings"] == ["ANALYZER_WARNING_REDACTED"]
    for secret in (
        "RAW_SECRET",
        "FULL_LOG_SECRET",
        "AUTH_SECRET",
        "KEY_SECRET",
        "PACKET_SECRET",
        "SYN_LOG_SECRET",
        "private/full.log",
        "PAYLOAD_IN_ALLOWED_KEY",
        "LOG_IN_ALLOWED_KEY",
        "API_KEY_IN_COVERAGE",
        "BEARER_SECRET",
        "PCAP_SECRET",
    ):
        assert secret not in serialized


def test_mcp_transport_compression_preserves_late_interval_and_slow_flow() -> None:
    class LargeSummaryAdapter(MockAnalyzerAdapter):
        async def analyze(self, request, progress_callback=None):
            response = await super().analyze(request, progress_callback)
            response.interval_summary = [
                {
                    "interval_start": float(index),
                    "interval_end": float(index + 1),
                    "direction": "download",
                    "throughput_mbps": 900.0 if index < 1000 else 1.0,
                    "payload_bytes": 1000,
                }
                for index in range(1001)
            ]
            response.flow_summary = {
                f"f-{index}": {
                    "direction": "download",
                    "throughput_mbps": 900.0,
                    "payload_bytes": 1_000_000 + index,
                }
                for index in range(256)
            }
            response.flow_summary["f-9999"] = {
                "direction": "download",
                "throughput_mbps": 1.0,
                "payload_bytes": 1,
            }
            return response

    async def exercise() -> dict[str, object]:
        server = create_server(LargeSummaryAdapter(FIXTURE))
        async with FastMCPClient(server) as client:
            result = await client.call_tool(
                "analyze_speed_capture", {"request": _request().model_dump(mode="json")}
            )
            assert isinstance(result.data, dict)
            return result.data

    envelope = asyncio.run(exercise())
    data = envelope["data"]

    assert envelope["ok"] is True
    assert len(data["interval_summary"]) <= 1000
    assert any(
        interval["interval_start"] == 1000.0
        for interval in data["interval_summary"]
    )
    assert len(data["flow_summary"]) <= 256
    assert "f-9999" in data["flow_summary"]
    assert data["transport_summary"]["intervals"]["total"] == 1001
    assert data["transport_summary"]["intervals"]["omitted"] == 1
    assert data["transport_summary"]["flows"]["total"] == 257
    assert data["transport_summary"]["flows"]["omitted"] == 1
    assert len(json.dumps(envelope).encode("utf-8")) <= 1_000_000

    context = ContextBuilder(max_intervals=24, max_flows=32).build(
        AnalyzeResponse.model_validate(data),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )
    assert "f-9999" in context.flow_metrics
    assert any(
        interval["interval_start"] == 1000.0
        for interval in context.anomaly_intervals
    )
    assert context.flow_compression["total"] == 257
    assert context.flow_compression["omitted"] == 225
    assert context.normal_interval_summary["transport_total"] == 1001
    assert context.normal_interval_summary["transport_omitted"] == 1


def test_mcp_evidence_response_filters_values_paths_and_oversized_fields() -> None:
    class UnsafeEvidenceAdapter(MockAnalyzerAdapter):
        async def get_evidence(self, request):
            return EvidenceResponse(
                analysis_id=request.analysis_id,
                evidence_type=request.evidence_type,
                summary={"returned": 1, "api_key": "SUMMARY_SECRET"},
                items=[
                    {
                        "evidence_id": "ev-1",
                        "event_type": "retransmission",
                        "frame.number": 42,
                        "flow_id": "f-1",
                        "direction": "download",
                        "tcp.len": 1000,
                        "tcp.payload": "PAYLOAD_SECRET",
                        "authorization": "AUTH_SECRET",
                        "nested": {"log": "LOG_SECRET"},
                    }
                ],
                total=1,
                source="/private/user/analysis.sqlite",
                coverage_range={
                    "offset": 0,
                    "complete": True,
                    "query_key": "QUERY_SECRET",
                },
                warnings=["FULL_WARNING_SECRET /private/log"],
            )

    async def exercise() -> dict[str, object]:
        server = create_server(UnsafeEvidenceAdapter(FIXTURE))
        async with FastMCPClient(server) as client:
            result = await client.call_tool(
                "get_tcp_evidence",
                {
                    "request": EvidenceRequest(
                        analysis_id="mock-contract", evidence_type="events"
                    ).model_dump(mode="json")
                },
            )
            assert isinstance(result.data, dict)
            return result.data

    envelope = asyncio.run(exercise())
    serialized = json.dumps(envelope)

    assert envelope["ok"] is True
    assert envelope["data"]["items"] == [
        {
            "evidence_id": "ev-1",
            "event_type": "retransmission",
            "frame.number": 42,
            "flow_id": "f-1",
            "direction": "download",
            "tcp.len": 1000,
        }
    ]
    assert envelope["data"]["summary"] == {"returned": 1}
    assert envelope["data"]["source"] == "sqlite"
    assert envelope["data"]["coverage_range"] == {
        "offset": 0,
        "complete": True,
    }
    assert envelope["data"]["warnings"] == ["EVIDENCE_WARNING_REDACTED"]
    for secret in (
        "SUMMARY_SECRET",
        "PAYLOAD_SECRET",
        "AUTH_SECRET",
        "LOG_SECRET",
        "private/user",
        "QUERY_SECRET",
        "FULL_WARNING_SECRET",
        "private/log",
    ):
        assert secret not in serialized
    assert len(serialized.encode("utf-8")) <= 1_000_000


def test_mcp_summary_evidence_preserves_safe_coverage_fields() -> None:
    class CoverageEvidenceAdapter(MockAnalyzerAdapter):
        async def get_evidence(self, request):
            return EvidenceResponse(
                analysis_id=request.analysis_id,
                evidence_type="summary",
                items=[
                    {
                        "name": "coverage_summary",
                        "total_packets_seen": 123,
                        "tcp_packets_seen": 120,
                        "complete": True,
                        "truncated": False,
                        "truncation_reason": "PRIVATE_REASON",
                    }
                ],
                total=1,
            )

    async def exercise() -> dict[str, object]:
        server = create_server(CoverageEvidenceAdapter(FIXTURE))
        async with FastMCPClient(server) as client:
            result = await client.call_tool(
                "get_tcp_evidence",
                {
                    "request": EvidenceRequest(
                        analysis_id="mock-contract", evidence_type="summary"
                    ).model_dump(mode="json")
                },
            )
            assert isinstance(result.data, dict)
            return result.data

    envelope = asyncio.run(exercise())

    assert envelope["data"]["items"] == [
        {
            "name": "coverage_summary",
            "total_packets_seen": 123,
            "tcp_packets_seen": 120,
            "complete": True,
            "truncated": False,
            "truncation_reason": "ANALYSIS_TRUNCATED",
        }
    ]
    assert "PRIVATE_REASON" not in json.dumps(envelope)
