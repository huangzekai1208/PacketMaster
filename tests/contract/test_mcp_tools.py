from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from packetmaster.analyzer.mock import MockAnalyzerAdapter
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server

FIXTURE = Path(__file__).parents[1] / "fixtures" / "mock_analysis.json"


def _request(**overrides: object) -> AnalyzeRequest:
    values: dict[str, object] = {
        "request_id": "contract-1",
        "pcap_path": "/tmp/captures/test capture.pcapng",
    }
    values.update(overrides)
    return AnalyzeRequest.model_validate(values)


def test_mock_adapter_returns_deterministic_structured_result() -> None:
    adapter = MockAnalyzerAdapter(FIXTURE)

    response = asyncio.run(adapter.analyze(_request()))

    assert isinstance(response, AnalyzeResponse)
    assert response.target is Target.DOWNLOAD
    assert response.analysis_id == "mock-contract"
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
    assert response.coverage_range["complete"] is True


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
        "flows": {"f-1": {"direction": target}},
        "intervals": [],
        "syn_options": {},
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "coverage.json").write_text(json.dumps(coverage), encoding="utf-8")
    (output / "tcp_analysis.json").write_text(json.dumps(summary), encoding="utf-8")
    manifest = {
        "analysis_id": "real-contract",
        "status": status,
        "target": target,
        "coverage_summary": coverage,
        "available_evidence": ["summary", "flows"],
        "warnings": [],
        "artifact_paths": {
            "manifest": str((output / "manifest.json").resolve()),
            "coverage": str((output / "coverage.json").resolve()),
            "tcp_analysis": str((output / "tcp_analysis.json").resolve()),
        },
        "error": None,
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
    client = SpeedMCPClient.from_stdio(
        "python",
        ["-m", "packetmaster.mcp.server"],
        cwd=str(tmp_path),
        log_file=str(tmp_path / "mcp.log"),
    )
    transport = client._client.transport
    assert transport.command == "python"
    assert transport.args == ["-m", "packetmaster.mcp.server"]


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
        manifest["artifact_paths"]["tcp_analysis"] = str(outside)
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
