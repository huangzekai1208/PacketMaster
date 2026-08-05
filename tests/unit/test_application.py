import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

from packetmaster.application import DiagnosisProgress, DiagnosisService
from packetmaster.config import Settings
from packetmaster.domain import CoverageSummary, DiagnosticReport, Target
from packetmaster.llm_observability import (
    LLMCallRecord,
    LLMObservationCollector,
)


def _report() -> DiagnosticReport:
    return DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        achievement_ratio_pct=60,
        target=Target.DOWNLOAD,
        primary_cause="测试原因",
        confidence=80,
        coverage_summary=CoverageSummary(
            total_packets_seen=10,
            tcp_packets_seen=10,
            speed_packets_analyzed=10,
            complete=True,
        ),
    )


class _Client:
    def __init__(self, server, progress_callback) -> None:
        self.progress_callback = progress_callback

    async def __aenter__(self):
        result = self.progress_callback(0.5, "Scanning capture flows")
        if result is not None:
            await result
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        pass


class _Graph:
    async def ainvoke(self, state):
        return {
            "report": _report(),
            "trace": [{"node": "report", "status": "ok"}],
        }


class _ObservedGraph(_Graph):
    def __init__(self, observer: LLMObservationCollector) -> None:
        self.observer = observer

    async def ainvoke(self, state):
        self.observer.record(
            LLMCallRecord(
                call_id="a" * 32,
                operation="hypothesis",
                model_name="test-model",
                prompt_name="hypothesis.md",
                prompt_sha256="b" * 64,
                output_schema="HypothesisBatch",
                structured_output_method="json_schema",
                started_at=datetime.now(UTC),
                latency_seconds=0.2,
                attempt_count=1,
                retry_count=0,
                input_bytes=100,
                message_count=2,
                status="succeeded",
                usage={
                    "input_tokens": 50,
                    "output_tokens": 10,
                    "total_tokens": 60,
                },
                estimated_cost_usd=0.001,
            )
        )
        return await super().ainvoke(state)


def test_diagnosis_service_reports_progress_and_persists_outputs(
    tmp_path: Path,
) -> None:
    progress: list[DiagnosisProgress] = []
    settings = Settings(artifact_root=tmp_path / "artifacts")
    service = DiagnosisService(
        settings,
        adapter=object(),
        diagnosis_model=object(),
        context_builder=object(),
        server_factory=lambda adapter: object(),
        client_factory=_Client,
        graph_factory=lambda **kwargs: _Graph(),
    )

    outcome = asyncio.run(
        service.run(
            pcap_path=str((tmp_path / "capture.pcapng").resolve()),
            standard=1000,
            actual=600,
            target=Target.DOWNLOAD,
            request_id="application-service",
            progress_handler=progress.append,
        )
    )

    root = settings.artifact_root / "application-service"
    assert outcome.report.primary_cause == "测试原因"
    assert progress == [DiagnosisProgress(0.5, "Scanning capture flows")]
    assert json.loads((root / "report.json").read_text(encoding="utf-8"))[
        "primary_cause"
    ] == "测试原因"
    assert json.loads((root / "trace.jsonl").read_text(encoding="utf-8")) == {
        "node": "report",
        "status": "ok",
    }


def test_diagnosis_service_persists_scoped_llm_observability(
    tmp_path: Path,
) -> None:
    settings = Settings(artifact_root=tmp_path / "artifacts")
    observer = LLMObservationCollector()
    service = DiagnosisService(
        settings,
        adapter=object(),
        diagnosis_model=object(),
        context_builder=object(),
        server_factory=lambda adapter: object(),
        client_factory=_Client,
        graph_factory=lambda **kwargs: _ObservedGraph(observer),
        llm_observer=observer,
    )

    outcome = asyncio.run(
        service.run(
            pcap_path=str((tmp_path / "capture.pcapng").resolve()),
            standard=1000,
            actual=600,
            target=Target.DOWNLOAD,
            request_id="observed-analysis",
        )
    )

    assert outcome.llm_call_count == 1
    assert outcome.llm_calls_path is not None
    record = json.loads(outcome.llm_calls_path.read_text(encoding="utf-8"))
    assert record["trace_id"] == "observed-analysis"
    assert record["operation"] == "hypothesis"
    assert outcome.llm_summary is not None
    assert outcome.llm_summary.total_tokens == 60
    assert outcome.llm_summary.estimated_cost_usd == 0.001
