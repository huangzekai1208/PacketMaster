import asyncio
import json
from pathlib import Path

from packetmaster.application import DiagnosisProgress, DiagnosisService
from packetmaster.config import Settings
from packetmaster.domain import CoverageSummary, DiagnosticReport, Target


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
