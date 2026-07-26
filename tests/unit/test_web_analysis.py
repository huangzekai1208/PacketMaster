from __future__ import annotations

import asyncio
import json
from pathlib import Path

from packetmaster.config import Settings
from packetmaster.domain import (
    ChatAnswer,
    CoverageSummary,
    DiagnosticReport,
    EvidenceRequest,
    EvidenceResponse,
    EvidenceType,
    Target,
)
from packetmaster.web.analysis import AnalysisReadService
from packetmaster.web.api import _event_stream
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.chat_service import AnalysisChatService
from packetmaster.web.contracts import TaskStatus
from packetmaster.web.database import (
    ChatTurnRepository,
    SessionRepository,
    WebDatabase,
)
from packetmaster.web.tasks import AnalysisTaskRepository


class _Adapter:
    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        return EvidenceResponse(
            analysis_id=request.analysis_id,
            evidence_type=request.evidence_type.value,
            items=[
                {
                    "evidence_id": "ev-1",
                    "event_type": "retransmission",
                    "frame.number": 10,
                    "payload": "must-not-leak",
                    "absolute_path": "/private/capture.pcapng",
                }
            ],
            total=1,
            source="/private/analysis.sqlite",
        )


class _ChatModel:
    async def answer_question(self, context):
        return ChatAnswer(answer="主要证据是发生了重传。", ready=True)


def _completed(tmp_path: Path):
    artifact_root = tmp_path / "artifacts"
    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    sessions = SessionRepository(database)
    sessions.create(session_id="session-1")
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    ).register(str(capture_path))
    tasks = AnalysisTaskRepository(database)
    task = tasks.create_queued(
        session_id="session-1",
        capture_id=capture.capture_id,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=20,
        analysis_id="analysis-1",
    )
    root = artifact_root / task.analysis_id
    root.mkdir(parents=True)
    report = DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=20,
        achievement_ratio_pct=2,
        target=Target.DOWNLOAD,
        primary_cause="tcp_retransmission",
        confidence=80,
        coverage_summary=CoverageSummary(complete=True),
    )
    report_path = root / "report.json"
    report_path.write_text(report.model_dump_json(), encoding="utf-8")
    (root / "tcp_analysis.json").write_text(
        json.dumps(
            {
                "coverage_summary": {"complete": True, "truncated": False},
                "tcp_summary": {
                    "packet_count": 100,
                    "retransmission_count": 4,
                    "rtt_histogram": [{"upper_bound_ms": 10, "count": 5}],
                },
                "interval_summary": [
                    {
                        "interval_start": 0,
                        "interval_end": 1,
                        "throughput_mbps": 20,
                        "direction": "download",
                    }
                ],
                "flow_summary": {
                    "tcp|192.0.2.1:1|198.51.100.1:2": {
                        "direction": "download",
                        "packet_count": 100,
                        "payload_bytes": 1000,
                        "throughput_mbps": 20,
                        "retransmission_count": 4,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    for status in (
        TaskStatus.VALIDATING,
        TaskStatus.ANALYZING,
        TaskStatus.REASONING,
        TaskStatus.REPORTING,
    ):
        tasks.transition(task.analysis_id, status)
    tasks.transition(
        task.analysis_id, TaskStatus.COMPLETED, report_path=str(report_path)
    )
    settings = Settings(
        artifact_root=artifact_root,
        web_database_path=database.path,
        web_allowed_capture_roots=[tmp_path],
    )
    return database, tasks, settings


def test_report_metrics_flows_and_evidence_are_bounded(tmp_path: Path) -> None:
    _, tasks, settings = _completed(tmp_path)
    service = AnalysisReadService(settings, tasks, adapter=_Adapter())

    assert service.report("analysis-1").report.primary_cause == "tcp_retransmission"
    assert service.metrics("analysis-1").intervals[0]["throughput_mbps"] == 20
    assert service.flows("analysis-1").total == 1
    evidence = asyncio.run(
        service.evidence(
            EvidenceRequest(
                analysis_id="analysis-1",
                evidence_type=EvidenceType.RETRANSMISSION,
                limit=50,
            )
        )
    )
    serialized = evidence.model_dump_json()
    assert evidence.source == "sqlite"
    assert "payload" not in serialized
    assert "/private" not in serialized


def test_completed_analysis_chat_is_persistent(tmp_path: Path) -> None:
    database, tasks, settings = _completed(tmp_path)
    reads = AnalysisReadService(settings, tasks, adapter=_Adapter())
    chat = AnalysisChatService(
        reads=reads, turns=ChatTurnRepository(database), model=_ChatModel()
    )

    answer = asyncio.run(chat.ask("analysis-1", "为什么速度不达标？"))
    restored = chat.history("analysis-1")

    assert answer.answer == "主要证据是发生了重传。"
    assert restored.total == 1
    assert restored.items[0].turn_id == answer.turn_id


def test_sse_stream_is_ordered_and_resumes_after_last_event(tmp_path: Path) -> None:
    _, tasks, _ = _completed(tmp_path)

    class Request:
        async def is_disconnected(self):
            return False

    async def collect(after: int):
        return [
            item
            async for item in _event_stream(Request(), tasks, "analysis-1", after)
        ]

    all_events = asyncio.run(collect(0))
    resumed = asyncio.run(collect(3))

    assert all_events[0].startswith("id: 1\n")
    assert resumed[0].startswith("id: 4\n")
    assert "report.json" not in "".join(all_events)
    assert "/private" not in "".join(all_events)
