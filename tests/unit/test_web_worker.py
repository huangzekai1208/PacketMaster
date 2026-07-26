import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packetmaster.application import DiagnosisOutcome, DiagnosisProgress
from packetmaster.domain import CoverageSummary, DiagnosticReport, Target
from packetmaster.errors import AppError
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import TaskStatus
from packetmaster.web.database import SessionRepository, WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository
from packetmaster.web.worker import AnalysisWorker


def _report() -> DiagnosticReport:
    return DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        achievement_ratio_pct=60,
        target=Target.DOWNLOAD,
        primary_cause="测试原因",
        confidence=80,
        coverage_summary=CoverageSummary(complete=True),
    )


def _task(tmp_path: Path):
    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    SessionRepository(database).create(session_id="session-1")
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    ).register(str(capture_path))
    repository = AnalysisTaskRepository(database)
    repository.create_queued(
        session_id="session-1",
        capture_id=capture.capture_id,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        analysis_id="analysis-1",
    )
    return repository


def test_worker_claims_task_reports_progress_and_completes(tmp_path: Path) -> None:
    repository = _task(tmp_path)

    class Service:
        async def run(self, **kwargs):
            kwargs["progress_handler"](
                DiagnosisProgress(fraction=0.5, message="扫描中")
            )
            return DiagnosisOutcome(report=_report())

    worker = AnalysisWorker(repository, Service, worker_id="worker-1")

    assert asyncio.run(worker.run_once()) is True
    task = repository.get("analysis-1")
    assert task.status is TaskStatus.COMPLETED
    assert task.progress_fraction == 0.5
    assert asyncio.run(worker.run_once()) is False


def test_worker_persists_recoverable_failure(tmp_path: Path) -> None:
    repository = _task(tmp_path)

    class Service:
        async def run(self, **kwargs):
            raise AppError(
                code="MODEL_CALL_FAILED",
                message="模型调用失败",
                recoverable=True,
                suggested_action="重试任务。",
            )

    worker = AnalysisWorker(repository, Service, worker_id="worker-1")

    assert asyncio.run(worker.run_once()) is True
    task = repository.get("analysis-1")
    assert task.status is TaskStatus.FAILED
    assert task.error_code == "MODEL_CALL_FAILED"


def test_only_one_worker_can_claim_a_queued_task(tmp_path: Path) -> None:
    repository = _task(tmp_path)

    first = repository.claim_next("worker-1")
    second = repository.claim_next("worker-2")

    assert first is not None
    assert first.analysis_id == "analysis-1"
    assert second is None


def test_stale_claimed_task_is_marked_interrupted(tmp_path: Path) -> None:
    repository = _task(tmp_path)
    claimed_at = datetime(2026, 7, 26, tzinfo=UTC)
    repository.claim_next("worker-1", now=claimed_at)

    interrupted = repository.interrupt_stale(
        heartbeat_timeout=timedelta(seconds=30),
        now=claimed_at + timedelta(seconds=31),
    )

    assert interrupted == ["analysis-1"]
    assert repository.get("analysis-1").status is TaskStatus.INTERRUPTED
