import asyncio
import json
import signal
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packetmaster.application import DiagnosisOutcome, DiagnosisProgress
from packetmaster.domain import CoverageSummary, DiagnosticReport, Target
from packetmaster.errors import AppError
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import TaskStatus
from packetmaster.web.database import SessionRepository, WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository
from packetmaster.web.worker import AnalysisWorker, _configure_worker_signal_handling


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
                DiagnosisProgress(fraction=0.5, message="Scanning capture flows")
            )
            return DiagnosisOutcome(report=_report())

    worker = AnalysisWorker(repository, Service, worker_id="worker-1")

    assert asyncio.run(worker.run_once()) is True
    task = repository.get("analysis-1")
    assert task.status is TaskStatus.COMPLETED
    assert task.progress_fraction == 0.5
    events = repository.events("analysis-1", after_event_id=0)
    assert any(event.stage_message == "正在扫描报文流" for event in events)
    assert all("Scanning capture flows" not in event.stage_message for event in events)
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
                details={
                    "exception_type": "TimeoutError",
                    "path": "/private/tmp/secret-capture.pcap",
                },
            )

    worker = AnalysisWorker(repository, Service, worker_id="worker-1")

    assert asyncio.run(worker.run_once()) is True
    task = repository.get("analysis-1")
    assert task.status is TaskStatus.FAILED
    assert task.error_code == "MODEL_CALL_FAILED"
    private = repository.private_details("analysis-1")
    assert private is not None
    assert json.loads(str(private["error_details_json"])) == {
        "exception_type": "TimeoutError"
    }


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


def test_queued_cancellation_is_idempotent_and_worker_does_not_claim(
    tmp_path: Path,
) -> None:
    repository = _task(tmp_path)

    first = repository.request_cancel("analysis-1")
    second = repository.request_cancel("analysis-1")
    worker = AnalysisWorker(repository, lambda: object(), worker_id="worker-1")

    assert first.status is TaskStatus.CANCELLED
    assert second.status is TaskStatus.CANCELLED
    assert asyncio.run(worker.run_once()) is False


def test_worker_cancels_running_diagnosis(tmp_path: Path) -> None:
    repository = _task(tmp_path)
    started = asyncio.Event()

    class Service:
        async def run(self, **kwargs):
            started.set()
            await asyncio.Future()

    worker = AnalysisWorker(
        repository,
        Service,
        worker_id="worker-1",
        heartbeat_interval_seconds=0.01,
    )

    async def scenario() -> None:
        running = asyncio.create_task(worker.run_once())
        await started.wait()
        repository.request_cancel("analysis-1")
        await running

    asyncio.run(scenario())

    assert repository.get("analysis-1").status is TaskStatus.CANCELLED


def test_retry_creates_new_task_without_overwriting_original(tmp_path: Path) -> None:
    repository = _task(tmp_path)
    repository.request_cancel("analysis-1")

    retry = repository.retry("analysis-1", new_analysis_id="analysis-2")

    assert repository.get("analysis-1").status is TaskStatus.CANCELLED
    assert retry.analysis_id == "analysis-2"
    assert retry.status is TaskStatus.QUEUED
    claimed = repository.claim_next("worker-2")
    assert claimed is not None
    assert claimed.checkpoint_thread_id == "analysis-1"
    assert claimed.resume_from_checkpoint is True


def test_worker_ignores_terminal_interrupt_owned_by_parent(monkeypatch) -> None:
    configured = []
    monkeypatch.setattr(
        "packetmaster.web.worker.signal.signal",
        lambda interrupt, handler: configured.append((interrupt, handler)),
    )

    _configure_worker_signal_handling()

    assert configured == [(signal.SIGINT, signal.SIG_IGN)]
