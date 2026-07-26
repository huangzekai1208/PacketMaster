"""Single-process local worker for persisted PacketMaster analyses."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from packetmaster.application import DiagnosisProgress, DiagnosisService
from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.web.contracts import TaskStatus
from packetmaster.web.database import WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository, ClaimedAnalysis


class AnalysisWorker:
    def __init__(
        self,
        repository: AnalysisTaskRepository,
        service_factory: Callable[[], Any],
        *,
        worker_id: str | None = None,
        heartbeat_interval_seconds: float = 5.0,
    ) -> None:
        self.repository = repository
        self.service_factory = service_factory
        self.worker_id = worker_id or uuid.uuid4().hex
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

    async def run_once(self) -> bool:
        task = self.repository.claim_next(self.worker_id)
        if task is None:
            return False
        heartbeat = asyncio.create_task(self._heartbeat(task.analysis_id))
        try:
            await self._run_claimed(task)
        finally:
            heartbeat.cancel()
            try:
                await heartbeat
            except asyncio.CancelledError:
                pass
        return True

    async def run_forever(
        self, stop_event: Any, *, poll_interval_seconds: float = 0.5
    ) -> None:
        self.repository.interrupt_stale(
            heartbeat_timeout=timedelta(
                seconds=max(15.0, self.heartbeat_interval_seconds * 3)
            )
        )
        while not stop_event.is_set():
            processed = await self.run_once()
            if not processed:
                await asyncio.sleep(poll_interval_seconds)

    async def _run_claimed(self, task: ClaimedAnalysis) -> None:
        try:
            self.repository.transition(
                task.analysis_id,
                TaskStatus.ANALYZING,
                stage_message="正在分析报文",
            )

            def progress(event: DiagnosisProgress) -> None:
                self.repository.update_progress(
                    task.analysis_id,
                    fraction=event.fraction,
                    stage_message=event.message or "正在分析报文",
                )

            outcome = await self.service_factory().run(
                pcap_path=str(task.pcap_path),
                standard=task.standard_bandwidth_mbps,
                actual=task.actual_bandwidth_mbps,
                target=task.target,
                request_id=task.analysis_id,
                progress_handler=progress,
            )
            report_path = (
                str(outcome.report_path) if outcome.report_path is not None else None
            )
            if outcome.error is not None:
                self.repository.transition(
                    task.analysis_id,
                    TaskStatus.PARTIAL,
                    stage_message="分析部分完成",
                    error_code=outcome.error.code,
                    error_message=outcome.error.message,
                    recoverable=outcome.error.recoverable,
                    suggested_action=outcome.error.suggested_action,
                    report_path=report_path,
                )
                return
            self.repository.transition(
                task.analysis_id,
                TaskStatus.REASONING,
                stage_message="正在整理候选原因",
            )
            self.repository.transition(
                task.analysis_id,
                TaskStatus.VERIFYING,
                stage_message="正在复核诊断证据",
            )
            self.repository.transition(
                task.analysis_id,
                TaskStatus.REPORTING,
                stage_message="正在生成诊断报告",
            )
            self.repository.transition(
                task.analysis_id,
                TaskStatus.COMPLETED,
                stage_message="分析完成",
                report_path=report_path,
            )
        except AppError as exc:
            self.repository.transition(
                task.analysis_id,
                TaskStatus.FAILED,
                stage_message="分析失败",
                error_code=exc.code,
                error_message=exc.message,
                recoverable=exc.recoverable,
                suggested_action=exc.suggested_action,
            )
        except Exception:
            self.repository.transition(
                task.analysis_id,
                TaskStatus.FAILED,
                stage_message="分析失败",
                error_code="WORKER_TASK_FAILED",
                error_message="后台分析任务异常",
                recoverable=True,
                suggested_action="请重试该分析任务。",
            )

    async def _heartbeat(self, analysis_id: str) -> None:
        while True:
            await asyncio.sleep(self.heartbeat_interval_seconds)
            if not self.repository.heartbeat(analysis_id, self.worker_id):
                return


def run_worker_process(
    database_path: str, settings: Settings, stop_event: Any
) -> None:
    """Top-level Windows-spawn-compatible worker process target."""

    database = WebDatabase(Path(database_path))
    database.initialize()
    repository = AnalysisTaskRepository(database)
    worker = AnalysisWorker(
        repository,
        lambda: DiagnosisService(settings),
    )
    asyncio.run(worker.run_forever(stop_event))
