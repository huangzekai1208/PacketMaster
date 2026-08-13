"""本机单进程 Worker：从持久化队列领取任务并持续发送心跳。"""

from __future__ import annotations

import asyncio
import signal
import uuid
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from packetmaster.application import DiagnosisProgress, DiagnosisService
from packetmaster.application.stall import StallDiagnosisService
from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.progress import localize_progress_message
from packetmaster.web.contracts import AnalysisMode, TaskStatus
from packetmaster.web.database import WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository, ClaimedAnalysis

_PUBLIC_ERROR_DETAIL_KEYS = {
    "attempts",
    "exception_type",
    "returncode",
    "rss_peak_bytes",
    "size_bytes",
    "structured_output_method",
    "timeout_seconds",
}


def _public_error_details(
    values: dict[str, Any],
) -> dict[str, str | int | float | bool | None]:
    """Expose bounded diagnostic metadata without paths, payloads, or secrets."""
    result: dict[str, str | int | float | bool | None] = {}
    for key in sorted(_PUBLIC_ERROR_DETAIL_KEYS & values.keys()):
        value = values[key]
        if value is None or isinstance(value, str | int | float | bool):
            result[key] = value if not isinstance(value, str) else value[:256]
    return result


class AnalysisWorker:
    def __init__(
        self,
        repository: AnalysisTaskRepository,
        service_factory: Callable[[], Any],
        *,
        stall_service_factory: Callable[[], Any] | None = None,
        worker_id: str | None = None,
        heartbeat_interval_seconds: float = 5.0,
    ) -> None:
        self.repository = repository
        self.service_factory = service_factory
        self.stall_service_factory = stall_service_factory
        self.worker_id = worker_id or uuid.uuid4().hex
        self.heartbeat_interval_seconds = heartbeat_interval_seconds

    async def run_once(self) -> bool:
        # 心跳与取消检查在诊断协程运行期间进行，避免长报文任务被错误判定失联。
        task = self.repository.claim_next(self.worker_id)
        if task is None:
            return False
        execution = asyncio.create_task(self._run_claimed(task))
        try:
            while not execution.done():
                await asyncio.wait({execution}, timeout=self.heartbeat_interval_seconds)
                if execution.done():
                    break
                self.repository.heartbeat(task.analysis_id, self.worker_id)
                if self.repository.cancel_requested(task.analysis_id):
                    execution.cancel()
                    try:
                        await execution
                    except asyncio.CancelledError:
                        current = self.repository.get(task.analysis_id)
                        if current is not None and current.status not in {
                            TaskStatus.COMPLETED,
                            TaskStatus.PARTIAL,
                            TaskStatus.FAILED,
                            TaskStatus.CANCELLED,
                            TaskStatus.INTERRUPTED,
                        }:
                            self.repository.transition(
                                task.analysis_id,
                                TaskStatus.CANCELLED,
                                stage_message="任务已取消",
                            )
                    return True
            await execution
        except asyncio.CancelledError:
            execution.cancel()
            raise
        return True

    async def run_forever(
        self, stop_event: Any, *, poll_interval_seconds: float = 0.5
    ) -> None:
        # 启动时先将旧 Worker 遗留的超时任务标记为 interrupted，避免永久卡在活动状态。
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
        # 诊断服务负责实际分析；Worker 只负责状态机、进度转发和错误归类。
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
                    stage_message=localize_progress_message(event.message),
                )

            def stage(node: str) -> None:
                mapping = {
                    "analyze": (TaskStatus.ANALYZING, "正在分析报文"),
                    "reason": (TaskStatus.REASONING, "正在整理候选原因"),
                    "retrieve_knowledge": (TaskStatus.REASONING, "正在检索知识"),
                    "augment_hypotheses": (TaskStatus.REASONING, "正在融合知识"),
                    "inspect_evidence": (TaskStatus.VERIFYING, "正在查询诊断证据"),
                    "verify": (TaskStatus.VERIFYING, "正在复核诊断证据"),
                    "report": (TaskStatus.REPORTING, "正在生成诊断报告"),
                }
                desired = mapping.get(node)
                if desired is None:
                    return
                current = self.repository.get(task.analysis_id)
                if current is None:
                    return
                status, message = desired
                if current.status is status:
                    self.repository.update_progress(
                        task.analysis_id,
                        fraction=current.progress_fraction,
                        stage_message=message,
                    )
                else:
                    self.repository.transition(
                        task.analysis_id, status, stage_message=message
                    )

            if task.mode is AnalysisMode.STALL:
                if self.stall_service_factory is None:
                    raise AppError(
                        code="STALL_ANALYZER_UNAVAILABLE",
                        message="通用卡顿分析服务未配置",
                        recoverable=True,
                        suggested_action="请检查后台 Worker 配置后重试。",
                    )
                outcome = await self.stall_service_factory().run(
                    pcap_path=str(task.pcap_path),
                    request_id=task.analysis_id,
                    symptom_context=task.analysis_context,
                    progress=lambda fraction, message: self.repository.update_progress(
                        task.analysis_id,
                        fraction=fraction,
                        stage_message=message,
                    ),
                )
                self.repository.transition(
                    task.analysis_id,
                    TaskStatus.PARTIAL if outcome.partial else TaskStatus.COMPLETED,
                    stage_message=("分析部分完成" if outcome.partial else "分析完成"),
                    report_path=str(outcome.report_path),
                )
                return
            outcome = await self.service_factory().run(
                pcap_path=str(task.pcap_path),
                standard=task.standard_bandwidth_mbps,
                actual=task.actual_bandwidth_mbps,
                target=task.target,
                request_id=task.analysis_id,
                progress_handler=progress,
                checkpoint_thread_id=task.checkpoint_thread_id,
                resume_from_checkpoint=task.resume_from_checkpoint,
                stage_handler=stage,
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
                    error_details=_public_error_details(outcome.error.details),
                    recoverable=outcome.error.recoverable,
                    suggested_action=outcome.error.suggested_action,
                    report_path=report_path,
                )
                return
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
                error_details=_public_error_details(exc.details),
                recoverable=exc.recoverable,
                suggested_action=exc.suggested_action,
            )
        except Exception as exc:
            self.repository.transition(
                task.analysis_id,
                TaskStatus.FAILED,
                stage_message="分析失败",
                error_code="WORKER_TASK_FAILED",
                error_message="后台分析任务异常",
                error_details={"exception_type": exc.__class__.__name__},
                recoverable=True,
                suggested_action="请重试该分析任务。",
            )


def _configure_worker_signal_handling() -> None:
    signal.signal(signal.SIGINT, signal.SIG_IGN)


def run_worker_process(database_path: str, settings: Settings, stop_event: Any) -> None:
    """Top-level Windows-spawn-compatible worker process target."""

    _configure_worker_signal_handling()
    database = WebDatabase(Path(database_path))
    database.initialize()
    repository = AnalysisTaskRepository(database)
    worker = AnalysisWorker(
        repository,
        lambda: DiagnosisService(settings),
        stall_service_factory=lambda: StallDiagnosisService(settings),
    )
    asyncio.run(worker.run_forever(stop_event))
