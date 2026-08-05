"""分析任务状态机与事件的 SQLite 事务持久化。"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packetmaster.domain import Target
from packetmaster.errors import AppError
from packetmaster.web.contracts import (
    AnalysisEvent,
    AnalysisSummary,
    CaptureSummary,
    EventType,
    TaskStatus,
)
from packetmaster.web.database import WebDatabase

_ACTIVE_STATUSES = {
    TaskStatus.QUEUED,
    TaskStatus.VALIDATING,
    TaskStatus.ANALYZING,
    TaskStatus.REASONING,
    TaskStatus.VERIFYING,
    TaskStatus.REPORTING,
}
_TERMINAL_STATUSES = {
    TaskStatus.COMPLETED,
    TaskStatus.PARTIAL,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
    TaskStatus.INTERRUPTED,
}
_TRANSITIONS = {
    # 所有合法迁移显式列出，阻止 Worker 或 API 跳过关键分析阶段。
    TaskStatus.DRAFT: {TaskStatus.AWAITING_CONFIRMATION},
    TaskStatus.AWAITING_CONFIRMATION: {
        TaskStatus.QUEUED,
        TaskStatus.CANCELLED,
    },
    TaskStatus.QUEUED: {TaskStatus.VALIDATING, TaskStatus.CANCELLED},
    TaskStatus.VALIDATING: {
        TaskStatus.ANALYZING,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.INTERRUPTED,
    },
    TaskStatus.ANALYZING: {
        TaskStatus.REASONING,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.INTERRUPTED,
    },
    TaskStatus.REASONING: {
        TaskStatus.VERIFYING,
        TaskStatus.REPORTING,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.INTERRUPTED,
    },
    TaskStatus.VERIFYING: {
        TaskStatus.REPORTING,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.INTERRUPTED,
    },
    TaskStatus.REPORTING: {
        TaskStatus.COMPLETED,
        TaskStatus.PARTIAL,
        TaskStatus.FAILED,
        TaskStatus.CANCELLED,
        TaskStatus.INTERRUPTED,
    },
}


@dataclass(frozen=True)
class ClaimedAnalysis:
    analysis_id: str
    session_id: str
    capture_id: str
    pcap_path: Path
    standard_bandwidth_mbps: float
    actual_bandwidth_mbps: float
    target: Target


class AnalysisTaskRepository:
    """任务、Worker 心跳和 SSE 事件的唯一写入入口。"""

    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def create_queued(
        self,
        *,
        session_id: str,
        capture_id: str,
        standard_bandwidth_mbps: float,
        actual_bandwidth_mbps: float,
        target: Target = Target.DOWNLOAD,
        analysis_id: str | None = None,
        retry_of_analysis_id: str | None = None,
        now: datetime | None = None,
    ) -> AnalysisSummary:
        # immediate 事务先锁定写入，确保一个会话在任意时刻至多有一个活动任务。
        identifier = analysis_id or uuid.uuid4().hex
        current = (now or datetime.now(UTC)).astimezone(UTC)
        timestamp = current.isoformat()
        with self.database.transaction(immediate=True) as connection:
            active = connection.execute(
                f"""
                SELECT analysis_id FROM analyses
                WHERE session_id = ? AND status IN ({_placeholders(_ACTIVE_STATUSES)})
                LIMIT 1
                """,
                (session_id, *(status.value for status in _ACTIVE_STATUSES)),
            ).fetchone()
            if active is not None:
                raise AppError(
                    code="ANALYSIS_ALREADY_ACTIVE",
                    message="当前会话已有正在运行的分析任务",
                    recoverable=True,
                    suggested_action="请等待当前任务结束，或先取消当前任务。",
                )
            try:
                connection.execute(
                    """
                    INSERT INTO analyses (
                        analysis_id, session_id, capture_id, status,
                        standard_bandwidth_mbps, actual_bandwidth_mbps,
                        target, created_at, updated_at, retry_of_analysis_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        session_id,
                        capture_id,
                        TaskStatus.QUEUED.value,
                        standard_bandwidth_mbps,
                        actual_bandwidth_mbps,
                        target.value,
                        timestamp,
                        timestamp,
                        retry_of_analysis_id,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AppError(
                    code="INVALID_ANALYSIS_REFERENCE",
                    message="会话或报文引用不存在",
                    recoverable=True,
                    suggested_action="请重新选择会话和报文后再试。",
                ) from exc
            connection.execute(
                """
                UPDATE sessions
                SET status = ?, current_analysis_id = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (
                    TaskStatus.QUEUED.value,
                    identifier,
                    timestamp,
                    session_id,
                ),
            )
            _insert_event(
                connection,
                analysis_id=identifier,
                event_type=EventType.ANALYSIS_STATUS,
                status=TaskStatus.QUEUED,
                now=current,
                stage_message="任务已进入分析队列",
            )
        task = self.get(identifier)
        if task is None:
            raise RuntimeError("created analysis task is unavailable")
        return task

    def get(self, analysis_id: str) -> AnalysisSummary | None:
        with self.database.connect() as connection:
            row = connection.execute(
                _ANALYSIS_SELECT + " WHERE a.analysis_id = ?", (analysis_id,)
            ).fetchone()
        return _analysis(row) if row is not None else None

    def private_details(self, analysis_id: str) -> dict[str, object] | None:
        """Return backend-only task metadata for trusted application services."""

        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT report_path, recoverable, suggested_action, error_message,
                       error_details_json
                FROM analyses WHERE analysis_id = ?
                """,
                (analysis_id,),
            ).fetchone()
        return dict(row) if row is not None else None

    def count_for_session(self, session_id: str) -> int:
        with self.database.connect() as connection:
            return int(
                connection.execute(
                    "SELECT COUNT(*) FROM analyses WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
            )

    def transition(
        self,
        analysis_id: str,
        status: TaskStatus,
        *,
        stage_message: str = "",
        error_code: str | None = None,
        error_message: str | None = None,
        error_details: dict[str, str | int | float | bool | None] | None = None,
        recoverable: bool = False,
        suggested_action: str = "",
        report_path: str | None = None,
        now: datetime | None = None,
    ) -> AnalysisSummary:
        # 更新任务、会话状态和 SSE 事件必须处于同一事务，页面才能观察一致状态。
        current_time = (now or datetime.now(UTC)).astimezone(UTC)
        timestamp = current_time.isoformat()
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                raise _task_not_found()
            current_status = TaskStatus(row["status"])
            if current_status is status:
                return self._analysis_in_connection(connection, analysis_id)
            if status not in _TRANSITIONS.get(current_status, set()):
                raise AppError(
                    code="INVALID_TASK_TRANSITION",
                    message="分析任务状态迁移无效",
                    recoverable=False,
                    suggested_action="刷新任务状态后重试。",
                    details={
                        "current_status": current_status.value,
                        "requested_status": status.value,
                    },
                )
            started_at = (
                timestamp if status is TaskStatus.VALIDATING else row["started_at"]
            )
            finished_at = timestamp if status in _TERMINAL_STATUSES else None
            connection.execute(
                """
                UPDATE analyses
                SET status = ?, stage_message = ?, updated_at = ?,
                    started_at = ?, finished_at = ?, error_code = ?,
                    error_message = ?, recoverable = ?, suggested_action = ?,
                    error_details_json = ?,
                    report_path = COALESCE(?, report_path)
                WHERE analysis_id = ?
                """,
                (
                    status.value,
                    stage_message,
                    timestamp,
                    started_at,
                    finished_at,
                    error_code,
                    error_message,
                    int(recoverable),
                    suggested_action,
                    json.dumps(error_details or {}, ensure_ascii=False),
                    report_path,
                    analysis_id,
                ),
            )
            connection.execute(
                """
                UPDATE sessions SET status = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (status.value, timestamp, row["session_id"]),
            )
            _insert_event(
                connection,
                analysis_id=analysis_id,
                event_type=_event_type(status),
                status=status,
                now=current_time,
                stage_message=stage_message,
                error_code=error_code,
            )
            return self._analysis_in_connection(connection, analysis_id)

    def claim_next(
        self, worker_id: str, *, now: datetime | None = None
    ) -> ClaimedAnalysis | None:
        # 单 Worker 从队列原子领取任务，并立即切换为 validating 防止重复消费。
        current = (now or datetime.now(UTC)).astimezone(UTC)
        timestamp = current.isoformat()
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                """
                SELECT a.*, c.local_path
                FROM analyses AS a
                JOIN captures AS c ON c.capture_id = a.capture_id
                WHERE a.status = ? AND a.cancel_requested = 0
                ORDER BY a.created_at, a.analysis_id
                LIMIT 1
                """,
                (TaskStatus.QUEUED.value,),
            ).fetchone()
            if row is None:
                return None
            connection.execute(
                """
                UPDATE analyses
                SET status = ?, stage_message = ?, updated_at = ?,
                    started_at = ?, worker_heartbeat_at = ?, worker_id = ?
                WHERE analysis_id = ? AND status = ?
                """,
                (
                    TaskStatus.VALIDATING.value,
                    "正在校验分析任务",
                    timestamp,
                    timestamp,
                    timestamp,
                    worker_id,
                    row["analysis_id"],
                    TaskStatus.QUEUED.value,
                ),
            )
            connection.execute(
                """
                UPDATE sessions SET status = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (TaskStatus.VALIDATING.value, timestamp, row["session_id"]),
            )
            _insert_event(
                connection,
                analysis_id=row["analysis_id"],
                event_type=EventType.ANALYSIS_STATUS,
                status=TaskStatus.VALIDATING,
                now=current,
                stage_message="正在校验分析任务",
            )
            return ClaimedAnalysis(
                analysis_id=row["analysis_id"],
                session_id=row["session_id"],
                capture_id=row["capture_id"],
                pcap_path=Path(row["local_path"]),
                standard_bandwidth_mbps=row["standard_bandwidth_mbps"],
                actual_bandwidth_mbps=row["actual_bandwidth_mbps"],
                target=Target(row["target"]),
            )

    def heartbeat(
        self, analysis_id: str, worker_id: str, *, now: datetime | None = None
    ) -> bool:
        timestamp = (now or datetime.now(UTC)).astimezone(UTC).isoformat()
        with self.database.transaction(immediate=True) as connection:
            cursor = connection.execute(
                f"""
                UPDATE analyses SET worker_heartbeat_at = ?, updated_at = ?
                WHERE analysis_id = ? AND worker_id = ?
                    AND status IN ({_placeholders(_ACTIVE_STATUSES)})
                """,
                (
                    timestamp,
                    timestamp,
                    analysis_id,
                    worker_id,
                    *(status.value for status in _ACTIVE_STATUSES),
                ),
            )
        return cursor.rowcount > 0

    def request_cancel(
        self, analysis_id: str, *, now: datetime | None = None
    ) -> AnalysisSummary:
        # 已排队任务可直接取消；运行中任务设置协作式取消标志，由 Worker 终止执行。
        current = (now or datetime.now(UTC)).astimezone(UTC)
        timestamp = current.isoformat()
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                raise _task_not_found()
            status = TaskStatus(row["status"])
            if status in _TERMINAL_STATUSES:
                return self._analysis_in_connection(connection, analysis_id)
            if status is TaskStatus.QUEUED:
                connection.execute(
                    """
                    UPDATE analyses
                    SET status = ?, stage_message = ?, updated_at = ?,
                        finished_at = ?, cancel_requested = 1
                    WHERE analysis_id = ?
                    """,
                    (
                        TaskStatus.CANCELLED.value,
                        "任务已取消",
                        timestamp,
                        timestamp,
                        analysis_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE sessions SET status = ?, updated_at = ?
                    WHERE session_id = ?
                    """,
                    (
                        TaskStatus.CANCELLED.value,
                        timestamp,
                        row["session_id"],
                    ),
                )
                _insert_event(
                    connection,
                    analysis_id=analysis_id,
                    event_type=EventType.ANALYSIS_CANCELLED,
                    status=TaskStatus.CANCELLED,
                    now=current,
                    stage_message="任务已取消",
                )
            elif not row["cancel_requested"]:
                connection.execute(
                    """
                    UPDATE analyses
                    SET cancel_requested = 1, stage_message = ?, updated_at = ?
                    WHERE analysis_id = ?
                    """,
                    ("正在取消分析", timestamp, analysis_id),
                )
                _insert_event(
                    connection,
                    analysis_id=analysis_id,
                    event_type=EventType.ANALYSIS_STATUS,
                    status=status,
                    now=current,
                    stage_message="正在取消分析",
                )
            return self._analysis_in_connection(connection, analysis_id)

    def cancel_requested(self, analysis_id: str) -> bool:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT cancel_requested FROM analyses WHERE analysis_id = ?",
                (analysis_id,),
            ).fetchone()
        if row is None:
            raise _task_not_found()
        return bool(row["cancel_requested"])

    def retry(
        self,
        analysis_id: str,
        *,
        new_analysis_id: str | None = None,
        now: datetime | None = None,
    ) -> AnalysisSummary:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
        if row is None:
            raise _task_not_found()
        status = TaskStatus(row["status"])
        if status not in {
            TaskStatus.PARTIAL,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.INTERRUPTED,
        }:
            raise AppError(
                code="ANALYSIS_NOT_RETRYABLE",
                message="当前分析任务不能重试",
                recoverable=False,
                suggested_action="仅可重试部分完成、失败、取消或中断的任务。",
            )
        return self.create_queued(
            session_id=row["session_id"],
            capture_id=row["capture_id"],
            standard_bandwidth_mbps=row["standard_bandwidth_mbps"],
            actual_bandwidth_mbps=row["actual_bandwidth_mbps"],
            target=Target(row["target"]),
            analysis_id=new_analysis_id,
            retry_of_analysis_id=analysis_id,
            now=now,
        )

    def interrupt_stale(
        self,
        *,
        heartbeat_timeout: timedelta,
        now: datetime | None = None,
    ) -> list[str]:
        if heartbeat_timeout.total_seconds() <= 0:
            raise ValueError("heartbeat timeout must be positive")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        cutoff = (current - heartbeat_timeout).isoformat()
        interrupted: list[str] = []
        with self.database.transaction(immediate=True) as connection:
            rows = connection.execute(
                f"""
                SELECT analysis_id, session_id FROM analyses
                WHERE status IN ({_placeholders(_ACTIVE_STATUSES)})
                    AND worker_id IS NOT NULL
                    AND worker_heartbeat_at < ?
                ORDER BY analysis_id
                """,
                (*(status.value for status in _ACTIVE_STATUSES), cutoff),
            ).fetchall()
            for row in rows:
                analysis_id = row["analysis_id"]
                connection.execute(
                    """
                    UPDATE analyses
                    SET status = ?, stage_message = ?, updated_at = ?,
                        finished_at = ?, error_code = ?, error_message = ?,
                        recoverable = 1, suggested_action = ?
                    WHERE analysis_id = ?
                    """,
                    (
                        TaskStatus.INTERRUPTED.value,
                        "后台分析进程已中断",
                        current.isoformat(),
                        current.isoformat(),
                        "WORKER_INTERRUPTED",
                        "后台分析进程失去心跳",
                        "请重试该分析任务。",
                        analysis_id,
                    ),
                )
                connection.execute(
                    """
                    UPDATE sessions SET status = ?, updated_at = ?
                    WHERE session_id = ?
                    """,
                    (
                        TaskStatus.INTERRUPTED.value,
                        current.isoformat(),
                        row["session_id"],
                    ),
                )
                _insert_event(
                    connection,
                    analysis_id=analysis_id,
                    event_type=EventType.ANALYSIS_STATUS,
                    status=TaskStatus.INTERRUPTED,
                    now=current,
                    stage_message="后台分析进程已中断",
                    error_code="WORKER_INTERRUPTED",
                )
                interrupted.append(analysis_id)
        return interrupted

    def update_progress(
        self,
        analysis_id: str,
        *,
        fraction: float | None,
        stage_message: str,
        processed_packets: int | None = None,
        elapsed_seconds: float | None = None,
        now: datetime | None = None,
    ) -> AnalysisEvent:
        if fraction is not None and not 0 <= fraction <= 1:
            raise ValueError("progress fraction must be between zero and one")
        current = (now or datetime.now(UTC)).astimezone(UTC)
        with self.database.transaction(immediate=True) as connection:
            row = connection.execute(
                "SELECT status FROM analyses WHERE analysis_id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                raise _task_not_found()
            status = TaskStatus(row["status"])
            if status not in _ACTIVE_STATUSES:
                raise AppError(
                    code="TASK_NOT_ACTIVE",
                    message="分析任务当前不接受进度更新",
                    recoverable=False,
                    suggested_action="刷新任务状态。",
                )
            connection.execute(
                """
                UPDATE analyses
                SET progress_fraction = ?, stage_message = ?,
                    processed_packets = ?, updated_at = ?
                WHERE analysis_id = ?
                """,
                (
                    fraction,
                    stage_message,
                    processed_packets,
                    current.isoformat(),
                    analysis_id,
                ),
            )
            event_id = _insert_event(
                connection,
                analysis_id=analysis_id,
                event_type=EventType.ANALYSIS_PROGRESS,
                status=status,
                now=current,
                progress_fraction=fraction,
                stage_message=stage_message,
                processed_packets=processed_packets,
                elapsed_seconds=elapsed_seconds,
            )
            return self._event_in_connection(connection, event_id)

    def events(
        self, analysis_id: str, *, after_event_id: int = 0, limit: int = 100
    ) -> list[AnalysisEvent]:
        if after_event_id < 0 or not 1 <= limit <= 500:
            raise ValueError("invalid event page")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM analysis_events
                WHERE analysis_id = ? AND event_id > ?
                ORDER BY event_id
                LIMIT ?
                """,
                (analysis_id, after_event_id, limit),
            ).fetchall()
        return [_event(row) for row in rows]

    def _analysis_in_connection(
        self, connection: sqlite3.Connection, analysis_id: str
    ) -> AnalysisSummary:
        row = connection.execute(
            _ANALYSIS_SELECT + " WHERE a.analysis_id = ?", (analysis_id,)
        ).fetchone()
        if row is None:
            raise _task_not_found()
        return _analysis(row)

    def _event_in_connection(
        self, connection: sqlite3.Connection, event_id: int
    ) -> AnalysisEvent:
        row = connection.execute(
            "SELECT * FROM analysis_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        if row is None:
            raise RuntimeError("created analysis event is unavailable")
        return _event(row)


_ANALYSIS_SELECT = """
    SELECT a.*, c.file_name, c.size_bytes
    FROM analyses AS a
    JOIN captures AS c ON c.capture_id = a.capture_id
"""


def _placeholders(values: set[TaskStatus]) -> str:
    return ",".join("?" for _ in values)


def _insert_event(
    connection: sqlite3.Connection,
    *,
    analysis_id: str,
    event_type: EventType,
    status: TaskStatus,
    now: datetime,
    progress_fraction: float | None = None,
    stage_message: str = "",
    processed_packets: int | None = None,
    elapsed_seconds: float | None = None,
    error_code: str | None = None,
) -> int:
    cursor = connection.execute(
        """
        INSERT INTO analysis_events (
            analysis_id, event_type, status, created_at, progress_fraction,
            stage_message, processed_packets, elapsed_seconds, error_code
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            analysis_id,
            event_type.value,
            status.value,
            now.isoformat(),
            progress_fraction,
            stage_message,
            processed_packets,
            elapsed_seconds,
            error_code,
        ),
    )
    return int(cursor.lastrowid)


def _analysis(row: sqlite3.Row) -> AnalysisSummary:
    created_at = datetime.fromisoformat(row["created_at"])
    updated_at = datetime.fromisoformat(row["updated_at"])
    return AnalysisSummary(
        analysis_id=row["analysis_id"],
        session_id=row["session_id"],
        status=TaskStatus(row["status"]),
        stage_message=row["stage_message"],
        progress_fraction=row["progress_fraction"],
        capture=CaptureSummary(
            capture_id=row["capture_id"],
            file_name=row["file_name"],
            size_bytes=row["size_bytes"],
        ),
        standard_bandwidth_mbps=row["standard_bandwidth_mbps"],
        actual_bandwidth_mbps=row["actual_bandwidth_mbps"],
        target=Target(row["target"]),
        created_at=created_at,
        updated_at=updated_at,
        elapsed_seconds=max(0.0, (updated_at - created_at).total_seconds()),
        processed_packets=row["processed_packets"],
        error_code=row["error_code"],
    )


def _event(row: sqlite3.Row) -> AnalysisEvent:
    return AnalysisEvent(
        event_id=row["event_id"],
        analysis_id=row["analysis_id"],
        event_type=EventType(row["event_type"]),
        status=TaskStatus(row["status"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        progress_fraction=row["progress_fraction"],
        stage_message=row["stage_message"],
        processed_packets=row["processed_packets"],
        elapsed_seconds=row["elapsed_seconds"],
        error_code=row["error_code"],
    )


def _event_type(status: TaskStatus) -> EventType:
    return {
        TaskStatus.COMPLETED: EventType.ANALYSIS_COMPLETED,
        TaskStatus.PARTIAL: EventType.ANALYSIS_PARTIAL,
        TaskStatus.FAILED: EventType.ANALYSIS_FAILED,
        TaskStatus.CANCELLED: EventType.ANALYSIS_CANCELLED,
    }.get(status, EventType.ANALYSIS_STATUS)


def _task_not_found() -> AppError:
    return AppError(
        code="ANALYSIS_NOT_FOUND",
        message="分析任务不存在",
        recoverable=False,
        suggested_action="刷新任务列表。",
    )
