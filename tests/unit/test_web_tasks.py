from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packetmaster.domain import Target
from packetmaster.errors import AppError
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import EventType, TaskStatus
from packetmaster.web.database import SessionRepository, WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository


def _repositories(tmp_path: Path):
    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    sessions = SessionRepository(database)
    captures = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    )
    tasks = AnalysisTaskRepository(database)
    return sessions, captures, tasks


def _queued_task(tmp_path: Path):
    sessions, captures, tasks = _repositories(tmp_path)
    sessions.create(session_id="session-1")
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = captures.register(str(capture_path))
    task = tasks.create_queued(
        session_id="session-1",
        capture_id=capture.capture_id,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
        target=Target.DOWNLOAD,
        analysis_id="analysis-1",
        now=datetime(2026, 7, 26, tzinfo=UTC),
    )
    return sessions, captures, tasks, task


def test_analysis_state_and_event_change_in_one_transaction(tmp_path: Path) -> None:
    _, _, tasks, task = _queued_task(tmp_path)
    started = tasks.transition(
        task.analysis_id,
        TaskStatus.VALIDATING,
        stage_message="正在校验输入",
        now=datetime(2026, 7, 26, tzinfo=UTC) + timedelta(seconds=1),
    )
    analyzing = tasks.transition(
        task.analysis_id,
        TaskStatus.ANALYZING,
        stage_message="正在分析报文",
        now=datetime(2026, 7, 26, tzinfo=UTC) + timedelta(seconds=2),
    )
    progress = tasks.update_progress(
        task.analysis_id,
        fraction=0.5,
        stage_message="已扫描 1000 个报文",
        processed_packets=1000,
        elapsed_seconds=2,
    )

    events = tasks.events(task.analysis_id)
    assert started.status is TaskStatus.VALIDATING
    assert analyzing.status is TaskStatus.ANALYZING
    assert tasks.get(task.analysis_id).processed_packets == 1000
    assert [event.event_type for event in events] == [
        EventType.ANALYSIS_STATUS,
        EventType.ANALYSIS_STATUS,
        EventType.ANALYSIS_STATUS,
        EventType.ANALYSIS_PROGRESS,
    ]
    assert progress.event_id == events[-1].event_id


def test_repeated_transition_is_idempotent_and_invalid_transition_is_rejected(
    tmp_path: Path,
) -> None:
    _, _, tasks, task = _queued_task(tmp_path)
    tasks.transition(task.analysis_id, TaskStatus.VALIDATING)
    event_count = len(tasks.events(task.analysis_id))

    repeated = tasks.transition(task.analysis_id, TaskStatus.VALIDATING)

    assert repeated.status is TaskStatus.VALIDATING
    assert len(tasks.events(task.analysis_id)) == event_count
    with pytest.raises(AppError) as raised:
        tasks.transition(task.analysis_id, TaskStatus.COMPLETED)
    assert raised.value.code == "INVALID_TASK_TRANSITION"
    assert tasks.get(task.analysis_id).status is TaskStatus.VALIDATING


def test_session_cannot_create_two_active_analyses(tmp_path: Path) -> None:
    _, captures, tasks, task = _queued_task(tmp_path)
    second_path = tmp_path / "second.pcapng"
    second_path.write_bytes(b"capture")
    second = captures.register(str(second_path))

    with pytest.raises(AppError) as raised:
        tasks.create_queued(
            session_id=task.session_id,
            capture_id=second.capture_id,
            standard_bandwidth_mbps=1000,
            actual_bandwidth_mbps=500,
            analysis_id="analysis-2",
        )

    assert raised.value.code == "ANALYSIS_ALREADY_ACTIVE"
    assert tasks.get("analysis-2") is None


def test_terminal_task_allows_a_new_analysis_in_same_session(tmp_path: Path) -> None:
    _, captures, tasks, task = _queued_task(tmp_path)
    tasks.transition(task.analysis_id, TaskStatus.VALIDATING)
    tasks.transition(task.analysis_id, TaskStatus.ANALYZING)
    tasks.transition(task.analysis_id, TaskStatus.REASONING)
    tasks.transition(task.analysis_id, TaskStatus.REPORTING)
    completed = tasks.transition(task.analysis_id, TaskStatus.COMPLETED)
    second_path = tmp_path / "second.pcapng"
    second_path.write_bytes(b"capture")
    second_capture = captures.register(str(second_path))

    second = tasks.create_queued(
        session_id=task.session_id,
        capture_id=second_capture.capture_id,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=500,
        analysis_id="analysis-2",
    )

    assert completed.status is TaskStatus.COMPLETED
    assert second.status is TaskStatus.QUEUED
