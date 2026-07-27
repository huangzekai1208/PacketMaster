from __future__ import annotations

import tracemalloc
from pathlib import Path

import pytest

from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.database import SessionRepository, WebDatabase
from packetmaster.web.tasks import AnalysisTaskRepository

pytestmark = pytest.mark.performance


def test_web_task_wrapper_does_not_load_large_capture_into_memory(
    tmp_path: Path,
) -> None:
    capture_path = tmp_path / "sparse-large-capture.pcapng"
    capture_size = 2 * 1024**3
    with capture_path.open("wb") as capture_file:
        capture_file.seek(capture_size - 1)
        capture_file.write(b"\0")

    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    session = SessionRepository(database).create(session_id="session-large")
    registry = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    )

    tracemalloc.start()
    try:
        capture = registry.register(str(capture_path))
        task = AnalysisTaskRepository(database).create_queued(
            session_id=session.session_id,
            capture_id=capture.capture_id,
            standard_bandwidth_mbps=1000,
            actual_bandwidth_mbps=20,
        )
        _, peak_bytes = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    assert capture.size_bytes == capture_size
    assert task.capture.size_bytes == capture_size
    assert peak_bytes < 8 * 1024**2
    assert database.path.stat().st_size < 2 * 1024**2
