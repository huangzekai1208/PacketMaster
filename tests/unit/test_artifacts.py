from __future__ import annotations

import os
import time
from collections import namedtuple
from pathlib import Path

import pytest

from packetmaster.artifacts import ArtifactManager, create_request_id
from packetmaster.domain import Target
from packetmaster.errors import AppError

DiskUsage = namedtuple("DiskUsage", ["total", "used", "free"])


def test_create_makes_isolated_task_directories(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)

    first = manager.create("request-1")
    second = manager.create("request-2")

    assert first.root == (tmp_path / "output" / "request-1").resolve()
    assert first.filtered_dir.is_dir()
    assert first.logs_dir.is_dir()
    assert first.root != second.root
    assert first.coverage_json == first.root / "coverage.json"
    assert first.trace_jsonl == first.root / "trace.jsonl"


@pytest.mark.parametrize(
    "request_id",
    [".", "..", "../escape", "nested/path", r"nested\\path", "bad id"],
)
def test_create_rejects_path_traversal_and_invalid_request_ids(
    tmp_path: Path, request_id: str
) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=24)

    with pytest.raises(ValueError):
        manager.create(request_id)


@pytest.mark.parametrize("target", [Target.DOWNLOAD, "upload", Target.BOTH])
def test_preflight_accepts_supported_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, target: Target | str
) -> None:
    input_path = tmp_path / "capture.pcap"
    input_path.write_bytes(b"x")
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)
    monkeypatch.setattr(
        "packetmaster.artifacts.shutil.disk_usage",
        lambda path: DiskUsage(2 * 1024**3, 0, 2 * 1024**3),
    )

    assert manager.preflight(input_path, target).input_size_bytes == 1


def test_preflight_rejects_unsupported_target(tmp_path: Path) -> None:
    input_path = tmp_path / "capture.pcap"
    input_path.write_bytes(b"x")
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)

    with pytest.raises(ValueError, match="target"):
        manager.preflight(input_path, "sideways")


def test_preflight_returns_exact_resource_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "输入.pcap"
    input_path.write_bytes(b"x" * 10)
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)
    available = 2_000_000_000
    disk_usage_targets: list[Path] = []

    def disk_usage(target: Path) -> DiskUsage:
        disk_usage_targets.append(target)
        return DiskUsage(3_000_000_000, 1_000_000_000, available)

    monkeypatch.setattr(
        "packetmaster.artifacts.shutil.disk_usage",
        disk_usage,
    )

    budget = manager.preflight(input_path, "download")

    assert budget.input_size_bytes == 10
    assert budget.required_free_bytes == int(10 * 1.5) + 1024**3
    assert budget.available_free_bytes == available
    assert manager.root.is_dir()
    assert disk_usage_targets == [manager.root]


def test_preflight_raises_actionable_error_when_disk_space_is_insufficient(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "capture.pcap"
    input_path.write_bytes(b"x")
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)
    monkeypatch.setattr(
        "packetmaster.artifacts.shutil.disk_usage",
        lambda target: DiskUsage(100, 1, 100),
    )

    with pytest.raises(AppError) as exc_info:
        manager.preflight(input_path, "download")

    error = exc_info.value
    assert error.code == "INSUFFICIENT_DISK_SPACE"
    assert error.recoverable is True
    assert error.details == {
        "required": int(1 * 1.5) + 1024**3,
        "available": 100,
        "target": "download",
    }


def test_preflight_rejects_non_file_input(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path / "output", ttl_hours=24)

    with pytest.raises(FileNotFoundError):
        manager.preflight(tmp_path / "missing.pcap", "download")
    with pytest.raises(ValueError):
        manager.preflight(tmp_path, "download")


def test_append_trace_writes_utf8_jsonl(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=24)
    paths = manager.create("request-1")

    manager.append_trace(paths, {"event": "分析开始", "count": 1})
    manager.append_trace(paths, {"event": "complete"})

    assert paths.trace_jsonl.read_text(encoding="utf-8").splitlines() == [
        '{"event": "分析开始", "count": 1}',
        '{"event": "complete"}',
    ]


def test_keep_prevents_expired_task_cleanup(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=1)
    paths = manager.create("request-1")
    manager.mark_keep(paths)
    now = time.time()
    os.utime(paths.root, (now - 7200, now - 7200))

    assert manager.cleanup_expired(now) == []
    assert paths.root.exists()


def test_active_task_is_not_removed_until_marked_complete(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=1)
    paths = manager.create("active-request")
    manager.mark_active(paths)
    now = time.time()
    os.utime(paths.root, (now - 7200, now - 7200))

    assert manager.cleanup_expired(now) == []
    manager.mark_complete(paths)
    assert manager.cleanup_expired(now + 7200) == [paths.root]


def test_cleanup_removes_expired_task_directories_only(tmp_path: Path) -> None:
    manager = ArtifactManager(tmp_path, ttl_hours=1)
    expired = manager.create("expired")
    current = manager.create("current")
    plain_file = tmp_path / "not-a-task.txt"
    plain_file.write_text("keep", encoding="utf-8")
    now = time.time()
    os.utime(expired.root, (now - 7200, now - 7200))

    removed = manager.cleanup_expired(now)

    assert removed == [expired.root]
    assert not expired.root.exists()
    assert current.root.exists()
    assert plain_file.exists()


def test_create_request_id_is_allowed_and_unique() -> None:
    first = create_request_id()
    second = create_request_id()

    assert first != second
    assert first.replace("-", "").replace("_", "").isalnum()
    assert len(first) >= 16
