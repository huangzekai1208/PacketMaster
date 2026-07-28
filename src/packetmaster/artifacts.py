"""按请求隔离诊断产物，并在写入前检查本机磁盘空间。"""

from __future__ import annotations

import json
import re
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packetmaster.domain import Target
from packetmaster.errors import AppError

_REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")
_GIB = 1024**3


@dataclass(frozen=True)
class ArtifactPaths:
    root: Path
    filtered_dir: Path
    logs_dir: Path
    coverage_json: Path
    speed_stats_json: Path
    tcp_analysis_json: Path
    analysis_db: Path
    report_json: Path
    trace_jsonl: Path


@dataclass(frozen=True)
class ResourceBudget:
    input_size_bytes: int
    required_free_bytes: int
    available_free_bytes: int


class ArtifactManager:
    def __init__(self, root: Path, ttl_hours: int) -> None:
        self.root = root.expanduser().resolve()
        self.ttl_hours = ttl_hours

    def create(self, request_id: str) -> ArtifactPaths:
        if not _REQUEST_ID_PATTERN.fullmatch(request_id) or not request_id.strip("."):
            raise ValueError("request_id contains unsupported characters")

        task_root = (self.root / request_id).resolve()
        if not task_root.is_relative_to(self.root):
            raise ValueError("request_id must resolve inside the artifact root")
        filtered_dir = task_root / "filtered"
        logs_dir = task_root / "logs"
        filtered_dir.mkdir(parents=True, exist_ok=True)
        logs_dir.mkdir(parents=True, exist_ok=True)
        return ArtifactPaths(
            root=task_root,
            filtered_dir=filtered_dir,
            logs_dir=logs_dir,
            coverage_json=task_root / "coverage.json",
            speed_stats_json=task_root / "speed_stats.json",
            tcp_analysis_json=task_root / "tcp_analysis.json",
            analysis_db=task_root / "analysis.sqlite",
            report_json=task_root / "report.json",
            trace_jsonl=task_root / "trace.jsonl",
        )

    def preflight(self, input_path: Path, target: Target | str) -> ResourceBudget:
        try:
            validated_target = Target(target)
        except ValueError as error:
            raise ValueError(f"unsupported target: {target}") from error

        if not input_path.exists():
            raise FileNotFoundError(input_path)
        if not input_path.is_file():
            raise ValueError("input_path must be a file")

        self.root.mkdir(parents=True, exist_ok=True)
        input_size = input_path.stat().st_size
        required = int(input_size * 1.5) + _GIB
        available = shutil.disk_usage(self.root).free
        budget = ResourceBudget(input_size, required, available)
        if available < required:
            raise AppError(
                code="INSUFFICIENT_DISK_SPACE",
                message="Insufficient disk space for analysis artifacts",
                recoverable=True,
                suggested_action=(
                    "Free disk space or choose another artifact directory."
                ),
                details={
                    "required": required,
                    "available": available,
                    "target": validated_target.value,
                },
            )
        return budget

    def append_trace(self, paths: ArtifactPaths, event: dict[str, Any]) -> None:
        with paths.trace_jsonl.open("a", encoding="utf-8") as trace_file:
            trace_file.write(json.dumps(event, ensure_ascii=False))
            trace_file.write("\n")

    def mark_keep(self, paths: ArtifactPaths) -> None:
        (paths.root / ".keep").touch()

    def mark_active(self, paths: ArtifactPaths) -> None:
        (paths.root / ".active").touch()

    def mark_complete(self, paths: ArtifactPaths) -> None:
        (paths.root / ".active").unlink(missing_ok=True)

    def cleanup_expired(self, now: float) -> list[Path]:
        cutoff = now - self.ttl_hours * 3600
        removed: list[Path] = []
        if not self.root.exists():
            return removed

        for candidate in self.root.iterdir():
            if (
                candidate.is_dir()
                and not (candidate / ".keep").exists()
                and not (candidate / ".active").exists()
                and candidate.stat().st_mtime < cutoff
            ):
                shutil.rmtree(candidate)
                removed.append(candidate)
        return removed


def create_request_id() -> str:
    """Create a collision-resistant identifier accepted by ArtifactManager.create."""
    return uuid.uuid4().hex
