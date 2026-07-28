"""安全注册本机或浏览器上传的报文文件，并仅暴露公共元数据。"""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packetmaster.errors import AppError
from packetmaster.web.contracts import CaptureSummary
from packetmaster.web.database import WebDatabase


@dataclass(frozen=True)
class CaptureRecord:
    capture_id: str
    file_name: str
    size_bytes: int
    local_path: Path
    modified_at_ns: int
    sha256: str | None
    created_at: datetime
    last_used_at: datetime

    def public(self) -> CaptureSummary:
        return CaptureSummary(
            capture_id=self.capture_id,
            file_name=self.file_name,
            size_bytes=self.size_bytes,
        )


class CaptureRepository:
    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def register(
        self,
        path: Path,
        *,
        size_bytes: int,
        modified_at_ns: int,
        file_name: str | None = None,
        now: datetime | None = None,
    ) -> CaptureRecord:
        current = (now or datetime.now(UTC)).astimezone(UTC)
        timestamp = current.isoformat()
        local_path = str(path)
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                "SELECT * FROM captures WHERE local_path = ?", (local_path,)
            ).fetchone()
            if existing is not None:
                connection.execute(
                    """
                    UPDATE captures
                    SET file_name = ?, size_bytes = ?, modified_at_ns = ?,
                        last_used_at = ?
                    WHERE capture_id = ?
                    """,
                    (
                        file_name or path.name,
                        size_bytes,
                        modified_at_ns,
                        timestamp,
                        existing["capture_id"],
                    ),
                )
                refreshed = connection.execute(
                    "SELECT * FROM captures WHERE capture_id = ?",
                    (existing["capture_id"],),
                ).fetchone()
                return _record(refreshed)

            capture_id = uuid.uuid4().hex
            connection.execute(
                """
                INSERT INTO captures (
                    capture_id, file_name, size_bytes, local_path,
                    modified_at_ns, created_at, last_used_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    capture_id,
                    file_name or path.name,
                    size_bytes,
                    local_path,
                    modified_at_ns,
                    timestamp,
                    timestamp,
                ),
            )
            row = connection.execute(
                "SELECT * FROM captures WHERE capture_id = ?", (capture_id,)
            ).fetchone()
            return _record(row)

    def get(self, capture_id: str) -> CaptureRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM captures WHERE capture_id = ?", (capture_id,)
            ).fetchone()
        return _record(row) if row is not None else None

    def recent(self, *, limit: int = 20) -> list[CaptureRecord]:
        if not 1 <= limit <= 100:
            raise ValueError("invalid capture limit")
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM captures
                ORDER BY last_used_at DESC, capture_id
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [_record(row) for row in rows]

    def delete(self, capture_id: str) -> bool:
        try:
            with self.database.transaction(immediate=True) as connection:
                cursor = connection.execute(
                    "DELETE FROM captures WHERE capture_id = ?", (capture_id,)
                )
        except sqlite3.IntegrityError as exc:
            raise AppError(
                code="CAPTURE_IN_USE",
                message="报文仍被分析任务引用",
                recoverable=True,
                suggested_action="保留该引用，或先删除关联任务。",
            ) from exc
        return cursor.rowcount > 0


class CaptureRegistry:
    def __init__(
        self, repository: CaptureRepository, *, allowed_roots: list[Path]
    ) -> None:
        if not allowed_roots:
            raise ValueError("at least one capture root is required")
        self.repository = repository
        self.allowed_roots = tuple(
            root.expanduser().resolve() for root in allowed_roots
        )

    def register(self, value: str) -> CaptureSummary:
        if not value or len(value) > 4096:
            raise _capture_error(
                "INVALID_CAPTURE_PATH",
                "报文路径无效",
                "请输入完整的本机 pcap 或 pcapng 文件路径。",
            )
        candidate = Path(value).expanduser()
        if not candidate.is_absolute():
            raise _capture_error(
                "CAPTURE_PATH_NOT_ABSOLUTE",
                "Web 模式需要使用绝对报文路径",
                "请提供完整的 Windows 或 macOS 文件路径。",
            )
        try:
            resolved = candidate.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise _capture_error(
                "CAPTURE_NOT_FOUND",
                "报文文件不存在或无法访问",
                "请检查路径后重新注册报文。",
            ) from exc
        return self._register_resolved(resolved)

    def register_uploaded(self, path: Path, *, original_name: str) -> CaptureSummary:
        # 受管文件名是随机值，向 UI 保留用户选择时的原始文件名即可。
        file_name = Path(original_name).name
        if not file_name or file_name != original_name:
            raise _capture_error(
                "INVALID_CAPTURE_NAME",
                "报文文件名无效",
                "请重新选择 pcap 或 pcapng 文件。",
            )
        if Path(file_name).suffix.casefold() not in {".pcap", ".pcapng"}:
            raise _capture_error(
                "UNSUPPORTED_CAPTURE_TYPE",
                "只支持 pcap 和 pcapng 报文",
                "请选择后缀为 .pcap 或 .pcapng 的文件。",
            )
        try:
            resolved = path.resolve(strict=True)
        except (FileNotFoundError, OSError) as exc:
            raise _capture_error(
                "CAPTURE_NOT_FOUND",
                "上传的报文文件不存在或无法访问",
                "请重新选择报文文件后重试。",
            ) from exc
        return self._register_resolved(resolved, file_name=file_name)

    def _register_resolved(
        self, resolved: Path, *, file_name: str | None = None
    ) -> CaptureSummary:
        # 路径注册和上传注册都必须落在白名单目录内，防止任意文件读取。
        if not any(resolved.is_relative_to(root) for root in self.allowed_roots):
            raise _capture_error(
                "CAPTURE_OUTSIDE_ALLOWED_ROOT",
                "报文文件不在允许目录中",
                "请选择允许目录中的报文，或修改后端允许目录配置。",
            )
        if not resolved.is_file():
            raise _capture_error(
                "CAPTURE_NOT_FILE",
                "报文路径不是普通文件",
                "请选择 pcap 或 pcapng 文件。",
            )
        if resolved.suffix.casefold() not in {".pcap", ".pcapng"}:
            raise _capture_error(
                "UNSUPPORTED_CAPTURE_TYPE",
                "只支持 pcap 和 pcapng 报文",
                "请选择后缀为 .pcap 或 .pcapng 的文件。",
            )
        if not os.access(resolved, os.R_OK):
            raise _capture_error(
                "CAPTURE_NOT_READABLE",
                "报文文件不可读",
                "请检查文件读取权限。",
            )
        try:
            with resolved.open("rb") as capture_file:
                capture_file.read(1)
            stat = resolved.stat()
        except OSError as exc:
            raise _capture_error(
                "CAPTURE_NOT_READABLE",
                "报文文件不可读",
                "请检查文件读取权限。",
            ) from exc
        return self.repository.register(
            resolved,
            size_bytes=stat.st_size,
            modified_at_ns=stat.st_mtime_ns,
            file_name=file_name,
        ).public()

    def recent(self, *, limit: int = 20) -> list[CaptureSummary]:
        return [record.public() for record in self.repository.recent(limit=limit)]

    def summary(self, capture_id: str) -> CaptureSummary:
        record = self.repository.get(capture_id)
        if record is None:
            raise _capture_error(
                "CAPTURE_REFERENCE_NOT_FOUND",
                "报文引用不存在",
                "请重新注册报文文件。",
            )
        return record.public()

    def resolve(self, capture_id: str) -> Path:
        record = self.repository.get(capture_id)
        if record is None:
            raise _capture_error(
                "CAPTURE_REFERENCE_NOT_FOUND",
                "报文引用不存在",
                "请重新注册报文文件。",
            )
        return record.local_path

    def delete(self, capture_id: str) -> bool:
        return self.repository.delete(capture_id)


def _record(row: sqlite3.Row) -> CaptureRecord:
    return CaptureRecord(
        capture_id=row["capture_id"],
        file_name=row["file_name"],
        size_bytes=row["size_bytes"],
        local_path=Path(row["local_path"]),
        modified_at_ns=row["modified_at_ns"],
        sha256=row["sha256"],
        created_at=datetime.fromisoformat(row["created_at"]),
        last_used_at=datetime.fromisoformat(row["last_used_at"]),
    )


def _capture_error(code: str, message: str, action: str) -> AppError:
    return AppError(
        code=code,
        message=message,
        recoverable=True,
        suggested_action=action,
    )
