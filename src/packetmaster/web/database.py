"""Versioned SQLite persistence for the local PacketMaster Web workspace."""

from __future__ import annotations

import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from packetmaster.web.contracts import (
    MessageType,
    SessionSummary,
    TaskStatus,
    WebMessage,
)

_SCHEMA_VERSION = 1
_MIGRATIONS = {
    1: """
        CREATE TABLE sessions (
            session_id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            status TEXT NOT NULL,
            current_analysis_id TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX sessions_updated_at_idx
            ON sessions(updated_at DESC, session_id);
        CREATE INDEX sessions_status_idx
            ON sessions(status, updated_at DESC);

        CREATE TABLE messages (
            message_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id)
                ON DELETE CASCADE,
            message_type TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL,
            analysis_id TEXT,
            evidence_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX messages_session_idx
            ON messages(session_id, created_at, message_id);

        CREATE TABLE captures (
            capture_id TEXT PRIMARY KEY,
            file_name TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            local_path TEXT NOT NULL,
            modified_at_ns INTEGER NOT NULL,
            sha256 TEXT,
            created_at TEXT NOT NULL,
            last_used_at TEXT NOT NULL
        );
        CREATE INDEX captures_recent_idx
            ON captures(last_used_at DESC, capture_id);

        CREATE TABLE analyses (
            analysis_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id),
            capture_id TEXT NOT NULL REFERENCES captures(capture_id),
            status TEXT NOT NULL,
            stage_message TEXT NOT NULL DEFAULT '',
            progress_fraction REAL,
            standard_bandwidth_mbps REAL NOT NULL,
            actual_bandwidth_mbps REAL NOT NULL,
            target TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT,
            worker_heartbeat_at TEXT,
            processed_packets INTEGER,
            cancel_requested INTEGER NOT NULL DEFAULT 0,
            retry_of_analysis_id TEXT REFERENCES analyses(analysis_id),
            report_path TEXT,
            error_code TEXT,
            error_message TEXT,
            recoverable INTEGER NOT NULL DEFAULT 0,
            suggested_action TEXT NOT NULL DEFAULT ''
        );
        CREATE INDEX analyses_session_idx
            ON analyses(session_id, created_at DESC, analysis_id);
        CREATE INDEX analyses_queue_idx
            ON analyses(status, created_at, analysis_id);

        CREATE TABLE analysis_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id)
                ON DELETE CASCADE,
            event_type TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            progress_fraction REAL,
            stage_message TEXT NOT NULL DEFAULT '',
            processed_packets INTEGER,
            elapsed_seconds REAL,
            error_code TEXT
        );
        CREATE INDEX analysis_events_stream_idx
            ON analysis_events(analysis_id, event_id);

        CREATE TABLE chat_turns (
            turn_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES sessions(session_id)
                ON DELETE CASCADE,
            analysis_id TEXT NOT NULL REFERENCES analyses(analysis_id)
                ON DELETE CASCADE,
            question TEXT NOT NULL,
            answer TEXT NOT NULL,
            citations_json TEXT NOT NULL DEFAULT '[]',
            limitations_json TEXT NOT NULL DEFAULT '[]',
            suggestions_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE INDEX chat_turns_analysis_idx
            ON chat_turns(analysis_id, created_at, turn_id);
    """,
}


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC).isoformat()


def _datetime(value: str) -> datetime:
    return datetime.fromisoformat(value)


class WebDatabase:
    """Own connections and schema migration for one local database file."""

    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        self.path = path.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise RuntimeError(
                    f"database schema {version} is newer than {_SCHEMA_VERSION}"
                )
            for next_version in range(version + 1, _SCHEMA_VERSION + 1):
                migration = _MIGRATIONS[next_version]
                with connection:
                    connection.executescript(migration)
                    connection.execute(f"PRAGMA user_version = {next_version}")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()


class SessionRepository:
    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def create(
        self,
        *,
        title: str = "新诊断",
        session_id: str | None = None,
        now: datetime | None = None,
    ) -> SessionSummary:
        identifier = session_id or uuid.uuid4().hex
        current = now or _now()
        encoded = _timestamp(current)
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO sessions (
                    session_id, title, status, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (identifier, title, TaskStatus.DRAFT.value, encoded, encoded),
            )
        return SessionSummary(
            session_id=identifier,
            title=title,
            status=TaskStatus.DRAFT,
            created_at=current,
            updated_at=current,
        )

    def get(self, session_id: str) -> SessionSummary | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        return _session(row) if row is not None else None

    def list(
        self, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[SessionSummary], int]:
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("invalid session page")
        with self.database.connect() as connection:
            total = int(
                connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT * FROM sessions
                ORDER BY updated_at DESC, session_id
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
        return [_session(row) for row in rows], total

    def delete(self, session_id: str) -> bool:
        with self.database.transaction(immediate=True) as connection:
            cursor = connection.execute(
                "DELETE FROM sessions WHERE session_id = ?", (session_id,)
            )
        return cursor.rowcount > 0


class MessageRepository:
    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def append(
        self,
        *,
        session_id: str,
        message_type: MessageType,
        content: str,
        message_id: str | None = None,
        analysis_id: str | None = None,
        evidence_count: int = 0,
        now: datetime | None = None,
    ) -> WebMessage:
        identifier = message_id or uuid.uuid4().hex
        current = now or _now()
        encoded = _timestamp(current)
        message = WebMessage(
            message_id=identifier,
            session_id=session_id,
            message_type=message_type,
            content=content,
            created_at=current,
            analysis_id=analysis_id,
            evidence_count=evidence_count,
        )
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO messages (
                    message_id, session_id, message_type, content, created_at,
                    analysis_id, evidence_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    session_id,
                    message_type.value,
                    content,
                    encoded,
                    analysis_id,
                    evidence_count,
                ),
            )
            connection.execute(
                "UPDATE sessions SET updated_at = ? WHERE session_id = ?",
                (encoded, session_id),
            )
        return message

    def list(
        self, *, session_id: str, offset: int = 0, limit: int = 100
    ) -> tuple[list[WebMessage], int]:
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("invalid message page")
        with self.database.connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM messages WHERE session_id = ?",
                    (session_id,),
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT * FROM messages
                WHERE session_id = ?
                ORDER BY created_at, message_id
                LIMIT ? OFFSET ?
                """,
                (session_id, limit, offset),
            ).fetchall()
        return [_message(row) for row in rows], total


def _session(row: sqlite3.Row) -> SessionSummary:
    return SessionSummary(
        session_id=row["session_id"],
        title=row["title"],
        status=TaskStatus(row["status"]),
        current_analysis_id=row["current_analysis_id"],
        created_at=_datetime(row["created_at"]),
        updated_at=_datetime(row["updated_at"]),
    )


def _message(row: sqlite3.Row) -> WebMessage:
    return WebMessage(
        message_id=row["message_id"],
        session_id=row["session_id"],
        message_type=MessageType(row["message_type"]),
        content=row["content"],
        created_at=_datetime(row["created_at"]),
        analysis_id=row["analysis_id"],
        evidence_count=row["evidence_count"],
    )
