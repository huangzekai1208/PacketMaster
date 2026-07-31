"""本机 PacketMaster Web 工作区的版本化 SQLite 持久化。"""

from __future__ import annotations

import json
import sqlite3
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packetmaster.domain import Target
from packetmaster.errors import AppError
from packetmaster.web.contracts import (
    ChatTurnResult,
    MessageType,
    RagMessageCitation,
    SessionSummary,
    TaskStatus,
    WebMessage,
)

_SCHEMA_VERSION = 6
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
    2: """
        CREATE UNIQUE INDEX captures_local_path_idx ON captures(local_path);
    """,
    3: """
        ALTER TABLE analyses ADD COLUMN worker_id TEXT;
        CREATE INDEX analyses_worker_idx
            ON analyses(worker_id, status, worker_heartbeat_at);
    """,
    4: """
        CREATE TABLE session_intents (
            session_id TEXT PRIMARY KEY REFERENCES sessions(session_id)
                ON DELETE CASCADE,
            capture_id TEXT REFERENCES captures(capture_id) ON DELETE SET NULL,
            standard_bandwidth_mbps REAL,
            actual_bandwidth_mbps REAL,
            target TEXT NOT NULL DEFAULT 'download',
            assumptions_json TEXT NOT NULL DEFAULT '[]',
            ambiguities_json TEXT NOT NULL DEFAULT '[]',
            confirmed_analysis_id TEXT REFERENCES analyses(analysis_id),
            updated_at TEXT NOT NULL
        );
    """,
    5: """
        ALTER TABLE chat_turns ADD COLUMN knowledge_citations_json TEXT
            NOT NULL DEFAULT '[]';
    """,
    6: """
        ALTER TABLE messages ADD COLUMN rag_status TEXT;
        ALTER TABLE messages ADD COLUMN rag_reason TEXT NOT NULL DEFAULT '';
        ALTER TABLE messages ADD COLUMN rag_citations_json TEXT
            NOT NULL DEFAULT '[]';
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
        try:
            with self.database.transaction(immediate=True) as connection:
                cursor = connection.execute(
                    "DELETE FROM sessions WHERE session_id = ?", (session_id,)
                )
        except sqlite3.IntegrityError as exc:
            raise AppError(
                code="SESSION_IN_USE",
                message="会话仍有关联的分析任务",
                recoverable=True,
                suggested_action="请保留该会话，已完成任务的清理将在后续版本提供。",
            ) from exc
        return cursor.rowcount > 0

    def set_status(
        self,
        session_id: str,
        status: TaskStatus,
        *,
        current_analysis_id: str | None = None,
    ) -> SessionSummary:
        timestamp = _timestamp(_now())
        with self.database.transaction(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE sessions
                SET status = ?, current_analysis_id = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (status.value, current_analysis_id, timestamp, session_id),
            )
        if cursor.rowcount == 0:
            raise _session_not_found()
        result = self.get(session_id)
        if result is None:
            raise _session_not_found()
        return result


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
        rag_status: str | None = None,
        rag_reason: str = "",
        rag_citations: list[RagMessageCitation] | None = None,
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
            rag_status=rag_status,
            rag_reason=rag_reason,
            rag_citations=rag_citations or [],
        )
        with self.database.transaction(immediate=True) as connection:
            connection.execute(
                """
                INSERT INTO messages (
                    message_id, session_id, message_type, content, created_at,
                    analysis_id, evidence_count, rag_status, rag_reason,
                    rag_citations_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    session_id,
                    message_type.value,
                    content,
                    encoded,
                    analysis_id,
                    evidence_count,
                    rag_status,
                    rag_reason,
                    json.dumps(
                        [item.model_dump(mode="json") for item in rag_citations or []],
                        ensure_ascii=False,
                    ),
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


@dataclass(frozen=True)
class PendingIntentRecord:
    session_id: str
    capture_id: str | None
    standard_bandwidth_mbps: float | None
    actual_bandwidth_mbps: float | None
    target: Target
    assumptions: list[str]
    ambiguities: list[str]
    confirmed_analysis_id: str | None
    updated_at: datetime


class PendingIntentRepository:
    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def get(self, session_id: str) -> PendingIntentRecord | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM session_intents WHERE session_id = ?", (session_id,)
            ).fetchone()
        return _pending_intent(row) if row is not None else None

    def upsert(
        self,
        *,
        session_id: str,
        capture_id: str | None,
        standard_bandwidth_mbps: float | None,
        actual_bandwidth_mbps: float | None,
        target: Target = Target.DOWNLOAD,
        assumptions: list[str] | None = None,
        ambiguities: list[str] | None = None,
    ) -> PendingIntentRecord:
        current = _now()
        timestamp = _timestamp(current)
        with self.database.transaction(immediate=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO session_intents (
                        session_id, capture_id, standard_bandwidth_mbps,
                        actual_bandwidth_mbps, target, assumptions_json,
                        ambiguities_json, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(session_id) DO UPDATE SET
                        capture_id = excluded.capture_id,
                        standard_bandwidth_mbps = excluded.standard_bandwidth_mbps,
                        actual_bandwidth_mbps = excluded.actual_bandwidth_mbps,
                        target = excluded.target,
                        assumptions_json = excluded.assumptions_json,
                        ambiguities_json = excluded.ambiguities_json,
                        confirmed_analysis_id = NULL,
                        updated_at = excluded.updated_at
                    """,
                    (
                        session_id,
                        capture_id,
                        standard_bandwidth_mbps,
                        actual_bandwidth_mbps,
                        target.value,
                        json.dumps(assumptions or [], ensure_ascii=False),
                        json.dumps(ambiguities or [], ensure_ascii=False),
                        timestamp,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise _session_not_found() from exc
        result = self.get(session_id)
        if result is None:
            raise RuntimeError("saved pending intent is unavailable")
        return result

    def mark_confirmed(self, session_id: str, analysis_id: str) -> None:
        with self.database.transaction(immediate=True) as connection:
            cursor = connection.execute(
                """
                UPDATE session_intents
                SET confirmed_analysis_id = ?, updated_at = ?
                WHERE session_id = ?
                """,
                (analysis_id, _timestamp(_now()), session_id),
            )
        if cursor.rowcount == 0:
            raise _session_not_found()


class ChatTurnRepository:
    def __init__(self, database: WebDatabase) -> None:
        self.database = database

    def append(
        self,
        *,
        session_id: str,
        analysis_id: str,
        question: str,
        answer: str,
        citations: list[dict[str, object]],
        limitations: list[str],
        suggestions: list[str],
        knowledge_citations: list[dict[str, object]] | None = None,
        turn_id: str | None = None,
    ) -> ChatTurnResult:
        identifier = turn_id or uuid.uuid4().hex
        current = _now()
        with self.database.transaction(immediate=True) as connection:
            try:
                connection.execute(
                    """
                    INSERT INTO chat_turns (
                        turn_id, session_id, analysis_id, question, answer,
                        citations_json, limitations_json, suggestions_json,
                        knowledge_citations_json, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        identifier,
                        session_id,
                        analysis_id,
                        question,
                        answer,
                        json.dumps(citations, ensure_ascii=False),
                        json.dumps(limitations, ensure_ascii=False),
                        json.dumps(suggestions, ensure_ascii=False),
                        json.dumps(
                            knowledge_citations or [], ensure_ascii=False
                        ),
                        _timestamp(current),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise AppError(
                    code="INVALID_CHAT_REFERENCE",
                    message="问答关联的会话或任务不存在",
                    recoverable=True,
                    suggested_action="请刷新页面后重新选择分析任务。",
                ) from exc
        return ChatTurnResult(
            turn_id=identifier,
            analysis_id=analysis_id,
            question=question,
            answer=answer,
            citations=citations,
            limitations=limitations,
            suggestions=suggestions,
            knowledge_citations=knowledge_citations or [],
            created_at=current,
        )

    def list(
        self, analysis_id: str, *, offset: int = 0, limit: int = 50
    ) -> tuple[list[ChatTurnResult], int]:
        with self.database.connect() as connection:
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM chat_turns WHERE analysis_id = ?",
                    (analysis_id,),
                ).fetchone()[0]
            )
            rows = connection.execute(
                """
                SELECT * FROM chat_turns WHERE analysis_id = ?
                ORDER BY created_at, turn_id LIMIT ? OFFSET ?
                """,
                (analysis_id, limit, offset),
            ).fetchall()
        return [_chat_turn(row) for row in rows], total


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
        rag_status=row["rag_status"],
        rag_reason=row["rag_reason"],
        rag_citations=[
            RagMessageCitation.model_validate(item)
            for item in json.loads(row["rag_citations_json"])
        ],
    )


def _pending_intent(row: sqlite3.Row) -> PendingIntentRecord:
    return PendingIntentRecord(
        session_id=row["session_id"],
        capture_id=row["capture_id"],
        standard_bandwidth_mbps=row["standard_bandwidth_mbps"],
        actual_bandwidth_mbps=row["actual_bandwidth_mbps"],
        target=Target(row["target"]),
        assumptions=list(json.loads(row["assumptions_json"])),
        ambiguities=list(json.loads(row["ambiguities_json"])),
        confirmed_analysis_id=row["confirmed_analysis_id"],
        updated_at=_datetime(row["updated_at"]),
    )


def _chat_turn(row: sqlite3.Row) -> ChatTurnResult:
    return ChatTurnResult(
        turn_id=row["turn_id"],
        analysis_id=row["analysis_id"],
        question=row["question"],
        answer=row["answer"],
        citations=json.loads(row["citations_json"]),
        limitations=json.loads(row["limitations_json"]),
        suggestions=json.loads(row["suggestions_json"]),
        knowledge_citations=json.loads(
            row["knowledge_citations_json"]
        )
        if "knowledge_citations_json" in row.keys()
        else [],
        created_at=_datetime(row["created_at"]),
    )


def _session_not_found() -> AppError:
    return AppError(
        code="SESSION_NOT_FOUND",
        message="会话不存在",
        recoverable=True,
        suggested_action="请刷新会话列表或新建会话。",
    )
