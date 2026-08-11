from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packetmaster.domain import Target
from packetmaster.errors import AppError
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import MessageType, RagMessageCitation, TaskStatus
from packetmaster.web.database import (
    MessageRepository,
    PendingIntentRepository,
    SessionRepository,
    WebDatabase,
)


def _database(tmp_path: Path) -> WebDatabase:
    database = WebDatabase(tmp_path / "packetmaster-web.sqlite")
    database.initialize()
    return database


def test_database_initialization_is_versioned_idempotent_and_uses_wal(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    database.initialize()

    with database.connect() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

    assert version == 9
    assert journal_mode == "wal"
    assert {
        "sessions",
        "messages",
        "captures",
        "analyses",
        "analysis_events",
        "chat_turns",
        "session_intents",
    } <= tables


def test_schema_migration_renames_legacy_default_sessions(tmp_path: Path) -> None:
    database = _database(tmp_path)
    session = SessionRepository(database).create(title="新诊断")
    with database.transaction(immediate=True) as connection:
        connection.execute("DROP INDEX analyses_checkpoint_thread_idx")
        connection.execute("ALTER TABLE analyses DROP COLUMN checkpoint_thread_id")
        connection.execute("ALTER TABLE analyses DROP COLUMN error_details_json")
        connection.execute("PRAGMA user_version = 6")

    database.initialize()

    restored = SessionRepository(database).get(session.session_id)
    assert restored is not None
    assert restored.title == "新会话"


def test_pending_intent_survives_repository_recreation(tmp_path: Path) -> None:
    database = _database(tmp_path)
    SessionRepository(database).create(session_id="session-1")
    intents = PendingIntentRepository(database)
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    ).register(str(capture_path))

    intents.upsert(
        session_id="session-1",
        capture_id=capture.capture_id,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=20,
        target=Target.DOWNLOAD,
        assumptions=["未填写单位时按 Mbps 解释"],
    )

    restored = PendingIntentRepository(WebDatabase(database.path)).get("session-1")
    assert restored is not None
    assert restored.capture_id == capture.capture_id
    assert restored.standard_bandwidth_mbps == 1000
    assert restored.actual_bandwidth_mbps == 20
    assert restored.target is Target.DOWNLOAD


def test_sessions_and_messages_persist_with_stable_pagination(tmp_path: Path) -> None:
    database = _database(tmp_path)
    sessions = SessionRepository(database)
    messages = MessageRepository(database)
    start = datetime(2026, 7, 26, tzinfo=UTC)
    first = sessions.create(session_id="session-1", now=start)
    sessions.create(session_id="session-2", now=start + timedelta(seconds=1))
    messages.append(
        session_id=first.session_id,
        message_id="message-1",
        message_type=MessageType.USER,
        content="分析测速报文",
        now=start,
    )
    messages.append(
        session_id=first.session_id,
        message_id="message-2",
        message_type=MessageType.CLARIFICATION,
        content="请提供报文文件。",
        now=start + timedelta(seconds=1),
    )

    reopened_sessions = SessionRepository(WebDatabase(database.path))
    reopened_messages = MessageRepository(WebDatabase(database.path))
    page, total = reopened_sessions.list(offset=0, limit=1)
    message_page, message_total = reopened_messages.list(
        session_id="session-1", offset=1, limit=1
    )

    assert total == 2
    assert page[0].session_id == "session-1"
    assert message_total == 2
    assert message_page[0].message_id == "message-2"


def test_message_rag_trace_survives_repository_recreation(tmp_path: Path) -> None:
    database = _database(tmp_path)
    SessionRepository(database).create(session_id="session-1")
    MessageRepository(database).append(
        session_id="session-1",
        message_id="message-rag",
        message_type=MessageType.ASSISTANT,
        content="相对序列号只是显示方式。",
        rag_status="used",
        rag_citations=[
            RagMessageCitation(
                knowledge_id="wireshark.tcp",
                title="Wireshark TCP 分析",
                chunk_id="wireshark.tcp:v1:c3",
                reranker_score=0.9321,
            )
        ],
    )

    restored, _ = MessageRepository(WebDatabase(database.path)).list(
        session_id="session-1"
    )

    assert restored[0].rag_status == "used"
    assert restored[0].rag_citations[0].title == "Wireshark TCP 分析"
    assert restored[0].rag_citations[0].reranker_score == 0.9321


def test_concurrent_message_writes_are_serialized(tmp_path: Path) -> None:
    database = _database(tmp_path)
    SessionRepository(database).create(session_id="session-1")

    def append(index: int) -> None:
        MessageRepository(database).append(
            session_id="session-1",
            message_id=f"message-{index:02d}",
            message_type=MessageType.USER,
            content=f"问题 {index}",
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        list(executor.map(append, range(20)))

    page, total = MessageRepository(database).list(
        session_id="session-1", limit=100
    )
    assert total == 20
    assert len(page) == 20


def test_session_with_terminal_analysis_is_deleted_with_related_records(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    sessions = SessionRepository(database)
    sessions.create(session_id="session-1")
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    ).register(str(capture_path))
    now = datetime(2026, 8, 6, tzinfo=UTC).isoformat()
    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO analyses (
                analysis_id, session_id, capture_id, status,
                standard_bandwidth_mbps, actual_bandwidth_mbps, target,
                created_at, updated_at, checkpoint_thread_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "analysis-1",
                "session-1",
                capture.capture_id,
                TaskStatus.COMPLETED.value,
                1000,
                600,
                Target.DOWNLOAD.value,
                now,
                now,
                "thread-1",
            ),
        )
        connection.execute(
            """
            INSERT INTO analysis_events (
                analysis_id, event_type, status, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            ("analysis-1", "analysis_completed", "completed", now),
        )
        connection.execute(
            """
            INSERT INTO chat_turns (
                turn_id, session_id, analysis_id, question, answer, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("turn-1", "session-1", "analysis-1", "原因？", "拥塞。", now),
        )
        connection.execute(
            """
            INSERT INTO session_intents (
                session_id, capture_id, confirmed_analysis_id, updated_at
            ) VALUES (?, ?, ?, ?)
            """,
            ("session-1", capture.capture_id, "analysis-1", now),
        )
    MessageRepository(database).append(
        session_id="session-1",
        message_id="message-1",
        message_type=MessageType.REPORT,
        content="分析完成",
        analysis_id="analysis-1",
    )

    assert sessions.delete("session-1") is True

    with database.connect() as connection:
        for table in (
            "sessions",
            "messages",
            "session_intents",
            "analyses",
            "analysis_events",
            "chat_turns",
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table}"
            ).fetchone()[0]
            assert count == 0
        assert connection.execute("SELECT COUNT(*) FROM captures").fetchone()[0] == 1
    assert capture_path.is_file()


@pytest.mark.parametrize(
    "status",
    [
        TaskStatus.QUEUED,
        TaskStatus.VALIDATING,
        TaskStatus.ANALYZING,
        TaskStatus.REASONING,
        TaskStatus.VERIFYING,
        TaskStatus.REPORTING,
    ],
)
def test_session_with_active_analysis_cannot_be_deleted(
    tmp_path: Path, status: TaskStatus
) -> None:
    database = _database(tmp_path)
    sessions = SessionRepository(database)
    sessions.create(session_id="session-1")
    capture_path = tmp_path / "capture.pcapng"
    capture_path.write_bytes(b"capture")
    capture = CaptureRegistry(
        CaptureRepository(database), allowed_roots=[tmp_path]
    ).register(str(capture_path))
    now = datetime(2026, 8, 6, tzinfo=UTC).isoformat()
    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO analyses (
                analysis_id, session_id, capture_id, status,
                standard_bandwidth_mbps, actual_bandwidth_mbps, target,
                created_at, updated_at, checkpoint_thread_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "analysis-1",
                "session-1",
                capture.capture_id,
                status.value,
                1000,
                600,
                Target.DOWNLOAD.value,
                now,
                now,
                "thread-1",
            ),
        )

    with pytest.raises(AppError) as raised:
        sessions.delete("session-1")

    assert raised.value.code == "SESSION_ANALYSIS_ACTIVE"
    assert sessions.get("session-1") is not None
