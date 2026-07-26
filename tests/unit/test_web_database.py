from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from packetmaster.web.contracts import MessageType
from packetmaster.web.database import MessageRepository, SessionRepository, WebDatabase


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

    assert version == 2
    assert journal_mode == "wal"
    assert {
        "sessions",
        "messages",
        "captures",
        "analyses",
        "analysis_events",
        "chat_turns",
    } <= tables


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
