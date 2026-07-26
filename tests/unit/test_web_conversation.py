from __future__ import annotations

import asyncio
from pathlib import Path

from packetmaster.domain import GeneralChatAnswer, Target
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import MissingParameter, TaskStatus
from packetmaster.web.conversation import WebConversationService
from packetmaster.web.database import (
    MessageRepository,
    PendingIntentRepository,
    SessionRepository,
    WebDatabase,
)
from packetmaster.web.tasks import AnalysisTaskRepository


class _Model:
    def __init__(self) -> None:
        self.questions: list[str] = []

    async def general_chat(self, user_text, conversation_summary="", turns=None):
        self.questions.append(user_text)
        return GeneralChatAnswer(answer="TCP 是一种面向连接的传输层协议。")


def _service(tmp_path: Path, model=None):
    database = WebDatabase(tmp_path / "web.sqlite")
    database.initialize()
    return WebConversationService(
        sessions=SessionRepository(database),
        messages=MessageRepository(database),
        intents=PendingIntentRepository(database),
        captures=CaptureRegistry(
            CaptureRepository(database), allowed_roots=[tmp_path]
        ),
        tasks=AnalysisTaskRepository(database),
        model=model or _Model(),
    ), database


def test_general_question_does_not_enter_diagnosis(tmp_path: Path) -> None:
    model = _Model()
    service, database = _service(tmp_path, model)
    session = service.create_session()

    result = asyncio.run(
        service.submit_message(session.session_id, content="TCP 是什么？")
    )

    assert result.route == "general"
    assert result.parameters is None
    assert result.assistant_message.content.startswith("TCP 是")
    assert AnalysisTaskRepository(database).count_for_session(session.session_id) == 0
    assert model.questions == ["TCP 是什么？"]


def test_general_chat_redacts_secrets_and_absolute_paths_before_storage_and_model(
    tmp_path: Path,
) -> None:
    model = _Model()
    service, database = _service(tmp_path, model)
    session = service.create_session()
    secret = "sk-1234567890abcdefghijkl"
    local_path = "/Users/example/private/notes.txt"

    asyncio.run(
        service.submit_message(
            session.session_id,
            content=f"请记住 {secret} 和 {local_path}",
        )
    )

    stored, _ = MessageRepository(database).list(session_id=session.session_id)
    persisted = "\n".join(message.content for message in stored)
    assert secret not in persisted
    assert local_path not in persisted
    assert secret not in model.questions[0]
    assert local_path not in model.questions[0]


def test_complete_parameters_wait_for_confirmation_and_default_download(
    tmp_path: Path,
) -> None:
    service, database = _service(tmp_path)
    session = service.create_session()
    capture = tmp_path / "download.pcapng"
    capture.write_bytes(b"capture")

    result = asyncio.run(
        service.submit_message(
            session.session_id,
            content=f"分析 {capture}，标准带宽1G，实际带宽20M",
        )
    )

    assert result.parameters is not None
    assert result.parameters.ready_for_confirmation is True
    assert result.parameters.target is Target.DOWNLOAD
    assert result.parameters.missing == []
    assert result.analysis is None
    assert AnalysisTaskRepository(database).count_for_session(session.session_id) == 0
    stored, _ = MessageRepository(database).list(session_id=session.session_id)
    assert str(capture) not in "\n".join(message.content for message in stored)


def test_parameters_can_be_completed_across_turns_and_restart(tmp_path: Path) -> None:
    service, database = _service(tmp_path)
    session = service.create_session()
    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture")

    first = asyncio.run(
        service.submit_message(session.session_id, content=f"请分析 {capture}")
    )
    assert first.parameters.missing == [
        MissingParameter.STANDARD_BANDWIDTH,
        MissingParameter.ACTUAL_BANDWIDTH,
    ]
    second = asyncio.run(
        service.submit_message(session.session_id, content="1000")
    )
    assert second.parameters.missing == [MissingParameter.ACTUAL_BANDWIDTH]

    restored = WebConversationService(
        sessions=SessionRepository(WebDatabase(database.path)),
        messages=MessageRepository(WebDatabase(database.path)),
        intents=PendingIntentRepository(WebDatabase(database.path)),
        captures=CaptureRegistry(
            CaptureRepository(WebDatabase(database.path)), allowed_roots=[tmp_path]
        ),
        tasks=AnalysisTaskRepository(WebDatabase(database.path)),
        model=_Model(),
    )
    third = asyncio.run(
        restored.submit_message(session.session_id, content="20M")
    )
    assert third.parameters.ready_for_confirmation is True
    assert third.parameters.standard_bandwidth_mbps == 1000
    assert third.parameters.actual_bandwidth_mbps == 20


def test_confirmation_is_idempotent(tmp_path: Path) -> None:
    service, database = _service(tmp_path)
    session = service.create_session()
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    registered = service.register_capture(str(capture))
    asyncio.run(
        service.submit_message(
            session.session_id,
            content="标准带宽1000M，实际带宽20M",
            capture_id=registered.capture_id,
        )
    )

    first = service.confirm(session.session_id)
    second = service.confirm(session.session_id)

    assert first.analysis_id == second.analysis_id
    assert first.status is TaskStatus.QUEUED
    assert AnalysisTaskRepository(database).count_for_session(session.session_id) == 1
