from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace

from packetmaster.domain import GeneralChatAnswer, Target
from packetmaster.rag.contracts import KnowledgeBundle, RagMode, RetrievalCandidate
from packetmaster.rag.query import KnowledgeQueryBuilder
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.contracts import AnalysisMode, MissingParameter, TaskStatus
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
        self.knowledge: list[KnowledgeBundle | None] = []

    async def general_chat(
        self, user_text, conversation_summary="", turns=None, knowledge=None
    ):
        self.questions.append(user_text)
        self.knowledge.append(knowledge)
        return GeneralChatAnswer(answer="TCP 是一种面向连接的传输层协议。")


def _service(tmp_path: Path, model=None, rag_runtime=None):
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
        rag_runtime=rag_runtime,
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
    assert SessionRepository(database).get(session.session_id).title == "TCP 是什么"


def test_session_waits_for_meaningful_content_before_generating_title(
    tmp_path: Path,
) -> None:
    service, database = _service(tmp_path)
    session = service.create_session()

    assert session.title == "新会话"
    asyncio.run(service.submit_message(session.session_id, content="你好"))
    assert SessionRepository(database).get(session.session_id).title == "新会话"

    asyncio.run(
        service.submit_message(
            session.session_id, content="请帮我分析 TCP 接收窗口为什么限制吞吐？"
        )
    )

    assert (
        SessionRepository(database).get(session.session_id).title
        == "TCP 接收窗口为什么限制吞吐"
    )


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


def test_general_chat_retrieves_and_injects_active_knowledge(tmp_path: Path) -> None:
    candidate = RetrievalCandidate(
        knowledge_id="rfc.window",
        version_id="rfc.window:v1",
        chunk_id="rfc.window:v1:c1",
        title="TCP 窗口机制",
        knowledge_type="standard",
        authority="high",
        source_name="RFC",
        content="接收窗口会限制在途未确认数据量。",
        rerank_score=0.9412,
    )

    class Retriever:
        def __init__(self) -> None:
            self.calls = 0
            self.reranker = object()

        async def retrieve(self, query):
            self.calls += 1
            return KnowledgeBundle(
                query_id=query.query_id,
                results=[candidate],
                total_content_bytes=len(candidate.content.encode("utf-8")),
            )

    retriever = Retriever()
    runtime = SimpleNamespace(
        mode=RagMode.ACTIVE,
        query_builder=KnowledgeQueryBuilder(),
        retriever=retriever,
    )
    model = _Model()
    service, database = _service(tmp_path, model, runtime)
    session = service.create_session()

    result = asyncio.run(
        service.submit_message(session.session_id, content="TCP 窗口如何影响吞吐？")
    )

    assert retriever.calls == 1
    assert model.knowledge[0] is not None
    assert model.knowledge[0].results[0].chunk_id == candidate.chunk_id
    assert result.assistant_message.rag_status == "used"
    assert result.assistant_message.rag_citations[0].title == "TCP 窗口机制"
    assert result.assistant_message.rag_citations[0].chunk_id == candidate.chunk_id
    assert result.assistant_message.rag_citations[0].reranker_score == 0.9412
    stored, _ = MessageRepository(database).list(session_id=session.session_id)
    assert stored[-1].rag_citations == result.assistant_message.rag_citations


def test_general_chat_reports_rag_degradation_without_blocking_answer(
    tmp_path: Path,
) -> None:
    class Retriever:
        reranker = object()

        async def retrieve(self, query):
            raise RuntimeError("service unavailable")

    runtime = SimpleNamespace(
        mode=RagMode.ACTIVE,
        query_builder=KnowledgeQueryBuilder(),
        retriever=Retriever(),
    )
    model = _Model()
    service, _ = _service(tmp_path, model, runtime)
    session = service.create_session()

    result = asyncio.run(
        service.submit_message(session.session_id, content="TCP 序列号为什么从零开始？")
    )

    assert result.assistant_message.content.startswith("TCP 是")
    assert result.assistant_message.rag_status == "degraded"
    assert result.assistant_message.rag_reason == "RAG_RETRIEVAL_FAILED"
    assert result.assistant_message.rag_citations == []
    assert model.knowledge == [None]


def test_general_chat_does_not_label_rrf_score_as_reranker_score(
    tmp_path: Path,
) -> None:
    candidate = RetrievalCandidate(
        knowledge_id="rfc.window",
        version_id="rfc.window:v1",
        chunk_id="rfc.window:v1:c1",
        title="TCP 窗口机制",
        knowledge_type="standard",
        authority="high",
        source_name="RFC",
        content="接收窗口会限制在途未确认数据量。",
        rerank_score=0.08,
    )

    class Retriever:
        reranker = object()

        async def retrieve(self, query):
            return KnowledgeBundle(
                query_id=query.query_id,
                results=[candidate],
                total_content_bytes=len(candidate.content.encode("utf-8")),
                warnings=["模型重排序降级：RERANK_TIMEOUT"],
            )

    runtime = SimpleNamespace(
        mode=RagMode.ACTIVE,
        query_builder=KnowledgeQueryBuilder(),
        retriever=Retriever(),
    )
    service, _ = _service(tmp_path, _Model(), runtime)
    session = service.create_session()

    result = asyncio.run(
        service.submit_message(session.session_id, content="TCP 窗口如何影响吞吐？")
    )

    assert result.assistant_message.rag_status == "degraded"
    assert result.assistant_message.rag_citations[0].reranker_score is None


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


def test_stall_mode_does_not_request_bandwidth(tmp_path: Path) -> None:
    service, _database = _service(tmp_path)
    session = service.create_session()
    capture = tmp_path / "stall.pcapng"
    capture.write_bytes(b"capture")
    registered = service.register_capture(str(capture))

    result = asyncio.run(
        service.submit_message(
            session.session_id,
            content="观看视频时出现卡顿",
            capture_id=registered.capture_id,
            mode=AnalysisMode.STALL,
        )
    )

    assert result.parameters is not None
    assert result.parameters.mode is AnalysisMode.STALL
    assert result.parameters.missing == []
    assert result.parameters.ready_for_confirmation is False
    assert result.assistant_message.content.startswith("已选择通用卡顿分析")
    assert "请提供标准带宽" not in result.assistant_message.content


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
