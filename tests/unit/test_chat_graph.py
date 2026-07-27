from __future__ import annotations

import asyncio
from types import SimpleNamespace

from packetmaster.chat_graph import build_chat_graph
from packetmaster.domain import ChatAnswer, ChatSessionState, EvidenceRequest, Target
from packetmaster.rag.contracts import (
    KnowledgeBundle,
    KnowledgeCitation,
    RagMode,
    RetrievalCandidate,
)
from packetmaster.rag.query import KnowledgeQueryBuilder
from packetmaster.rag.validation import KnowledgeCitationValidator
from tests.fakes import FakeMCPClient


def _session() -> ChatSessionState:
    return ChatSessionState(
        session_id="chat-1",
        analysis_id="analysis-1",
        target=Target.DOWNLOAD,
        question="主因是什么？",
        report={"primary_cause": "接收端窗口受限"},
        diagnosis_context={"global_metrics": {"zero_window_count": 2}},
    )


class _ChatModel:
    def __init__(self, *, request_forever: bool = False) -> None:
        self.request_forever = request_forever
        self.answer_calls = 0
        self.verify_calls = 0

    @staticmethod
    def _request() -> EvidenceRequest:
        return EvidenceRequest(
            analysis_id="analysis-1",
            evidence_type="zero_window",
            fields=["evidence_id", "frame.number"],
        )

    async def answer_question(self, context):
        self.answer_calls += 1
        assert context.diagnosis_context["global_metrics"]["zero_window_count"] == 2
        return ChatAnswer(
            answer="需要确认零窗口的具体位置。",
            requested_evidence=[self._request()],
            ready=False,
        )

    async def verify_chat_answer(self, context, answer, evidence):
        self.verify_calls += 1
        return ChatAnswer(
            answer="零窗口事件支持接收端窗口受限的判断。",
            requested_evidence=[self._request()] if self.request_forever else [],
            ready=not self.request_forever,
        )


def _rag_runtime():
    candidate = RetrievalCandidate(
        knowledge_id="rfc.window",
        version_id="rfc.window:v1",
        chunk_id="rfc.window:v1:c1",
        title="TCP 窗口机制",
        knowledge_type="standard",
        authority="high",
        source_name="RFC",
        content="接收窗口会限制在途未确认数据量。",
    )

    class Retriever:
        def __init__(self):
            self.calls = 0

        async def retrieve(self, query):
            self.calls += 1
            return KnowledgeBundle(
                query_id=query.query_id,
                results=[candidate],
                total_content_bytes=len(candidate.content.encode("utf-8")),
            )

    class Store:
        async def get_candidate(self, chunk_id):
            return candidate if chunk_id == candidate.chunk_id else None

    retriever = Retriever()
    return SimpleNamespace(
        mode=RagMode.ACTIVE,
        query_builder=KnowledgeQueryBuilder(),
        retriever=retriever,
        citation_validator=KnowledgeCitationValidator(Store()),
        degradation_reason=None,
    )


class _KnowledgeChatModel:
    def __init__(self, *, forged: bool = False) -> None:
        self.forged = forged
        self.contexts = []

    async def answer_question(self, context):
        self.contexts.append(context)
        if not context.knowledge_context:
            return ChatAnswer(answer="当前报告未直接解释该协议机制。", ready=True)
        citation = KnowledgeCitation(
            knowledge_id="rfc.window",
            version_id="rfc.window:v1",
            chunk_id="rfc.window:v1:c1",
            title="TCP 窗口机制",
            knowledge_type="standard",
            source_name="RFC",
            supported_statement="接收窗口限制在途数据量",
            supporting_quote=(
                "不存在的引文"
                if self.forged
                else "接收窗口会限制在途未确认数据量"
            ),
        )
        return ChatAnswer(
            answer="知识经验表明，接收窗口会限制在途数据量。",
            knowledge_citations=[citation.model_dump(mode="json")],
            ready=True,
        )

def test_chat_graph_answers_with_one_evidence_round_without_reanalysis() -> None:
    mcp = FakeMCPClient()
    model = _ChatModel()
    graph = build_chat_graph(mcp_client=mcp, diagnosis_model=model)

    result = asyncio.run(graph.ainvoke({"session": _session()}))

    assert model.answer_calls == 1
    assert model.verify_calls == 1
    assert len(mcp.evidence_calls) == 1
    assert result["answer"].ready is True
    assert result["session"].conversation_turns[-1].answer.startswith("零窗口")
    assert [event["node"] for event in result["trace"]] == [
        "prepare_question",
        "answer_question",
        "inspect_question_evidence",
        "verify_answer",
        "finalize_answer",
    ]


def test_chat_graph_caps_evidence_at_two_rounds() -> None:
    mcp = FakeMCPClient()
    graph = build_chat_graph(
        mcp_client=mcp, diagnosis_model=_ChatModel(request_forever=True)
    )

    result = asyncio.run(graph.ainvoke({"session": _session()}))

    assert result["round_count"] == 2
    assert len(mcp.evidence_calls) == 2
    assert result["answer"].ready is True
    assert "轮次上限" in result["answer"].limitations[-1]


def test_chat_graph_rejects_cross_analysis_evidence_request() -> None:
    class _CrossAnalysisModel(_ChatModel):
        async def answer_question(self, context):
            return ChatAnswer(
                answer="需要额外证据。",
                requested_evidence=[
                    EvidenceRequest(analysis_id="other", evidence_type="events")
                ],
                ready=False,
            )

    graph = build_chat_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=_CrossAnalysisModel()
    )
    result = asyncio.run(graph.ainvoke({"session": _session()}))

    assert result["error"]["code"] == "EVIDENCE_ANALYSIS_MISMATCH"
    assert result["answer"].ready is True
    assert result["trace"][-1]["status"] == "degraded"


def test_chat_graph_retrieves_knowledge_for_protocol_mechanism_question() -> None:
    session = _session()
    session.question = "为什么接收窗口会限制吞吐？"
    runtime = _rag_runtime()
    model = _KnowledgeChatModel()
    graph = build_chat_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=model,
        rag_runtime=runtime,
    )

    result = asyncio.run(graph.ainvoke({"session": session}))

    assert runtime.retriever.calls == 1
    assert model.contexts[0].knowledge_context["results"][0]["chunk_id"] == (
        "rfc.window:v1:c1"
    )
    assert result["answer"].knowledge_citations[0]["source_name"] == "RFC"


def test_chat_graph_keeps_concrete_flow_question_on_packet_evidence_path() -> None:
    session = _session()
    session.question = "当前哪条流发生 Zero Window？"
    runtime = _rag_runtime()
    graph = build_chat_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=_ChatModel(),
        rag_runtime=runtime,
    )

    result = asyncio.run(graph.ainvoke({"session": session}))

    assert runtime.retriever.calls == 0
    assert result["answer"].answer.startswith("零窗口事件")


def test_chat_graph_retries_without_rag_when_knowledge_citation_is_invalid() -> None:
    session = _session()
    session.question = "为什么接收窗口会限制吞吐？"
    model = _KnowledgeChatModel(forged=True)
    graph = build_chat_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=model,
        rag_runtime=_rag_runtime(),
    )

    result = asyncio.run(graph.ainvoke({"session": session}))

    assert len(model.contexts) == 2
    assert model.contexts[0].knowledge_context
    assert model.contexts[1].knowledge_context == {}
    assert result["answer"].answer == "当前报告未直接解释该协议机制。"
    assert "RAG_CITATION_VALIDATION_FAILED" in result["answer"].limitations[-1]
