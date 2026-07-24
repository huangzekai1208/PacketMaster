from __future__ import annotations

import asyncio

from packetmaster.chat_graph import build_chat_graph
from packetmaster.domain import ChatAnswer, ChatSessionState, EvidenceRequest, Target
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
