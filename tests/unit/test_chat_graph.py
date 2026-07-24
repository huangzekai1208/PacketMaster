import asyncio

from packetmaster.chat_graph import build_chat_graph
from packetmaster.domain import ChatAnswer, ChatSessionState, EvidenceRequest, Target


class _MCP:
    def __init__(self):
        self.calls = []

    async def get_tcp_evidence(self, request):
        self.calls.append(request)
        return {
            "analysis_id": request.analysis_id,
            "evidence_type": request.evidence_type,
            "items": [{"evidence_id": "ev-1"}],
            "total": 1,
        }


class _Model:
    def __init__(self, request=False):
        self.request = request
        self.answer_calls = 0
        self.verify_calls = 0

    async def answer_question(self, context):
        self.answer_calls += 1
        return ChatAnswer(
            answer="需要查看重传证据。",
            requested_evidence=(
                [
                    EvidenceRequest(
                        analysis_id="analysis-1", evidence_type="retransmission"
                    )
                ]
                if self.request
                else []
            ),
            ready=not self.request,
        )

    async def verify_chat_answer(self, context, answer, evidence):
        self.verify_calls += 1
        if self.request and self.verify_calls == 1:
            return ChatAnswer(
                answer="仍需第二页证据。",
                requested_evidence=[
                    EvidenceRequest(
                        analysis_id="analysis-1", evidence_type="retransmission"
                    )
                ],
            )
        return ChatAnswer(answer="证据显示存在重传。", ready=True)


def _state() -> ChatSessionState:
    return ChatSessionState(
        session_id="session-1",
        analysis_id="analysis-1",
        target=Target.DOWNLOAD,
        question="主因是什么？",
    )


def test_chat_graph_answers_without_evidence_request() -> None:
    model = _Model()
    result = asyncio.run(
        build_chat_graph(mcp_client=_MCP(), diagnosis_model=model).ainvoke(
            {"session": _state()}
        )
    )

    assert result["answer"].ready is True
    assert model.answer_calls == 1
    assert model.verify_calls == 0


def test_chat_graph_limits_evidence_to_two_rounds() -> None:
    mcp = _MCP()
    model = _Model(request=True)
    result = asyncio.run(
        build_chat_graph(mcp_client=mcp, diagnosis_model=model).ainvoke(
            {"session": _state()}
        )
    )

    assert len(mcp.calls) == 2
    assert result["inspection_count"] == 2
    assert model.answer_calls == 1
    assert model.verify_calls == 2


def test_chat_graph_rejects_cross_analysis_evidence_request() -> None:
    class CrossModel(_Model):
        async def answer_question(self, context):
            return ChatAnswer(
                answer="需要证据。",
                requested_evidence=[
                    EvidenceRequest(analysis_id="other", evidence_type="summary")
                ],
            )

    result = asyncio.run(
        build_chat_graph(mcp_client=_MCP(), diagnosis_model=CrossModel()).ainvoke(
            {"session": _state()}
        )
    )

    assert result["error"]["code"] == "EVIDENCE_ANALYSIS_MISMATCH"
