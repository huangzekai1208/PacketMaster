"""已完成 Web 分析的持久化追问服务，回答仅使用有界证据。"""

from __future__ import annotations

from typing import Any

from packetmaster.chat_graph import build_chat_graph
from packetmaster.domain import ChatSessionState, ConversationTurn
from packetmaster.errors import AppError
from packetmaster.web.analysis import AnalysisReadService
from packetmaster.web.contracts import ChatTurnResult, Page, TaskStatus
from packetmaster.web.conversation import redact_message
from packetmaster.web.database import ChatTurnRepository


class _EvidenceClient:
    def __init__(self, reads: AnalysisReadService) -> None:
        self.reads = reads

    async def get_tcp_evidence(self, request):
        return await self.reads.evidence(request)


class AnalysisChatService:
    def __init__(
        self,
        *,
        reads: AnalysisReadService,
        turns: ChatTurnRepository,
        model: Any,
        rag_runtime: Any | None = None,
    ) -> None:
        self.reads = reads
        self.turns = turns
        self.model = model
        self.rag_runtime = rag_runtime

    async def ask(self, analysis_id: str, question: str) -> ChatTurnResult:
        detail = self.reads.detail(analysis_id)
        if detail.analysis.status not in {TaskStatus.COMPLETED, TaskStatus.PARTIAL}:
            raise AppError(
                code="CHAT_ANALYSIS_NOT_READY",
                message="诊断报告尚未完成，暂时不能进行证据问答",
                recoverable=True,
                suggested_action="请等待报告生成后再提问。",
            )
        safe_question = redact_message(question)
        history, _ = self.turns.list(analysis_id, limit=50)
        report = self.reads.report(analysis_id).report
        session = ChatSessionState(
            session_id=detail.analysis.session_id,
            analysis_id=analysis_id,
            target=detail.analysis.target,
            report=report,
            diagnosis_context=self.reads.metrics(analysis_id).model_dump(mode="json"),
            conversation_turns=[
                ConversationTurn(question=item.question, answer=item.answer)
                for item in history[-8:]
            ],
            question=safe_question,
        )
        graph = build_chat_graph(
            mcp_client=_EvidenceClient(self.reads),
            diagnosis_model=self.model,
            rag_runtime=self.rag_runtime,
        )
        result = await graph.ainvoke({"session": session})
        answer = result.get("answer")
        if answer is None:
            raise AppError(
                code="CHAT_ANSWER_UNAVAILABLE",
                message="本次问答没有生成可用回答",
                recoverable=True,
                suggested_action="请稍后重试或直接查看诊断报告。",
            )
        return self.turns.append(
            session_id=detail.analysis.session_id,
            analysis_id=analysis_id,
            question=safe_question,
            answer=redact_message(answer.answer),
            citations=[item.model_dump(mode="json") for item in answer.evidence_basis],
            knowledge_citations=answer.knowledge_citations,
            limitations=answer.limitations,
            suggestions=answer.follow_up_suggestions,
        )

    def history(
        self, analysis_id: str, *, offset: int = 0, limit: int = 50
    ) -> Page[ChatTurnResult]:
        self.reads.detail(analysis_id)
        items, total = self.turns.list(analysis_id, offset=offset, limit=limit)
        return Page(items=items, total=total, offset=offset, limit=limit)
