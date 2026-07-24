"""Bounded evidence question graph for the PacketMaster CLI chat."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from packetmaster.analyzer.base import validate_evidence_request
from packetmaster.chat import build_model_context, validate_question
from packetmaster.domain import (
    ChatAnswer,
    ChatSessionState,
    EvidenceRequest,
    EvidenceResponse,
)
from packetmaster.errors import AppError

MAX_CHAT_INSPECTIONS = 2
MAX_CHAT_REQUESTS_PER_INSPECTION = 5


class ChatGraphState(TypedDict, total=False):
    session: ChatSessionState
    question: str
    answer: ChatAnswer
    evidence: list[EvidenceResponse]
    inspection_count: int
    error: dict[str, Any]
    trace: list[dict[str, Any]]


def _error_dict(error: Exception) -> dict[str, Any]:
    if isinstance(error, AppError):
        return error.to_dict()
    return AppError(
        code="CHAT_GRAPH_FAILED",
        message="PacketMaster 问答流程失败",
        recoverable=True,
        suggested_action="查看当前报告或重试当前问题。",
        details={"exception_type": error.__class__.__name__},
    ).to_dict()


def _trace(
    state: ChatGraphState, node: str, status: str, **extra: Any
) -> list[dict[str, Any]]:
    return [
        *state.get("trace", []),
        {"node": node, "status": status, **extra},
    ]


def build_chat_graph(*, mcp_client: Any, diagnosis_model: Any):
    async def prepare_question(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = ChatSessionState.model_validate(state["session"])
            question = validate_question(state.get("question", session.question or ""))
            if not session.analysis_id:
                raise AppError(
                    code="CHAT_ANALYSIS_REQUIRED",
                    message="当前会话还没有完成报文分析",
                    recoverable=True,
                    suggested_action="先完成一次诊断，再提出证据问题。",
                )
            session.question = question
            return {
                "session": session,
                "question": question,
                "inspection_count": 0,
                "evidence": [],
                "trace": _trace(state, "prepare_question", "ok"),
            }
        except Exception as exc:
            return {
                "error": _error_dict(exc),
                "trace": _trace(state, "prepare_question", "error"),
            }

    async def answer_question(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            context = build_model_context(session)
            answer = await diagnosis_model.answer_question(context)
            return {
                "answer": answer,
                "trace": _trace(state, "answer_question", "ok"),
            }
        except Exception as exc:
            return {
                "error": _error_dict(exc),
                "trace": _trace(state, "answer_question", "error"),
            }

    async def inspect_question_evidence(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            answer = state["answer"]
            responses: list[EvidenceResponse] = []
            for candidate in answer.requested_evidence[
                :MAX_CHAT_REQUESTS_PER_INSPECTION
            ]:
                request = EvidenceRequest.model_validate(candidate)
                validate_evidence_request(request)
                if request.analysis_id != session.analysis_id:
                    raise AppError(
                        code="EVIDENCE_ANALYSIS_MISMATCH",
                        message="证据请求指向了其他分析任务",
                        recoverable=False,
                        suggested_action="只使用当前会话的 analysis_id。",
                    )
                responses.append(await mcp_client.get_tcp_evidence(request))
            count = state.get("inspection_count", 0) + 1
            return {
                "evidence": [*state.get("evidence", []), *responses],
                "inspection_count": count,
                "trace": _trace(
                    state,
                    "inspect_question_evidence",
                    "ok",
                    request_count=len(responses),
                ),
            }
        except Exception as exc:
            return {
                "error": _error_dict(exc),
                "trace": _trace(state, "inspect_question_evidence", "error"),
            }

    async def verify_answer(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            context = build_model_context(session)
            answer = await diagnosis_model.verify_chat_answer(
                context, state["answer"], state.get("evidence", [])
            )
            return {
                "answer": answer,
                "trace": _trace(state, "verify_answer", "ok"),
            }
        except Exception as exc:
            return {
                "error": _error_dict(exc),
                "trace": _trace(state, "verify_answer", "error"),
            }

    async def finalize_answer(state: ChatGraphState) -> dict[str, Any]:
        return {"trace": _trace(state, "finalize_answer", "ok")}

    def after_prepare(state: ChatGraphState) -> str:
        return "error" if state.get("error") else "answer"

    def after_answer(state: ChatGraphState) -> str:
        if state.get("error"):
            return "finalize"
        answer = state.get("answer")
        if (
            answer
            and answer.requested_evidence
            and state.get("inspection_count", 0) < MAX_CHAT_INSPECTIONS
        ):
            return "inspect"
        return "finalize"

    def after_inspect(state: ChatGraphState) -> str:
        return "finalize" if state.get("error") else "verify"

    def after_verify(state: ChatGraphState) -> str:
        answer = state.get("answer")
        if (
            not state.get("error")
            and answer
            and answer.requested_evidence
            and state.get("inspection_count", 0) < MAX_CHAT_INSPECTIONS
        ):
            return "inspect"
        return "finalize"

    graph = StateGraph(ChatGraphState)
    graph.add_node("prepare_question", prepare_question)
    graph.add_node("answer_question", answer_question)
    graph.add_node("inspect_question_evidence", inspect_question_evidence)
    graph.add_node("verify_answer", verify_answer)
    graph.add_node("finalize_answer", finalize_answer)
    graph.add_edge(START, "prepare_question")
    graph.add_conditional_edges(
        "prepare_question",
        after_prepare,
        {"answer": "answer_question", "error": "finalize_answer"},
    )
    graph.add_conditional_edges(
        "answer_question",
        after_answer,
        {"inspect": "inspect_question_evidence", "finalize": "finalize_answer"},
    )
    graph.add_conditional_edges(
        "inspect_question_evidence",
        after_inspect,
        {"verify": "verify_answer", "finalize": "finalize_answer"},
    )
    graph.add_conditional_edges(
        "verify_answer",
        after_verify,
        {"inspect": "inspect_question_evidence", "finalize": "finalize_answer"},
    )
    graph.add_edge("finalize_answer", END)
    return graph.compile()
