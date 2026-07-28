"""单轮报告追问的证据驱动图，限制检索与模型上下文范围。"""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from packetmaster.analyzer.base import validate_evidence_request
from packetmaster.chat import ChatSession, build_model_context, validate_question
from packetmaster.context import bounded_evidence
from packetmaster.domain import (
    ChatAnswer,
    ChatSessionState,
    EvidenceRequest,
    EvidenceResponse,
)
from packetmaster.errors import AppError
from packetmaster.rag.contracts import (
    KnowledgeBundle,
    KnowledgeCitation,
    KnowledgeQuery,
    RagMode,
)

MAX_CHAT_EVIDENCE_ROUNDS = 2
MAX_CHAT_REQUESTS_PER_ROUND = 5


class ChatGraphState(TypedDict, total=False):
    session: ChatSessionState
    evidence: list[EvidenceResponse]
    answer: ChatAnswer
    knowledge_query: KnowledgeQuery
    knowledge_bundle: KnowledgeBundle
    rag_mode: RagMode
    rag_warning: str
    round_count: int
    error: dict[str, Any]
    trace: list[dict[str, Any]]


def _error_dict(error: Exception, default_code: str) -> dict[str, Any]:
    if isinstance(error, AppError):
        return error.to_dict()
    return AppError(
        code=default_code,
        message="Chat question processing failed",
        recoverable=True,
        suggested_action="Retry the question or inspect the current report.",
        details={"exception_type": error.__class__.__name__},
    ).to_dict()


def _trace(
    state: ChatGraphState,
    node: str,
    *,
    status: str,
    error_code: str | None = None,
    evidence_request_count: int = 0,
) -> list[dict[str, Any]]:
    return [
        *state.get("trace", []),
        {
            "node": node,
            "round": int(state.get("round_count", 0)),
            "status": status,
            "error_code": error_code,
            "evidence_request_count": evidence_request_count,
        },
    ]


def _validated_requests(
    session: ChatSessionState, requests: list[EvidenceRequest]
) -> list[EvidenceRequest]:
    if not session.analysis_id:
        raise AppError(
            code="CHAT_ANALYSIS_UNAVAILABLE",
            message="Chat session has no active analysis",
            recoverable=True,
            suggested_action="Start a new diagnosis before asking a question.",
        )
    validated: list[EvidenceRequest] = []
    for request in requests[:MAX_CHAT_REQUESTS_PER_ROUND]:
        item = EvidenceRequest.model_validate(request)
        validate_evidence_request(item)
        if item.analysis_id != session.analysis_id:
            raise AppError(
                code="EVIDENCE_ANALYSIS_MISMATCH",
                message="Chat evidence request targets another analysis",
                recoverable=False,
                suggested_action="Use evidence from the active chat analysis.",
            )
        validated.append(item)
    return validated


def _safe_evidence_layers(evidence: list[EvidenceResponse]) -> list[dict[str, Any]]:
    layers = bounded_evidence(evidence)
    return [
        {"evidence_type": evidence_type, **layer}
        for evidence_type, layer in layers.items()
    ]


def _question_needs_knowledge(question: str) -> bool:
    text = question.casefold()
    knowledge_markers = (
        "为什么",
        "原理",
        "机制",
        "如何",
        "怎么",
        "建议",
        "处置",
        "处理",
        "优化",
        "相似",
        "案例",
        "经验",
        "规范",
        "rfc",
        "拥塞控制",
        "window scaling",
    )
    concrete_markers = (
        "哪一帧",
        "哪些帧",
        "帧号",
        "哪条流",
        "哪些流",
        "时间点",
        "当前哪个",
        "当前多少",
    )
    if any(marker in text for marker in concrete_markers) and not any(
        marker in text for marker in knowledge_markers
    ):
        return False
    return any(marker in text for marker in knowledge_markers)


def build_chat_graph(
    *, mcp_client: Any, diagnosis_model: Any, rag_runtime: Any | None = None
):
    """Build a chat graph that can only inspect bounded local evidence."""

    async def prepare_question(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            session.question = validate_question(session.question or "")
            if not session.analysis_id:
                raise AppError(
                    code="CHAT_ANALYSIS_UNAVAILABLE",
                    message="Chat session has no active analysis",
                    recoverable=True,
                    suggested_action="Start a new diagnosis before asking a question.",
                )
            session.requested_evidence = []
            session.collected_evidence = []
            session.answer = None
            session.error = None
            return {
                "session": session,
                "evidence": [],
                "round_count": 0,
                "trace": _trace(state, "prepare_question", status="ok"),
            }
        except Exception as exc:
            error = _error_dict(exc, "INVALID_CHAT_QUESTION")
            return {
                "error": error,
                "trace": _trace(
                    state,
                    "prepare_question",
                    status="error",
                    error_code=error["code"],
                ),
            }

    def model_context(
        state: ChatGraphState, *, include_knowledge: bool = True
    ):
        context = build_model_context(state["session"])
        bundle = state.get("knowledge_bundle")
        if (
            include_knowledge
            and state.get("rag_mode") is RagMode.ACTIVE
            and bundle is not None
            and bundle.results
        ):
            return context.model_copy(
                update={"knowledge_context": bundle.model_dump(mode="json")}
            )
        return context

    async def retrieve_question_knowledge(
        state: ChatGraphState,
    ) -> dict[str, Any]:
        if rag_runtime is None or not _question_needs_knowledge(
            state["session"].question or ""
        ):
            return {
                "trace": _trace(
                    state, "retrieve_question_knowledge", status="skipped"
                )
            }
        mode = rag_runtime.mode
        try:
            query = rag_runtime.query_builder.build_chat(
                build_model_context(state["session"])
            )
            if query is None:
                return {
                    "rag_mode": mode,
                    "trace": _trace(
                        state, "retrieve_question_knowledge", status="skipped"
                    ),
                }
            bundle = await rag_runtime.retriever.retrieve(query)
            warning = rag_runtime.degradation_reason
            if bundle.warnings:
                warning = ";".join(bundle.warnings)
            update: dict[str, Any] = {
                "knowledge_query": query,
                "knowledge_bundle": bundle,
                "rag_mode": mode,
                "trace": _trace(
                    state,
                    "retrieve_question_knowledge",
                    status="degraded" if warning else "ok",
                ),
            }
            if warning:
                update["rag_warning"] = warning
            return update
        except Exception as exc:
            code = exc.code if isinstance(exc, AppError) else "RAG_RETRIEVAL_FAILED"
            return {
                "rag_mode": mode,
                "rag_warning": code,
                "trace": _trace(
                    state,
                    "retrieve_question_knowledge",
                    status="degraded",
                    error_code=code,
                ),
            }

    async def validate_knowledge_answer(
        state: ChatGraphState, answer: ChatAnswer
    ) -> ChatAnswer | None:
        bundle = state.get("knowledge_bundle")
        query = state.get("knowledge_query")
        if (
            state.get("rag_mode") is not RagMode.ACTIVE
            or bundle is None
            or query is None
            or not bundle.results
        ):
            return answer.model_copy(update={"knowledge_citations": []})
        try:
            citations = [
                KnowledgeCitation.model_validate(item)
                for item in answer.knowledge_citations
            ]
            if not citations:
                return None
            validation = await rag_runtime.citation_validator.validate(
                citations, bundle, query
            )
            if len(validation.valid_citations) != len(citations):
                return None
            return answer.model_copy(
                update={
                    "knowledge_citations": [
                        item.model_dump(mode="json")
                        for item in validation.valid_citations
                    ]
                }
            )
        except Exception:
            return None

    async def answer_question(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            answer = await diagnosis_model.answer_question(model_context(state))
            validated = await validate_knowledge_answer(state, answer)
            warning = state.get("rag_warning")
            if validated is None:
                answer = await diagnosis_model.answer_question(
                    model_context(state, include_knowledge=False)
                )
                warning = "RAG_CITATION_VALIDATION_FAILED"
            else:
                answer = validated
            requests = [] if answer.ready else _validated_requests(
                session, answer.requested_evidence
            )
            session.requested_evidence = requests
            update = {
                "session": session,
                "answer": answer,
                "trace": _trace(
                    state,
                    "answer_question",
                    status="ok",
                    evidence_request_count=len(requests),
                ),
            }
            if warning:
                update["rag_warning"] = warning
            return update
        except Exception as exc:
            error = _error_dict(exc, "CHAT_MODEL_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state,
                    "answer_question",
                    status="error",
                    error_code=error["code"],
                ),
            }

    async def inspect_evidence(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            responses: list[EvidenceResponse] = []
            for request in session.requested_evidence:
                response = await mcp_client.get_tcp_evidence(request)
                if (
                    response.analysis_id != session.analysis_id
                    or response.evidence_type != request.evidence_type
                    or len(response.items) > request.limit
                ):
                    raise AppError(
                        code="INVALID_EVIDENCE_OUTPUT",
                        message="Chat evidence response violates the request contract",
                        recoverable=False,
                        suggested_action="Check the MCP evidence adapter.",
                    )
                responses.append(response)
            evidence = [*state.get("evidence", []), *responses]
            session.collected_evidence = _safe_evidence_layers(evidence)
            round_count = int(state.get("round_count", 0)) + 1
            return {
                "session": session,
                "evidence": evidence,
                "round_count": round_count,
                "trace": _trace(
                    {**state, "round_count": round_count},
                    "inspect_question_evidence",
                    status="ok",
                    evidence_request_count=len(responses),
                ),
            }
        except Exception as exc:
            error = _error_dict(exc, "CHAT_EVIDENCE_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state,
                    "inspect_question_evidence",
                    status="error",
                    error_code=error["code"],
                ),
            }

    async def verify_answer(state: ChatGraphState) -> dict[str, Any]:
        try:
            session = state["session"]
            answer = await diagnosis_model.verify_chat_answer(
                model_context(state), state["answer"], state.get("evidence", [])
            )
            validated = await validate_knowledge_answer(state, answer)
            warning = state.get("rag_warning")
            if validated is None:
                answer = await diagnosis_model.verify_chat_answer(
                    model_context(state, include_knowledge=False),
                    state["answer"].model_copy(
                        update={"knowledge_citations": []}
                    ),
                    state.get("evidence", []),
                )
                warning = "RAG_CITATION_VALIDATION_FAILED"
            else:
                answer = validated
            requests = [] if answer.ready else _validated_requests(
                session, answer.requested_evidence
            )
            if int(state.get("round_count", 0)) >= MAX_CHAT_EVIDENCE_ROUNDS:
                answer = answer.model_copy(
                    update={
                        "ready": True,
                        "requested_evidence": [],
                        "limitations": [
                            *answer.limitations,
                            "已达到本问题的证据查询轮次上限。",
                        ],
                    }
                )
                requests = []
            session.requested_evidence = requests
            update = {
                "session": session,
                "answer": answer,
                "trace": _trace(
                    state,
                    "verify_answer",
                    status="ok",
                    evidence_request_count=len(requests),
                ),
            }
            if warning:
                update["rag_warning"] = warning
            return update
        except Exception as exc:
            error = _error_dict(exc, "CHAT_VERIFICATION_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state,
                    "verify_answer",
                    status="error",
                    error_code=error["code"],
                ),
            }

    async def finalize_answer(state: ChatGraphState) -> dict[str, Any]:
        session = state.get("session")
        error = state.get("error")
        answer = state.get("answer")
        if session is None:
            return {
                "trace": _trace(
                    state,
                    "finalize_answer",
                    status="error",
                    error_code=error["code"] if error else "CHAT_SESSION_UNAVAILABLE",
                )
            }
        if answer is None:
            answer = ChatAnswer(
                answer="本次问答暂时无法完成，请检查当前报告或稍后重试。",
                limitations=[
                    f"{error['code']}：本次问答未能完成。"
                    if error
                    else "当前问答没有可用结果。"
                ],
                ready=True,
            )
        if state.get("rag_warning"):
            limitation = f"{state['rag_warning']}：知识检索已降级。"
            if limitation not in answer.limitations:
                answer = answer.model_copy(
                    update={"limitations": [*answer.limitations, limitation]}
                )
        session.answer = answer
        session.requested_evidence = []
        if session.question:
            ChatSession(session).append_turn(session.question, answer.answer)
        return {
            "session": session,
            "answer": answer,
            "trace": _trace(
                state,
                "finalize_answer",
                status="degraded" if error else "ok",
                error_code=error["code"] if error else None,
            ),
        }

    def after_prepare(state: ChatGraphState) -> str:
        if state.get("error"):
            return "finalize"
        return "retrieve" if rag_runtime is not None else "answer"

    def after_answer(state: ChatGraphState) -> str:
        if state.get("error"):
            return "finalize"
        if state["answer"].ready or not state["session"].requested_evidence:
            return "finalize"
        return "inspect"

    def after_verify(state: ChatGraphState) -> str:
        if state.get("error"):
            return "finalize"
        if state["answer"].ready or not state["session"].requested_evidence:
            return "finalize"
        return "inspect"

    graph = StateGraph(ChatGraphState)
    graph.add_node("prepare_question", prepare_question)
    graph.add_node("retrieve_question_knowledge", retrieve_question_knowledge)
    graph.add_node("answer_question", answer_question)
    graph.add_node("inspect_question_evidence", inspect_evidence)
    graph.add_node("verify_answer", verify_answer)
    graph.add_node("finalize_answer", finalize_answer)
    graph.add_edge(START, "prepare_question")
    graph.add_conditional_edges(
        "prepare_question",
        after_prepare,
        {
            "retrieve": "retrieve_question_knowledge",
            "answer": "answer_question",
            "finalize": "finalize_answer",
        },
    )
    graph.add_edge("retrieve_question_knowledge", "answer_question")
    graph.add_conditional_edges(
        "answer_question",
        after_answer,
        {"inspect": "inspect_question_evidence", "finalize": "finalize_answer"},
    )
    graph.add_edge("inspect_question_evidence", "verify_answer")
    graph.add_conditional_edges(
        "verify_answer",
        after_verify,
        {"inspect": "inspect_question_evidence", "finalize": "finalize_answer"},
    )
    graph.add_edge("finalize_answer", END)
    return graph.compile()
