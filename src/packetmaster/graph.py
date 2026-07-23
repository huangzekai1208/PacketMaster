"""Bounded LangGraph workflow for evidence-driven TCP speed diagnosis."""

from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph
from pydantic import ValidationError

from packetmaster.analyzer.base import validate_evidence_request
from packetmaster.context import ContextBuilder, DiagnosisContext
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    Confidence,
    CoverageSummary,
    DiagnosticReport,
    EvidenceRequest,
    EvidenceResponse,
    HypothesisBatch,
    Target,
    VerificationResult,
)
from packetmaster.errors import AppError

MAX_EVIDENCE_ROUNDS = 3
MAX_REQUESTS_PER_ROUND = 10


class AgentState(TypedDict, total=False):
    request: AnalyzeRequest | dict[str, Any]
    standard_bandwidth_mbps: float
    actual_bandwidth_mbps: float
    target: Target
    analysis: AnalyzeResponse
    context: DiagnosisContext
    hypotheses: HypothesisBatch
    evidence_requests: list[EvidenceRequest]
    evidence: list[EvidenceResponse]
    verification: VerificationResult
    round_count: int
    report: DiagnosticReport
    error: dict[str, Any]
    trace: list[dict[str, Any]]


def _error_dict(error: Exception, default_code: str) -> dict[str, Any]:
    if isinstance(error, AppError):
        return error.to_dict()
    return AppError(
        code=default_code,
        message="PacketMaster graph node failed",
        recoverable=False,
        suggested_action="Inspect the structured trace and retry.",
        details={"exception_type": error.__class__.__name__},
    ).to_dict()


def _trace(
    state: AgentState,
    node: str,
    *,
    status: str,
    error_code: str | None = None,
    evidence_request_count: int = 0,
) -> list[dict[str, Any]]:
    event = {
        "node": node,
        "round": int(state.get("round_count", 0)),
        "status": status,
        "target": state.get("target", Target.DOWNLOAD).value,
        "error_code": error_code,
        "evidence_request_count": evidence_request_count,
    }
    return [*state.get("trace", []), event]


def build_graph(
    *,
    mcp_client: Any,
    diagnosis_model: Any,
    context_builder: ContextBuilder | None = None,
):
    builder = context_builder or ContextBuilder()

    async def validate(state: AgentState) -> dict[str, Any]:
        try:
            raw = state.get("request", {})
            if isinstance(raw, AnalyzeRequest):
                request = raw
            else:
                values = dict(raw)
                values.setdefault("target", Target.DOWNLOAD.value)
                request = AnalyzeRequest.model_validate(values)
            standard = float(state["standard_bandwidth_mbps"])
            actual = float(state["actual_bandwidth_mbps"])
            if standard <= 0 or actual <= 0:
                raise ValueError("bandwidth values must be positive")
            update: AgentState = {
                "request": request,
                "target": request.target,
                "standard_bandwidth_mbps": standard,
                "actual_bandwidth_mbps": actual,
                "round_count": 0,
                "evidence": [],
                "trace": _trace(
                    {**state, "target": request.target},
                    "validate",
                    status="ok",
                ),
            }
            return update
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            error = _error_dict(exc, "INVALID_REQUEST")
            return {
                "target": Target.DOWNLOAD,
                "error": error,
                "trace": _trace(
                    state,
                    "validate",
                    status="error",
                    error_code=error["code"],
                ),
            }

    async def analyze(state: AgentState) -> dict[str, Any]:
        try:
            response = await mcp_client.analyze_speed_capture(state["request"])
            if response.target is not state["target"]:
                raise AppError(
                    code="TARGET_DRIFT",
                    message="Analyzer target changed during graph execution",
                    recoverable=False,
                    suggested_action="Use a consistent isolated analysis request.",
                )
            return {
                "analysis": response,
                "trace": _trace(state, "analyze", status="ok"),
            }
        except Exception as exc:
            error = _error_dict(exc, "ANALYSIS_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state, "analyze", status="error", error_code=error["code"]
                ),
            }

    async def reason(state: AgentState) -> dict[str, Any]:
        try:
            context = builder.build(
                state["analysis"],
                state.get("evidence", []),
                standard_bandwidth_mbps=state["standard_bandwidth_mbps"],
                actual_bandwidth_mbps=state["actual_bandwidth_mbps"],
            )
            hypotheses = await diagnosis_model.generate_hypotheses(context)
            requests = hypotheses.requested_evidence[:MAX_REQUESTS_PER_ROUND]
            return {
                "context": context,
                "hypotheses": hypotheses,
                "evidence_requests": requests,
                "trace": _trace(
                    state,
                    "reason",
                    status="ok",
                    evidence_request_count=len(requests),
                ),
            }
        except Exception as exc:
            error = _error_dict(exc, "REASONING_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state, "reason", status="error", error_code=error["code"]
                ),
            }

    async def inspect_evidence(state: AgentState) -> dict[str, Any]:
        try:
            responses: list[EvidenceResponse] = []
            requests = state.get("evidence_requests", [])[:MAX_REQUESTS_PER_ROUND]
            for candidate in requests:
                request = EvidenceRequest.model_validate(candidate)
                validate_evidence_request(request)
                responses.append(await mcp_client.get_tcp_evidence(request))
            evidence = [*state.get("evidence", []), *responses]
            round_count = int(state.get("round_count", 0)) + 1
            context = builder.build(
                state["analysis"],
                evidence,
                standard_bandwidth_mbps=state["standard_bandwidth_mbps"],
                actual_bandwidth_mbps=state["actual_bandwidth_mbps"],
            )
            return {
                "evidence": evidence,
                "context": context,
                "round_count": round_count,
                "trace": _trace(
                    {**state, "round_count": round_count},
                    "inspect_evidence",
                    status="ok",
                    evidence_request_count=len(requests),
                ),
            }
        except Exception as exc:
            error = _error_dict(exc, "EVIDENCE_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state,
                    "inspect_evidence",
                    status="error",
                    error_code=error["code"],
                ),
            }

    async def verify(state: AgentState) -> dict[str, Any]:
        try:
            result = await diagnosis_model.verify(
                state["context"],
                state["hypotheses"],
                state.get("evidence", []),
            )
            requests = result.requested_evidence[:MAX_REQUESTS_PER_ROUND]
            return {
                "verification": result,
                "evidence_requests": requests,
                "trace": _trace(
                    state,
                    "verify",
                    status="ok",
                    evidence_request_count=len(requests),
                ),
            }
        except Exception as exc:
            error = _error_dict(exc, "VERIFICATION_FAILED")
            return {
                "error": error,
                "trace": _trace(
                    state, "verify", status="error", error_code=error["code"]
                ),
            }

    async def report(state: AgentState) -> dict[str, Any]:
        verification = state.get("verification")
        hypotheses = state.get("hypotheses", HypothesisBatch())
        accepted = verification.accepted_hypotheses if verification else []
        primary = accepted[0].cause if accepted else "unresolved"
        error = state.get("error")
        limitations = list(verification.limitations if verification else [])
        if error:
            limitations.insert(0, f"{error['code']}: analysis workflow degraded")
        if not accepted and not limitations:
            limitations.append("Evidence is insufficient; result remains unresolved.")
        analysis = state.get("analysis")
        coverage = (
            analysis.coverage_summary
            if analysis is not None
            else CoverageSummary()
        )
        standard = max(float(state.get("standard_bandwidth_mbps", 1.0)), 0.001)
        actual = max(float(state.get("actual_bandwidth_mbps", 1.0)), 0.001)
        diagnostic = DiagnosticReport(
            standard_bandwidth_mbps=standard,
            actual_bandwidth_mbps=actual,
            achievement_ratio_pct=actual / standard * 100,
            target=state.get("target", Target.DOWNLOAD),
            primary_cause=primary,
            candidate_causes=hypotheses.hypotheses,
            key_evidence=[
                {
                    "evidence_type": item.evidence_type,
                    "total": item.total,
                    "truncated": item.truncated,
                }
                for item in state.get("evidence", [])
            ][:20],
            confidence=(
                verification.confidence
                if verification and verification.confidence
                else Confidence.LOW
            ),
            coverage_summary=coverage,
            limitations=limitations,
            troubleshooting_steps=[
                item.suggestion for item in hypotheses.hypotheses if item.suggestion
            ][:20],
            optimization_suggestions=[],
            analysis_metadata={
                "analysis_id": analysis.analysis_id if analysis else None,
                "evidence_rounds": state.get("round_count", 0),
                "error_code": error["code"] if error else None,
            },
        )
        return {
            "report": diagnostic,
            "trace": _trace(
                state,
                "report",
                status="degraded" if error else "ok",
                error_code=error["code"] if error else None,
            ),
        }

    def after_node(state: AgentState) -> str:
        return "report" if state.get("error") else "continue"

    def after_reason(state: AgentState) -> str:
        if state.get("error"):
            return "report"
        return "inspect_evidence" if state.get("evidence_requests") else "report"

    def after_verify(state: AgentState) -> str:
        if state.get("error"):
            return "report"
        if (
            state.get("evidence_requests")
            and state.get("round_count", 0) < MAX_EVIDENCE_ROUNDS
        ):
            return "inspect_evidence"
        return "report"

    graph = StateGraph(AgentState)
    graph.add_node("validate", validate)
    graph.add_node("analyze", analyze)
    graph.add_node("reason", reason)
    graph.add_node("inspect_evidence", inspect_evidence)
    graph.add_node("verify", verify)
    graph.add_node("report", report)
    graph.add_edge(START, "validate")
    graph.add_conditional_edges(
        "validate", after_node, {"continue": "analyze", "report": "report"}
    )
    graph.add_conditional_edges(
        "analyze", after_node, {"continue": "reason", "report": "report"}
    )
    graph.add_conditional_edges(
        "reason",
        after_reason,
        {"inspect_evidence": "inspect_evidence", "report": "report"},
    )
    graph.add_conditional_edges(
        "inspect_evidence",
        after_node,
        {"continue": "verify", "report": "report"},
    )
    graph.add_conditional_edges(
        "verify",
        after_verify,
        {"inspect_evidence": "inspect_evidence", "report": "report"},
    )
    graph.add_edge("report", END)
    return graph.compile()
