"""Bounded LangGraph workflow for evidence-driven TCP speed diagnosis."""

from __future__ import annotations

import json
import math
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
MAX_EVIDENCE_RESPONSE_BYTES = 1_000_000


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


def _positive_float(value: Any, default: float = 1.0) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 and math.isfinite(parsed) else default


def _trace(
    state: AgentState,
    node: str,
    *,
    status: str,
    error_code: str | None = None,
    evidence_request_count: int = 0,
) -> list[dict[str, Any]]:
    raw_target = state.get("target", Target.DOWNLOAD)
    try:
        target = Target(raw_target).value
    except (TypeError, ValueError):
        target = Target.DOWNLOAD.value
    event = {
        "node": node,
        "round": int(state.get("round_count", 0)),
        "status": status,
        "target": target,
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

    def normalize_requests(
        state: AgentState, candidates: list[EvidenceRequest]
    ) -> list[EvidenceRequest]:
        normalized: list[EvidenceRequest] = []
        current_keys: set[str] = set()
        analysis_id = state["analysis"].analysis_id
        for candidate in candidates[:MAX_REQUESTS_PER_ROUND]:
            request = EvidenceRequest.model_validate(candidate)
            validate_evidence_request(request)
            if request.analysis_id != analysis_id:
                raise AppError(
                    code="EVIDENCE_ANALYSIS_MISMATCH",
                    message="Evidence request targets another analysis",
                    recoverable=False,
                    suggested_action="Use the active analysis_id.",
                )
            identity = request.model_dump(mode="json")
            identity.update(offset=0, limit=0)
            query_key = json.dumps(identity, sort_keys=True, separators=(",", ":"))
            if query_key in current_keys:
                continue
            current_keys.add(query_key)
            previous = [
                item
                for item in state.get("evidence", [])
                if item.coverage_range.get("query_key") == query_key
            ]
            if previous and request.offset <= int(
                previous[-1].coverage_range.get("offset", 0)
            ):
                if previous[-1].next_offset is None:
                    continue
                request = request.model_copy(
                    update={"offset": previous[-1].next_offset}
                )
            normalized.append(request)
        return normalized

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
            requests = normalize_requests(state, hypotheses.requested_evidence)
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
                response = await mcp_client.get_tcp_evidence(request)
                if (
                    response.analysis_id != state["analysis"].analysis_id
                    or response.evidence_type != request.evidence_type
                    or len(response.items) > request.limit
                ):
                    raise AppError(
                        code="INVALID_EVIDENCE_OUTPUT",
                        message="Evidence response violates the request contract",
                        recoverable=False,
                        suggested_action="Fix the MCP evidence adapter.",
                    )
                response.coverage_range.setdefault("offset", request.offset)
                identity = request.model_dump(mode="json")
                identity.update(offset=0, limit=0)
                response.coverage_range["query_key"] = json.dumps(
                    identity, sort_keys=True, separators=(",", ":")
                )
                response_bytes = len(
                    response.model_dump_json().encode("utf-8")
                )
                if response_bytes > MAX_EVIDENCE_RESPONSE_BYTES:
                    raise AppError(
                        code="INVALID_EVIDENCE_OUTPUT",
                        message="Evidence response exceeds the state size limit",
                        recoverable=False,
                        suggested_action="Reduce the evidence page payload.",
                        details={"size_bytes": response_bytes},
                    )
                responses.append(response)
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
            validated_requests = normalize_requests(
                state, result.requested_evidence
            )
            requests = [] if result.ready_for_report else validated_requests
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

    async def _report_impl(state: AgentState) -> dict[str, Any]:
        verification = state.get("verification")
        hypotheses = state.get("hypotheses", HypothesisBatch())
        error = state.get("error")
        accepted = (
            verification.accepted_hypotheses
            if verification and verification.ready_for_report and not error
            else []
        )
        primary = accepted[0].cause if accepted else "unresolved"
        limitations = list(verification.limitations if verification else [])
        if error:
            limitations.insert(0, f"{error['code']}: analysis workflow degraded")
        if not accepted and not limitations:
            limitations.append("Evidence is insufficient; result remains unresolved.")
        if (
            verification
            and not verification.ready_for_report
            and state.get("round_count", 0) >= MAX_EVIDENCE_ROUNDS
        ):
            limitations.append("Evidence round limit reached before verification.")
        analysis = state.get("analysis")
        coverage = (
            analysis.coverage_summary
            if analysis is not None
            else CoverageSummary()
        )
        standard = _positive_float(state.get("standard_bandwidth_mbps"))
        actual = _positive_float(state.get("actual_bandwidth_mbps"))
        try:
            report_target = Target(state.get("target", Target.DOWNLOAD))
        except (TypeError, ValueError):
            report_target = Target.DOWNLOAD
        diagnostic = DiagnosticReport(
            standard_bandwidth_mbps=standard,
            actual_bandwidth_mbps=actual,
            achievement_ratio_pct=actual / standard * 100,
            target=report_target,
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
                if (
                    verification
                    and verification.ready_for_report
                    and verification.confidence
                    and not error
                )
                else Confidence.LOW
            ),
            coverage_summary=coverage,
            evidence_quality={
                "coverage_complete": coverage.complete,
                "coverage_truncated": coverage.truncated,
                "evidence_pages": len(state.get("evidence", [])),
                "local_evidence_truncated": any(
                    item.truncated for item in state.get("evidence", [])
                ),
                "missing_information": limitations[:10],
            },
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

    async def report(state: AgentState) -> dict[str, Any]:
        try:
            return await _report_impl(state)
        except Exception as exc:
            error = _error_dict(exc, "REPORT_FAILED")
            try:
                fallback_target = Target(state.get("target", Target.DOWNLOAD))
            except (TypeError, ValueError):
                fallback_target = Target.DOWNLOAD
            fallback_standard = _positive_float(
                state.get("standard_bandwidth_mbps")
            )
            fallback_actual = _positive_float(state.get("actual_bandwidth_mbps"))
            fallback = DiagnosticReport(
                standard_bandwidth_mbps=fallback_standard,
                actual_bandwidth_mbps=fallback_actual,
                achievement_ratio_pct=(
                    fallback_actual / fallback_standard * 100
                ),
                target=fallback_target,
                primary_cause="unresolved",
                confidence=Confidence.LOW,
                coverage_summary=CoverageSummary(),
                limitations=["REPORT_FAILED: minimal fallback generated"],
                analysis_metadata={"error_code": error["code"]},
            )
            return {
                "report": fallback,
                "error": error,
                "trace": _trace(
                    state, "report", status="degraded", error_code=error["code"]
                ),
            }

    def after_node(state: AgentState) -> str:
        return "report" if state.get("error") else "continue"

    def after_reason(state: AgentState) -> str:
        if state.get("error"):
            return "report"
        return "inspect_evidence" if state.get("evidence_requests") else "verify"

    def after_verify(state: AgentState) -> str:
        if state.get("error"):
            return "report"
        verification = state.get("verification")
        if verification and verification.ready_for_report:
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
        {
            "inspect_evidence": "inspect_evidence",
            "verify": "verify",
            "report": "report",
        },
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
