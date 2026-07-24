"""Bounded LangGraph workflow for evidence-driven TCP speed diagnosis."""

from __future__ import annotations

import hashlib
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
    CoverageSummary,
    DiagnosticReport,
    EvidenceRequest,
    EvidenceResponse,
    HypothesisBatch,
    Observability,
    Target,
    VerificationResult,
)
from packetmaster.errors import AppError

MAX_EVIDENCE_ROUNDS = 3
MAX_REQUESTS_PER_ROUND = 10
MAX_EVIDENCE_RESPONSE_BYTES = 1_000_000
MAX_KEY_EVIDENCE_PAGES = 20
MAX_KEY_EVIDENCE_REFERENCES_PER_PAGE = 5
_REPORT_REFERENCE_FIELDS = (
    "evidence_id",
    "frame.number",
    "frame.time_relative",
    "flow_id",
    "direction",
)


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


def _report_key_evidence(responses: list[EvidenceResponse]) -> list[dict[str, Any]]:
    pages: list[dict[str, Any]] = []
    for response in responses[:MAX_KEY_EVIDENCE_PAGES]:
        coverage = response.coverage_range
        query_key = coverage.get("query_key")
        references = [
            {
                field: item[field]
                for field in _REPORT_REFERENCE_FIELDS
                if field in item
                and isinstance(item[field], str | bool | int | float)
            }
            for item in response.items[:MAX_KEY_EVIDENCE_REFERENCES_PER_PAGE]
        ]
        pages.append(
            {
                "evidence_type": response.evidence_type,
                "total": response.total,
                "total_exact": response.total_exact,
                "truncated": response.truncated,
                "page_offset": coverage.get("offset"),
                "coverage_complete": coverage.get("complete"),
                "query_key_sha256": (
                    hashlib.sha256(query_key.encode("utf-8")).hexdigest()
                    if isinstance(query_key, str)
                    else None
                ),
                "references": references,
            }
        )
    return pages


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
        hypotheses = state.get("hypotheses")
        error = state.get("error")
        limitations = list(verification.limitations if verification else [])
        if error:
            limitations.insert(0, f"{error['code']}：分析流程已降级")
        if (
            verification
            and not verification.ready_for_report
            and state.get("round_count", 0) >= MAX_EVIDENCE_ROUNDS
        ):
            limitations.append("达到证据查询轮次上限，复核仍未完成。")
        analysis = state.get("analysis")
        coverage = (
            analysis.coverage_summary
            if analysis is not None
            else CoverageSummary()
        )
        coverage_reliable = (
            coverage.complete
            and not coverage.truncated
            and coverage.speed_packets_analyzed > 0
        )
        if not coverage_reliable:
            limitations.append(
                "分析覆盖不完整或已截断，置信度需谨慎解读。"
            )
        candidate_source = (
            verification.candidate_hypotheses
            if verification and not error
            else (hypotheses.hypotheses if hypotheses else [])
        )
        report_candidates = sorted(
            candidate_source,
            key=lambda item: item.confidence,
            reverse=True,
        )
        supported_candidates = [
            item
            for item in report_candidates
            if any(evidence.strip() for evidence in item.supporting_evidence)
        ]
        if report_candidates and all(
            item.observability is Observability.OUTSIDE_CAPTURE
            for item in report_candidates
        ):
            limitations.append(
                "候选原因均属于报文外可观测范围，需要外部验证。"
            )
        primary_candidate = (
            supported_candidates[0] if supported_candidates and not error else None
        )
        primary = primary_candidate.cause if primary_candidate else "unresolved"
        report_confidence = primary_candidate.confidence if primary_candidate else 0.0
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
            candidate_causes=report_candidates,
            key_evidence=_report_key_evidence(state.get("evidence", [])),
            confidence=report_confidence,
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
                item.suggestion
                for item in (report_candidates if primary != "unresolved" else [])
                if item.suggestion
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
                confidence=0.0,
                coverage_summary=CoverageSummary(),
                limitations=["REPORT_FAILED：已生成最小降级报告"],
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
