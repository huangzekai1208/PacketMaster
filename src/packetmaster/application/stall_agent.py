"""场景驱动的多协议卡顿推理与证据验证循环。"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from packetmaster.domain import (
    EvidenceResponse,
    Hypothesis,
    StallEvidenceRequest,
    StallHypothesisBatch,
    StallVerificationResult,
)
from packetmaster.errors import AppError
from packetmaster.model import DiagnosisModel

MAX_ROUNDS = 2
MAX_EVIDENCE_ITEMS = 160


@dataclass(frozen=True)
class StallAgentResult:
    hypotheses: list[Hypothesis]
    evidence: list[EvidenceResponse]
    limitations: list[str]
    rounds: int


def _bounded_context(protocol: dict[str, Any]) -> dict[str, Any]:
    """Send summaries and bounded candidate metadata, never the local index itself."""
    context: dict[str, Any] = {}
    for key, value in protocol.items():
        if key in {"evidence_index", "keyword_payload"}:
            continue
        if isinstance(value, list):
            context[key] = value[:128]
        elif isinstance(value, dict):
            context[key] = value
        else:
            context[key] = value
    return context


def _normalize_request(
    request: StallEvidenceRequest, analysis_id: str
) -> StallEvidenceRequest:
    return request.model_copy(
        update={
            "analysis_id": analysis_id,
            "hosts": [str(item).lower().rstrip(".") for item in request.hosts[:16]],
            "ips": [str(item)[:64] for item in request.ips[:16]],
        }
    )


def _request_key(request: StallEvidenceRequest) -> str:
    return json.dumps(
        request.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
    )


def _matches(item: dict[str, Any], request: StallEvidenceRequest) -> bool:
    timestamp = item.get("frame.time_relative")
    if request.time_start is not None and (
        not isinstance(timestamp, int | float) or timestamp < request.time_start
    ):
        return False
    if request.time_end is not None and (
        not isinstance(timestamp, int | float) or timestamp > request.time_end
    ):
        return False
    if request.hosts:
        names = {
            str(item.get(key, "")).lower().rstrip(".")
            for key in ("domain", "host", "sni")
            if item.get(key)
        }
        if not any(
            name == host or name.endswith(f".{host}")
            for name in names
            for host in request.hosts
        ):
            return False
    if request.ips:
        endpoints = {str(item.get("src_ip", "")), str(item.get("dst_ip", ""))}
        if not endpoints.intersection(request.ips):
            return False
    return True


def _query(
    index: list[dict[str, Any]], request: StallEvidenceRequest
) -> EvidenceResponse:
    items = [
        item
        for item in index
        if item.get("evidence_type") == request.evidence_type.value
        and _matches(item, request)
    ]
    returned = items[: request.limit]
    query_key = hashlib.sha256(
        json.dumps(request.model_dump(mode="json"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return EvidenceResponse(
        analysis_id=request.analysis_id,
        evidence_type=request.evidence_type.value,
        summary={"matched": len(items), "query_key_sha256": query_key},
        items=returned,
        total=len(items),
        total_exact=True,
        truncated=len(items) > len(returned),
        source="local-stall-evidence-index",
        coverage_range={"complete": True, "query_key": query_key},
    )


def _sanitize_hypotheses(
    hypotheses: list[Hypothesis], evidence_ids: set[str]
) -> list[Hypothesis]:
    cleaned: list[Hypothesis] = []
    for hypothesis in hypotheses[:12]:
        refs = [ref for ref in hypothesis.evidence_refs if ref in evidence_ids]
        cleaned.append(hypothesis.model_copy(update={"evidence_refs": refs}))
    return cleaned


async def run_stall_agent(
    *,
    model: DiagnosisModel,
    analysis_id: str,
    symptom: str,
    protocol: dict[str, Any],
) -> StallAgentResult | None:
    """Run model proposal, local evidence retrieval, and model verification."""
    context = _bounded_context(protocol)
    try:
        proposal = await model.generate_stall_hypotheses(
            analysis_id=analysis_id,
            symptom=symptom,
            protocol_context=context,
        )
    except AppError:
        return None

    index = [
        item for item in protocol.get("evidence_index", []) if isinstance(item, dict)
    ]
    evidence: list[EvidenceResponse] = []
    seen_requests: set[str] = set()
    verification: StallVerificationResult | None = None
    limitations: list[str] = []
    rounds = 0
    for round_number in range(MAX_ROUNDS):
        rounds = round_number + 1
        requests = (
            proposal.requested_evidence
            if verification is None
            else verification.requested_evidence
        )
        normalized: list[StallEvidenceRequest] = []
        for raw in requests[:12]:
            request = _normalize_request(raw, analysis_id)
            key = _request_key(request)
            if key not in seen_requests:
                seen_requests.add(key)
                normalized.append(request)
        for request in normalized:
            response = _query(index, request)
            if response.items or response.total == 0:
                evidence.append(response)
        try:
            verification = await model.verify_stall_hypotheses(
                symptom=symptom,
                protocol_context=context,
                hypotheses=proposal,
                evidence=evidence[-12:],
            )
        except AppError:
            return StallAgentResult(
                hypotheses=proposal.hypotheses,
                evidence=evidence,
                limitations=["模型证据复核失败，保留初始候选原因。"],
                rounds=rounds,
            )
        limitations.extend(verification.limitations)
        evidence_ids = {
            str(item.get("evidence_id"))
            for response in evidence
            for item in response.items
            if item.get("evidence_id")
        }
        verified = _sanitize_hypotheses(verification.candidate_hypotheses, evidence_ids)
        proposal = StallHypothesisBatch(
            hypotheses=verified,
            requested_evidence=verification.requested_evidence,
        )
        if verification.ready_for_report or not verification.requested_evidence:
            break

    return StallAgentResult(
        hypotheses=proposal.hypotheses,
        evidence=evidence,
        limitations=list(dict.fromkeys(limitations))[:20],
        rounds=rounds,
    )
