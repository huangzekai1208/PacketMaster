"""Shared adapter protocol for local and test speed analyzers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
)
from packetmaster.errors import AppError

EVIDENCE_FIELDS = {
    "evidence_id",
    "event_type",
    "frame.number",
    "frame.time_relative",
    "flow_id",
    "direction",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.len",
    "tcp.analysis.ack_rtt",
}


@dataclass(frozen=True)
class EvidenceFilters:
    flow_ids: list[str] | None
    time_start: float | None
    time_end: float | None
    predicates: list[object]


def normalized_evidence_filters(request: EvidenceRequest) -> EvidenceFilters:
    query = request.query
    flow_ids = query.flow_ids if query and query.flow_ids else None
    if flow_ids is None and request.flow_id is not None:
        flow_ids = [request.flow_id]
    time_start = (
        query.time_start
        if query and query.time_start is not None
        else request.time_start
    )
    time_end = (
        query.time_end if query and query.time_end is not None else request.time_end
    )
    predicates: list[object] = list(query.predicates) if query else []
    if request.evidence_type != "events":
        predicates.append(
            {"field": "event_type", "operator": "eq", "value": request.evidence_type}
        )
    return EvidenceFilters(flow_ids, time_start, time_end, predicates)


def validate_evidence_request(request: EvidenceRequest) -> None:
    fields = list(request.fields)
    predicates = []
    if request.query is not None:
        fields.extend(request.query.fields)
        predicates = request.query.predicates
    unknown = sorted(set(fields) - EVIDENCE_FIELDS)
    if unknown:
        raise AppError(
            code="UNSAFE_EVIDENCE_QUERY",
            message=f"Unsupported evidence field: {unknown[0]}",
            recoverable=False,
            suggested_action="Use only whitelisted TCP evidence fields.",
        )
    for predicate in predicates:
        if predicate.field not in EVIDENCE_FIELDS:
            raise AppError(
                code="UNSAFE_EVIDENCE_QUERY",
                message=f"Unsupported evidence field: {predicate.field}",
                recoverable=False,
                suggested_action="Use only whitelisted TCP evidence fields.",
            )
        if predicate.operator.value == "in" and (
            not isinstance(predicate.value, list) or not predicate.value
        ):
            raise AppError(
                code="UNSAFE_EVIDENCE_QUERY",
                message="in predicate value must be a non-empty list",
                recoverable=False,
                suggested_action="Provide one or more predicate values.",
            )
        if predicate.operator.value == "exists" and predicate.value not in (
            None,
            True,
            False,
        ):
            raise AppError(
                code="UNSAFE_EVIDENCE_QUERY",
                message="exists predicate value must be boolean",
                recoverable=False,
                suggested_action="Use true or false for exists predicates.",
            )


class AnalyzerAdapter(Protocol):
    async def analyze(
        self, request: AnalyzeRequest, progress_callback: object | None = None
    ) -> AnalyzeResponse: ...

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse: ...
