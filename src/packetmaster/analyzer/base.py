"""Shared adapter protocol for local and test speed analyzers."""

from __future__ import annotations

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
