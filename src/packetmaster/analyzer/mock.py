"""Deterministic adapter used by contract tests and demonstrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packetmaster.analyzer.base import (
    normalized_evidence_filters,
    validate_evidence_request,
)
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
)
from packetmaster.errors import AppError


class MockAnalyzerAdapter:
    def __init__(self, fixture_path: Path) -> None:
        self.fixture_path = Path(fixture_path)

    def _fixture(self) -> dict[str, Any]:
        try:
            value = json.loads(self.fixture_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AppError(
                code="INVALID_MOCK_FIXTURE",
                message="Mock analysis fixture is unreadable",
                recoverable=False,
                suggested_action="Repair or replace the mock fixture.",
                details={"path": str(self.fixture_path)},
            ) from exc
        if not isinstance(value, dict):
            raise AppError(
                code="INVALID_MOCK_FIXTURE",
                message="Mock analysis fixture must be a JSON object",
                recoverable=False,
                suggested_action="Repair or replace the mock fixture.",
            )
        return value

    async def analyze(
        self, request: AnalyzeRequest, progress_callback: object | None = None
    ) -> AnalyzeResponse:
        fixture = self._fixture()
        data = {key: value for key, value in fixture.items() if key != "evidence"}
        data["target"] = request.target
        data["analysis_id"] = request.request_id
        response = AnalyzeResponse.model_validate(data)
        if not response.artifact_paths:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Mock analysis has no artifact manifest path",
                recoverable=False,
                suggested_action="Repair the mock fixture.",
            )
        return response

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        validate_evidence_request(request)
        fixture = self._fixture()
        evidence = fixture.get("evidence", {})
        if not isinstance(evidence, dict):
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Mock evidence is not an object",
                recoverable=False,
                suggested_action="Repair the mock fixture.",
            )
        items = evidence.get(request.evidence_type, [])
        if not isinstance(items, list):
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Mock evidence items are not a list",
                recoverable=False,
                suggested_action="Repair the mock fixture.",
            )
        filtered: list[dict[str, Any]] = []
        filters = normalized_evidence_filters(request)
        flow_ids = set(filters.flow_ids or [])
        for item in items:
            if flow_ids and item.get("flow_id") not in flow_ids:
                continue
            item_time = item.get("frame.time_relative", item.get("time_relative"))
            if filters.time_start is not None and (
                item_time is None or item_time < filters.time_start
            ):
                continue
            if filters.time_end is not None and (
                item_time is None or item_time > filters.time_end
            ):
                continue
            if not all(_matches(item, predicate) for predicate in filters.predicates):
                continue
            filtered.append(item)
        total = len(filtered)
        page = filtered[request.offset : request.offset + request.limit]
        page_end = request.offset + len(page)
        selected_fields = (
            request.query.fields
            if request.query and request.query.fields
            else request.fields
        )
        if selected_fields:
            page = [
                {
                    field: item.get(
                        field,
                        item.get("time_relative")
                        if field == "frame.time_relative"
                        else None,
                    )
                    for field in selected_fields
                }
                for item in page
            ]
        return EvidenceResponse(
            analysis_id=request.analysis_id,
            evidence_type=request.evidence_type,
            summary={"adapter": "mock"},
            items=page,
            total=total,
            next_offset=page_end if page_end < total else None,
            truncated=page_end < total,
            source="mock",
            coverage_range={
                "complete": page_end >= total,
                "source": "mock fixture",
            },
        )


def _matches(item: dict[str, Any], predicate: Any) -> bool:
    if isinstance(predicate, dict):
        field = predicate["field"]
        expected = predicate.get("value")
        operator = predicate["operator"]
    else:
        field = predicate.field
        expected = predicate.value
        operator = predicate.operator.value
    value = item.get(field)
    if field == "frame.time_relative":
        value = item.get(field, item.get("time_relative"))
    if operator == "exists":
        return (value is not None) is (expected is not False)
    if operator == "in":
        return value in expected
    if operator == "eq":
        return value == expected
    if operator == "ne":
        return value != expected
    if value is None:
        return False
    return {
        "gt": value > expected,
        "gte": value >= expected,
        "lt": value < expected,
        "lte": value <= expected,
    }.get(operator, False)
