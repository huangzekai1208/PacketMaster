"""Deterministic adapter used by contract tests and demonstrations."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

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

    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse:
        fixture = self._fixture()
        data = {key: value for key, value in fixture.items() if key != "evidence"}
        data["target"] = request.target
        data["analysis_id"] = fixture.get("analysis_id", request.request_id)
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
        fixture = self._fixture()
        evidence = fixture.get("evidence", {})
        if not isinstance(evidence, dict):
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Mock evidence is not an object",
                recoverable=False,
                suggested_action="Repair the mock fixture.",
            )
        if any(";" in field or "--" in field for field in request.fields):
            raise AppError(
                code="UNSAFE_EVIDENCE_QUERY",
                message="Evidence fields contain unsafe SQL tokens",
                recoverable=False,
                suggested_action="Use only whitelisted evidence fields.",
            )
        items = evidence.get(request.evidence_type, [])
        if not isinstance(items, list):
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Mock evidence items are not a list",
                recoverable=False,
                suggested_action="Repair the mock fixture.",
            )
        total = len(items)
        page = items[request.offset : request.offset + request.limit]
        page_end = request.offset + len(page)
        return EvidenceResponse(
            analysis_id=request.analysis_id,
            evidence_type=request.evidence_type,
            summary={"adapter": "mock"},
            items=page,
            total=total,
            next_offset=page_end if page_end < total else None,
            truncated=page_end < total,
            source="mock",
            coverage_range={"complete": True, "source": "mock fixture"},
        )
