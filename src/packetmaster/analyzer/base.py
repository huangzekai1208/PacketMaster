"""Shared adapter protocol for local and test speed analyzers."""

from __future__ import annotations

from typing import Protocol

from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
)


class AnalyzerAdapter(Protocol):
    async def analyze(self, request: AnalyzeRequest) -> AnalyzeResponse: ...

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse: ...
