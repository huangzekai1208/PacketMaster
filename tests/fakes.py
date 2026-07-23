from __future__ import annotations

from packetmaster.domain import (
    AnalysisStatus,
    AnalyzeResponse,
    Confidence,
    CoverageSummary,
    EvidenceRequest,
    EvidenceResponse,
    Hypothesis,
    HypothesisBatch,
    HypothesisType,
    Observability,
    VerificationResult,
)
from packetmaster.errors import AppError


class FakeMCPClient:
    def __init__(self, *, fail_analysis: bool = False) -> None:
        self.fail_analysis = fail_analysis
        self.targets: list[str] = []
        self.evidence_calls: list[EvidenceRequest] = []

    async def analyze_speed_capture(self, request):
        self.targets.append(request.target.value)
        if self.fail_analysis:
            raise AppError(
                code="ANALYSIS_FAILED",
                message="fake failure",
                recoverable=True,
                suggested_action="retry",
            )
        return AnalyzeResponse(
            analysis_id=request.request_id,
            status=AnalysisStatus.COMPLETED,
            target=request.target,
            coverage_summary=CoverageSummary(
                total_packets_seen=10,
                tcp_packets_seen=10,
                speed_packets_analyzed=10,
                analyzed_bytes=1000,
                analyzed_duration_seconds=1,
                complete=True,
                truncated=False,
            ),
            flow_summary={"f-1": {"direction": request.target.value}},
            tcp_summary={"packet_count": 10, "payload_bytes": 1000},
        )

    async def get_tcp_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        self.evidence_calls.append(request)
        return EvidenceResponse(
            analysis_id=request.analysis_id,
            evidence_type=request.evidence_type,
            items=[{"evidence_id": f"ev-{len(self.evidence_calls)}"}],
            total=1,
            source="fake",
            coverage_range={"complete": True},
        )


class FakeDiagnosisModel:
    def __init__(self, *, request_forever: bool = False) -> None:
        self.request_forever = request_forever
        self.targets: list[str] = []
        self.verify_calls = 0

    @staticmethod
    def _request(analysis_id: str) -> EvidenceRequest:
        return EvidenceRequest(
            analysis_id=analysis_id,
            evidence_type="retransmission",
            fields=["evidence_id", "event_type"],
            offset=0,
            limit=100,
        )

    async def generate_hypotheses(self, context) -> HypothesisBatch:
        self.targets.append(context.target.value)
        hypothesis = Hypothesis(
            cause="开放式候选原因",
            hypothesis_type=HypothesisType.DATA_DISCOVERED,
            observability=Observability.INDIRECT,
            confidence=Confidence.MEDIUM,
            supporting_evidence=["聚合吞吐不足"],
            contradicting_evidence=[],
            missing_evidence=["更多局部证据"],
            affected_flows=["f-1"],
        )
        return HypothesisBatch(
            hypotheses=[hypothesis],
            requested_evidence=[self._request(context.analysis_id)],
        )

    async def verify(self, context, hypotheses, evidence) -> VerificationResult:
        self.verify_calls += 1
        requests = (
            [self._request(context.analysis_id)] if self.request_forever else []
        )
        return VerificationResult(
            accepted_hypotheses=([] if self.request_forever else hypotheses.hypotheses),
            requested_evidence=requests,
            ready_for_report=not self.request_forever,
            confidence=Confidence.LOW if self.request_forever else Confidence.MEDIUM,
            limitations=(
                ["证据不足，保持 unresolved"] if self.request_forever else []
            ),
        )
