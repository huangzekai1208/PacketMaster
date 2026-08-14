import asyncio

from packetmaster.application.stall_agent import run_stall_agent
from packetmaster.domain import (
    Hypothesis,
    HypothesisType,
    Observability,
    StallEvidenceRequest,
    StallEvidenceType,
    StallHypothesisBatch,
    StallVerificationResult,
)


class _FakeStallModel:
    async def generate_stall_hypotheses(
        self, *, analysis_id, symptom, protocol_context
    ):
        return StallHypothesisBatch(
            hypotheses=[
                Hypothesis(
                    cause="登录域名解析失败",
                    hypothesis_type=HypothesisType.DATA_DISCOVERED,
                    observability=Observability.DIRECT,
                    confidence=70,
                )
            ],
            requested_evidence=[
                StallEvidenceRequest(
                    analysis_id=analysis_id,
                    evidence_type=StallEvidenceType.DNS,
                    hosts=["login.example.com"],
                )
            ],
        )

    async def verify_stall_hypotheses(
        self, *, symptom, protocol_context, hypotheses, evidence
    ):
        assert evidence[0].items[0]["evidence_id"] == "stall:dns:12"
        return StallVerificationResult(
            candidate_hypotheses=[
                hypotheses.hypotheses[0].model_copy(
                    update={
                        "confidence": 92,
                        "evidence_refs": ["stall:dns:12", "invented-id"],
                        "supporting_evidence": ["报文 12 返回 SERVFAIL"],
                    }
                )
            ],
            ready_for_report=True,
        )


def test_stall_agent_filters_fabricated_evidence_references() -> None:
    result = asyncio.run(
        run_stall_agent(
            model=_FakeStallModel(),
            analysis_id="stall-1",
            symptom="某应用无法登录",
            protocol={
                "dns_summary": {"domains": [{"name": "login.example.com"}]},
                "evidence_index": [
                    {
                        "evidence_id": "stall:dns:12",
                        "evidence_type": "dns",
                        "domain": "login.example.com",
                        "frame.number": "12",
                        "frame.time_relative": 1.2,
                    },
                    {
                        "evidence_id": "stall:dns:13",
                        "evidence_type": "dns",
                        "domain": "other.example.com",
                        "frame.number": "13",
                        "frame.time_relative": 1.3,
                    },
                ],
            },
        )
    )

    assert result is not None
    assert result.hypotheses[0].evidence_refs == ["stall:dns:12"]
    assert result.evidence[0].source == "local-stall-evidence-index"
