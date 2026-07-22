from __future__ import annotations

import asyncio
import json
from pathlib import Path

from packetmaster.context import ContextBuilder, DiagnosisContext
from packetmaster.domain import (
    AnalysisStatus,
    AnalyzeResponse,
    Confidence,
    CoverageSummary,
    EvidenceResponse,
    HypothesisBatch,
    VerificationResult,
)
from packetmaster.model import DiagnosisModel


def _analysis(intervals: list[dict[str, object]]) -> AnalyzeResponse:
    return AnalyzeResponse(
        analysis_id="context-1",
        status=AnalysisStatus.COMPLETED,
        target="download",
        coverage_summary=CoverageSummary(
            input_size_bytes=1024,
            total_packets_seen=1000,
            tcp_packets_seen=900,
            speed_packets_analyzed=800,
            analyzed_bytes=8_000_000,
            analyzed_duration_seconds=10,
            complete=True,
            truncated=False,
        ),
        flow_summary={
            "f-1": {
                "direction": "download",
                "bytes": 8_000_000,
                "retransmissions": 3,
            }
        },
        tcp_summary={"retransmissions": 3, "duplicate_acks": 2},
        interval_summary=intervals,
        syn_options={"mss": {"1460": 1}, "sack_permitted": 1},
        available_evidence=["summary", "flows", "intervals", "events"],
    )


def _evidence(items: list[dict[str, object]]) -> EvidenceResponse:
    return EvidenceResponse(
        analysis_id="context-1",
        evidence_type="events",
        items=items,
        total=len(items),
        source="analysis.sqlite",
        coverage_range={"offset": 0, "limit": 100, "complete": True},
    )


def test_context_preserves_late_anomalies_and_compresses_normal_intervals() -> None:
    intervals = [
        {
            "interval_start": float(index),
            "direction": "download",
            "bytes": 1000,
            "retransmissions": 0,
        }
        for index in range(100)
    ]
    intervals[5]["retransmissions"] = 1
    intervals[99]["zero_window"] = 1
    context = ContextBuilder(max_intervals=8).build(
        _analysis(intervals),
        [_evidence([])],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    starts = {item["interval_start"] for item in context.anomaly_intervals}
    assert 99.0 in starts
    assert 5.0 in starts
    assert len(context.anomaly_intervals) <= 8
    assert context.normal_interval_summary["compressed_count"] >= 90


def test_context_contains_direction_bandwidth_and_full_coverage() -> None:
    context = ContextBuilder().build(
        _analysis([]),
        [_evidence([])],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=625,
    )

    assert isinstance(context, DiagnosisContext)
    assert context.target == "download"
    assert context.bandwidth["achievement_ratio_pct"] == 62.5
    assert context.coverage["speed_packets_analyzed"] == 800
    assert context.coverage["complete"] is True
    assert context.global_metrics["retransmissions"] == 3
    assert context.flow_metrics["f-1"]["direction"] == "download"


def test_context_recursively_excludes_payload_logs_and_secrets() -> None:
    analysis = _analysis([])
    analysis.tcp_summary["tcp.payload"] = "RAW_SECRET"
    analysis.flow_summary["f-1"]["payload"] = "FLOW_SECRET"
    analysis.resource_usage["api_key"] = "KEY_SECRET"
    analysis.artifact_paths["logs"] = {"filter": "/tmp/full.log"}
    evidence = _evidence(
        [
            {
                "evidence_id": "ev-1",
                "event_type": "retransmission",
                "tcp.payload": "EVIDENCE_SECRET",
            }
        ]
    )

    context = ContextBuilder().build(
        analysis,
        [evidence],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )
    serialized = json.dumps(context.model_dump(mode="json"), ensure_ascii=False)
    lowered = serialized.lower()
    assert "payload" not in lowered
    assert "raw_secret" not in lowered
    assert "flow_secret" not in lowered
    assert "evidence_secret" not in lowered
    assert "key_secret" not in lowered
    assert "full.log" not in lowered


class FakeStructuredModel:
    def __init__(self) -> None:
        self.schema: type | None = None
        self.messages: list[object] = []

    def with_structured_output(self, schema: type) -> FakeStructuredModel:
        self.schema = schema
        return self

    async def ainvoke(self, messages: list[object]) -> object:
        self.messages = messages
        if self.schema is HypothesisBatch:
            return {
                "hypotheses": [
                    {
                        "cause": "应用层自适应限速策略",
                        "hypothesis_type": "data_discovered",
                        "observability": "indirect",
                        "confidence": "medium",
                        "supporting_evidence": ["吞吐低于标准带宽"],
                        "contradicting_evidence": ["未观察到持续零窗口"],
                        "missing_evidence": ["服务端应用指标"],
                        "affected_flows": ["f-1"],
                        "explanation": "该原因不属于固定 TCP 原因枚举。",
                        "suggestion": "核对服务端限速策略。",
                    }
                ],
                "requested_evidence": [],
            }
        return {
            "accepted_hypotheses": [],
            "rejected_causes": [],
            "requested_evidence": [],
            "ready_for_report": False,
            "confidence": "low",
            "limitations": ["报文外因素未被报文直接证实，保持 unresolved"],
        }


def test_diagnosis_model_uses_open_structured_output_without_network() -> None:
    fake = FakeStructuredModel()
    model = DiagnosisModel(client=fake)
    context = ContextBuilder().build(
        _analysis([]),
        [_evidence([])],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    hypotheses = asyncio.run(model.generate_hypotheses(context))
    verification = asyncio.run(model.verify(context, hypotheses, []))

    assert hypotheses.hypotheses[0].cause == "应用层自适应限速策略"
    assert isinstance(verification, VerificationResult)
    assert verification.ready_for_report is False
    assert verification.confidence is Confidence.LOW
    serialized_messages = json.dumps(fake.messages, ensure_ascii=False, default=str)
    assert "RAW_SECRET" not in serialized_messages


def test_prompts_require_open_hypotheses_and_outside_capture_limits() -> None:
    prompt_root = Path(__file__).parents[2] / "src" / "packetmaster" / "prompts"
    hypothesis = (prompt_root / "hypothesis.md").read_text(encoding="utf-8")
    verification = (prompt_root / "verification.md").read_text(encoding="utf-8")

    assert "不是原因白名单" in hypothesis
    assert "支持证据" in hypothesis
    assert "反向证据" in hypothesis
    assert "缺失证据" in hypothesis
    assert "outside_capture" in verification
    assert "不能描述为已由报文证实" in verification
    assert "unresolved" in verification
