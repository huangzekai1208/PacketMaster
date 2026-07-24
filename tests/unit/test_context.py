from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from langchain_core.exceptions import OutputParserException

from packetmaster.config import Settings
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
from packetmaster.errors import AppError
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
                "payload_bytes": 8_000_000,
                "retransmission_count": 3,
                "time_start": 1.0,
                "time_end": 11.0,
                "duration_seconds": 10.0,
                "throughput_mbps": 6.4,
                "rtt_histogram": [{"upper_bound_ms": 10, "count": 2}],
            }
        },
        tcp_summary={
            "payload_bytes": 8_000_000,
            "retransmission_count": 3,
            "duplicate_ack_count": 2,
        },
        interval_summary=intervals,
        syn_options={
            "syn_packet_count": 2,
            "mss_values": {"1460": 2},
            "window_scale_shifts": {"7": 2},
            "sack_permitted_count": 2,
        },
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
            "payload_bytes": 1000,
            "retransmission_count": 0,
        }
        for index in range(100)
    ]
    intervals[5]["retransmission_count"] = 1
    intervals[99]["zero_window_count"] = 1
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
    assert context.global_metrics["retransmission_count"] == 3
    assert context.global_metrics["payload_bytes"] == 8_000_000
    assert context.flow_metrics["f-1"]["direction"] == "download"
    assert context.flow_metrics["f-1"]["time_start"] == 1.0
    assert context.flow_metrics["f-1"]["time_end"] == 11.0
    assert context.flow_metrics["f-1"]["duration_seconds"] == 10.0
    assert context.flow_metrics["f-1"]["throughput_mbps"] == 6.4
    assert context.flow_metrics["f-1"]["rtt_histogram"][0]["count"] == 2


def test_context_recursively_excludes_payload_logs_and_secrets() -> None:
    analysis = _analysis([])
    analysis.tcp_summary["tcp.payload"] = "RAW_SECRET"
    analysis.flow_summary["f-1"]["payload"] = "FLOW_SECRET"
    analysis.resource_usage["api_key"] = "KEY_SECRET"
    analysis.artifact_paths["logs"] = {"filter": "/tmp/full.log"}
    analysis.warnings.append("sk-warning-secret RAW LOG BODY /tmp/private.log")
    analysis.coverage_summary.truncation_reason = "sk-coverage-secret"
    evidence = _evidence(
        [
            {
                "evidence_id": "ev-1",
                "event_type": "retransmission",
                "tcp.payload": "EVIDENCE_SECRET",
            }
        ]
    )
    evidence.source = "/Users/private/analysis.sqlite"
    evidence.warnings.append("sk-evidence-secret PAYLOAD LOG BODY")

    context = ContextBuilder().build(
        analysis,
        [evidence],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )
    serialized = json.dumps(context.model_dump(mode="json"), ensure_ascii=False)
    lowered = serialized.lower()
    assert "tcp.payload" not in lowered
    assert '"payload"' not in lowered
    assert "payload_bytes" in lowered
    assert "raw_secret" not in lowered
    assert "flow_secret" not in lowered
    assert "evidence_secret" not in lowered
    assert "key_secret" not in lowered
    assert "full.log" not in lowered
    assert "sk-warning-secret" not in lowered
    assert "sk-coverage-secret" not in lowered
    assert "sk-evidence-secret" not in lowered
    assert "analysis.sqlite" not in lowered
    assert context.syn_options["mss_values"] == {"1460": 2}
    assert context.syn_options["window_scale_shifts"] == {"7": 2}


def test_context_applies_global_evidence_bounds_and_keeps_late_pages() -> None:
    responses = []
    for layer in range(12):
        responses.append(
            EvidenceResponse(
                analysis_id="context-1",
                evidence_type=f"layer-{layer}",
                items=[
                    {
                        "evidence_id": f"ev-{layer}-{index}",
                        "event_type": "retransmission",
                        "packet_data": "DROP_ME",
                        "authorization": "DROP_ME_TOO",
                    }
                    for index in range(20)
                ],
                total=200,
                next_offset=(layer + 1) * 20,
                truncated=True,
                source="analysis.sqlite",
                coverage_range={"complete": False},
            )
        )
    context = ContextBuilder(
        max_evidence_layers=4, max_evidence_items=25
    ).build(
        _analysis([]),
        responses,
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )
    items = [
        item
        for layer in context.evidence_layers.values()
        for item in layer["items"]
    ]
    serialized = json.dumps(context.model_dump(mode="json"))
    assert len(context.evidence_layers) <= 4
    assert len(items) <= 25
    assert any(item["evidence_id"] == "ev-11-19" for item in items)
    last_layer = context.evidence_layers["layer-11"]
    assert last_layer["total"] == 200
    assert last_layer["total_exact"] is True
    assert last_layer["next_offset"] == 240
    assert last_layer["truncated"] is True
    assert last_layer["coverage_range"] == {"complete": False}
    assert "packet_data" not in serialized
    assert "authorization" not in serialized
    assert len(serialized) < 100_000


def test_context_compresses_excess_anomalies_with_explicit_coverage() -> None:
    intervals = [
        {
            "interval_start": float(index),
            "interval_end": float(index + 1),
            "direction": "download",
            "retransmission_count": 1,
            "payload_bytes": 100,
        }
        for index in range(30)
    ]

    context = ContextBuilder(max_intervals=10).build(
        _analysis(intervals),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    assert [item["interval_start"] for item in context.anomaly_intervals] == [
        0.0,
        1.0,
        2.0,
        3.0,
        4.0,
        25.0,
        26.0,
        27.0,
        28.0,
        29.0,
    ]
    summary = context.normal_interval_summary
    assert summary["anomaly_total"] == 30
    assert summary["anomaly_returned"] == 10
    assert summary["anomaly_omitted"] == 20
    assert summary["anomaly_compression"] == "head_tail"
    assert summary["anomaly_coverage"] == {"first": 0.0, "last": 29.0}


def test_context_detects_throughput_collapse_without_tcp_event_flags() -> None:
    intervals = [
        {
            "interval_start": float(index),
            "interval_end": float(index + 1),
            "direction": "download",
            "throughput_mbps": 1000.0 if index < 20 else 1.0,
            "payload_bytes": 125_000_000 if index < 20 else 125_000,
            "retransmission_count": 0,
        }
        for index in range(30)
    ]

    context = ContextBuilder(max_intervals=10).build(
        _analysis(intervals),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    starts = [item["interval_start"] for item in context.anomaly_intervals]
    assert 20.0 in starts
    assert 29.0 in starts
    assert context.normal_interval_summary["anomaly_total"] == 10
    assert context.normal_interval_summary["anomaly_omitted"] == 0


def test_context_flow_compression_keeps_low_throughput_anomalous_flow() -> None:
    analysis = _analysis([])
    analysis.flow_summary = {
        f"normal-{index}": {
            "direction": "download",
            "payload_bytes": 10_000_000 + index,
            "throughput_mbps": 900.0,
            "retransmission_count": 0,
        }
        for index in range(40)
    }
    analysis.flow_summary["slow-flow"] = {
        "direction": "download",
        "payload_bytes": 1_000,
        "throughput_mbps": 2.0,
        "retransmission_count": 0,
    }

    context = ContextBuilder(max_flows=8).build(
        analysis,
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    assert "slow-flow" in context.flow_metrics
    assert context.flow_compression == {
        "total": 41,
        "returned": 8,
        "omitted": 33,
        "anomaly_total": 1,
        "anomaly_returned": 1,
    }


@pytest.mark.parametrize("anomaly", ["rtt", "window"])
def test_context_detects_rtt_or_window_shift_without_tcp_events(anomaly: str) -> None:
    intervals = [
        {
            "interval_start": float(index),
            "direction": "download",
            "throughput_mbps": 900.0,
            "window_min": 65535 if index < 9 or anomaly != "window" else 100,
            "rtt_histogram": [
                {
                    "upper_bound_ms": (
                        10 if index < 9 or anomaly != "rtt" else 500
                    ),
                    "count": 10,
                }
            ],
            "retransmission_count": 0,
        }
        for index in range(10)
    ]

    context = ContextBuilder().build(
        _analysis(intervals),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    assert [item["interval_start"] for item in context.anomaly_intervals] == [9.0]


class FakeStructuredModel:
    def __init__(self) -> None:
        self.schema: type | None = None
        self.method: str | None = None
        self.messages: list[object] = []

    def with_structured_output(
        self, schema: type, *, method: str
    ) -> FakeStructuredModel:
        self.schema = schema
        self.method = method
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


class RepairingStructuredModel(FakeStructuredModel):
    def __init__(self, *, always_fail: bool = False) -> None:
        super().__init__()
        self.always_fail = always_fail
        self.calls = 0
        self.all_messages: list[list[object]] = []

    async def ainvoke(self, messages: list[object]) -> object:
        self.calls += 1
        self.all_messages.append(messages)
        if self.calls == 1 or self.always_fail:
            raise OutputParserException("invalid structured output")
        return await super().ainvoke(messages)


def test_diagnosis_model_uses_open_structured_output_without_network() -> None:
    fake = FakeStructuredModel()
    model = DiagnosisModel(
        client=fake,
        settings=Settings(
            model_name="gpt-4.1-mini",
            model_base_url="https://api.openai.com/v1",
            model_structured_output_method="auto",
        ),
    )
    context = ContextBuilder().build(
        _analysis([]),
        [_evidence([])],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    hypotheses = asyncio.run(model.generate_hypotheses(context))
    verification_evidence = _evidence(
        [
            {
                "evidence_id": "ev-safe",
                "event_type": "retransmission",
                "log_lines": "MODEL_LOG_SECRET",
                "token": "MODEL_TOKEN_SECRET",
            }
        ]
    )
    verification = asyncio.run(
        model.verify(context, hypotheses, [verification_evidence])
    )

    assert hypotheses.hypotheses[0].cause == "应用层自适应限速策略"
    assert isinstance(verification, VerificationResult)
    assert verification.ready_for_report is False
    assert verification.confidence is Confidence.LOW
    serialized_messages = json.dumps(fake.messages, ensure_ascii=False, default=str)
    assert "RAW_SECRET" not in serialized_messages
    assert "MODEL_LOG_SECRET" not in serialized_messages
    assert "MODEL_TOKEN_SECRET" not in serialized_messages
    assert fake.method == "json_schema"


@pytest.mark.parametrize(
    ("settings", "expected_method"),
    [
        (
            Settings(
                model_name="deepseek-v4-flash",
                model_base_url="https://api.deepseek.com",
            ),
            "json_mode",
        ),
        (
            Settings(
                model_name="provider/deepseek-r1",
                model_base_url="https://compatible.example/v1",
            ),
            "json_mode",
        ),
        (
            Settings(
                model_name="gpt-4.1-mini",
                model_base_url="https://api.openai.com/v1",
            ),
            "json_schema",
        ),
        (
            Settings(
                model_name="deepseek-v4-flash",
                model_base_url="https://api.deepseek.com",
                model_structured_output_method="function_calling",
            ),
            "function_calling",
        ),
    ],
)
def test_diagnosis_model_selects_compatible_structured_output_method(
    settings: Settings, expected_method: str
) -> None:
    fake = FakeStructuredModel()
    model = DiagnosisModel(client=fake, settings=settings)
    context = ContextBuilder().build(
        _analysis([]),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    asyncio.run(model.generate_hypotheses(context))

    assert fake.method == expected_method
    system_message = fake.messages[0]
    if expected_method == "json_mode":
        assert "只返回一个符合以下 JSON Schema" in system_message["content"]
        assert '"hypotheses"' in system_message["content"]
    else:
        assert "只返回一个符合以下 JSON Schema" not in system_message["content"]


def test_diagnosis_model_repairs_invalid_structured_output_once() -> None:
    fake = RepairingStructuredModel()
    model = DiagnosisModel(
        client=fake,
        settings=Settings(
            model_name="deepseek-v4-flash",
            model_base_url="https://api.deepseek.com",
        ),
    )
    context = ContextBuilder().build(
        _analysis([]),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    result = asyncio.run(model.generate_hypotheses(context))

    assert result.hypotheses
    assert fake.calls == 2
    assert "上一次响应未通过结构化校验" in fake.all_messages[1][-1]["content"]


def test_diagnosis_model_stops_after_one_failed_schema_repair() -> None:
    fake = RepairingStructuredModel(always_fail=True)
    model = DiagnosisModel(
        client=fake,
        settings=Settings(
            model_name="deepseek-v4-flash",
            model_base_url="https://api.deepseek.com",
        ),
    )
    context = ContextBuilder().build(
        _analysis([]),
        [],
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=600,
    )

    with pytest.raises(AppError) as raised:
        asyncio.run(model.generate_hypotheses(context))

    assert raised.value.code == "INVALID_MODEL_OUTPUT"
    assert raised.value.details == {
        "attempts": 2,
        "exception_type": "OutputParserException",
    }
    assert fake.calls == 2


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
    assert "custom_packet_query" in hypothesis
    assert "不得创造" in hypothesis
    assert "custom_packet_query" in verification
    assert "所有面向用户的文本必须使用简体中文" in hypothesis
    assert "所有面向用户的文本必须使用简体中文" in verification
    assert "不得翻译 JSON 属性名、Schema 枚举值" in hypothesis
    assert "rejected_causes" in verification
    assert "limitations" in verification
    assert DiagnosisModel._prompt("hypothesis.md") == hypothesis
