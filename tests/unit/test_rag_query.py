from __future__ import annotations

from packetmaster.context import DiagnosisContext
from packetmaster.domain import ChatModelContext, Hypothesis, HypothesisBatch
from packetmaster.rag.query import KnowledgeQueryBuilder


def _context(**updates) -> DiagnosisContext:
    values = {
        "analysis_id": "analysis-1",
        "target": "download",
        "bandwidth": {
            "standard_mbps": 1000.0,
            "actual_mbps": 20.0,
            "achievement_ratio_pct": 2.0,
        },
        "coverage": {"complete": True, "truncated": False},
        "global_metrics": {
            "zero_window_count": 8,
            "retransmission_count": 4,
            "rtt_ms": 120,
        },
        "flow_metrics": {
            "flow-1": {"window_min": 0, "throughput_mbps": 18}
        },
        "anomaly_intervals": [
            {"zero_window_count": 4, "throughput_mbps": 5}
        ],
    }
    values.update(updates)
    return DiagnosisContext.model_validate(values)


def test_query_builder_uses_packet_features_hypotheses_and_environment() -> None:
    hypothesis = Hypothesis(
        cause="接收端处理能力不足",
        hypothesis_type="data_discovered",
        observability="indirect",
        confidence=70,
        missing_evidence=["接收端 CPU 指标"],
    )

    query = KnowledgeQueryBuilder().build(
        _context(),
        HypothesisBatch(hypotheses=[hypothesis]),
        environment_tags={"operating_system": "Windows", "tool": "iperf3"},
    )

    assert query is not None
    assert query.direction.value == "download"
    assert query.achievement_ratio_pct == 2
    assert "zero_window" in query.keywords
    assert "retransmission" in query.keywords
    assert query.candidate_causes == ["接收端处理能力不足"]
    assert query.environment_tags["operating_system"] == "Windows"
    assert query.global_features["zero_window_count"] == 8


def test_query_builder_is_deterministic_and_bins_numeric_features() -> None:
    builder = KnowledgeQueryBuilder()

    first = builder.build(_context())
    second = builder.build(_context())

    assert first is not None and second is not None
    assert first.query_id == second.query_id
    assert "achievement:0-10pct" in first.keywords
    assert "rtt:high" in first.keywords


def test_query_builder_filters_sensitive_fields_and_absolute_paths() -> None:
    context = _context(
        global_metrics={
            "zero_window_count": 1,
            "api_key": "SECRET",
            "pcap_path": "/Users/operator/private/capture.pcapng",
        }
    )

    query = KnowledgeQueryBuilder().build(
        context,
        question="参考 C:\\captures\\private.pcapng，token=SECRET，为什么零窗口？",
        environment_tags={"log_path": "/private/log", "tool": "iperf3"},
    )

    assert query is not None
    serialized = query.model_dump_json()
    assert "SECRET" not in serialized
    assert "private.pcapng" not in serialized
    assert "/private/log" not in serialized
    assert query.environment_tags == {"tool": "iperf3"}


def test_query_builder_skips_context_without_retrieval_signal() -> None:
    context = _context(
        global_metrics={}, flow_metrics={}, anomaly_intervals=[], syn_options={}
    )

    assert KnowledgeQueryBuilder().build(context) is None


def test_query_builder_preserves_explicit_upload_and_question() -> None:
    query = KnowledgeQueryBuilder().build(
        _context(target="upload"), question="Linux CUBIC 为什么单流吞吐较低？"
    )

    assert query is not None
    assert query.direction.value == "upload"
    assert "Linux CUBIC" in query.query_text


def test_chat_query_builder_uses_bounded_question_and_hides_sensitive_data() -> None:
    context = ChatModelContext(
        analysis_id="analysis-1",
        target="download",
        report={
            "primary_cause": "接收窗口受限",
            "achievement_ratio_pct": 2,
        },
        diagnosis_context={
            "zero_window_count": 4,
            "api_key": "SECRET",
            "pcap_path": "/Users/operator/private.pcapng",
        },
        question="token=SECRET，为什么接收窗口会限制吞吐？",
    )

    query = KnowledgeQueryBuilder().build_chat(context)

    assert query is not None
    assert query.analysis_id == "analysis-1"
    assert "接收窗口受限" in query.candidate_causes
    assert "zero_window" in query.keywords
    serialized = query.model_dump_json()
    assert "SECRET" not in serialized
    assert "private.pcapng" not in serialized


def test_general_chat_query_builder_is_deterministic_and_redacts_sensitive_data() -> None:
    builder = KnowledgeQueryBuilder()

    first = builder.build_general_chat(
        "token=SECRET，TCP 零窗口如何处理？参考 /Users/operator/private.pcapng"
    )
    second = builder.build_general_chat(
        "token=SECRET，TCP 零窗口如何处理？参考 /Users/operator/private.pcapng"
    )

    assert first is not None and second is not None
    assert first.analysis_id is None
    assert first.query_id == second.query_id
    serialized = first.model_dump_json()
    assert "SECRET" not in serialized
    assert "private.pcapng" not in serialized
