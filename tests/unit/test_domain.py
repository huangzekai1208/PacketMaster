import pytest
from pydantic import ValidationError

from packetmaster.config import Settings
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    CoverageSummary,
    CustomEvidenceQuery,
    DiagnosticReport,
    EvidenceField,
    EvidencePredicate,
    EvidenceRequest,
    EvidenceResponse,
    Hypothesis,
    HypothesisBatch,
    Target,
    VerificationResult,
)
from packetmaster.errors import AppError


def test_analyze_request_defaults_target_to_download() -> None:
    request = AnalyzeRequest(
        request_id="request-1", pcap_path="/captures/session.pcapng"
    )

    assert request.target is Target.DOWNLOAD


def test_analyze_request_preserves_explicit_upload_target() -> None:
    request = AnalyzeRequest(
        request_id="request-1", pcap_path="/captures/session.pcapng", target="upload"
    )

    assert request.target is Target.UPLOAD


def test_analyze_request_preserves_explicit_both_target() -> None:
    request = AnalyzeRequest(
        request_id="request-1", pcap_path="/captures/session.pcapng", target="both"
    )

    assert request.target is Target.BOTH


def test_analyze_request_rejects_relative_capture_path() -> None:
    with pytest.raises(ValidationError, match="absolute"):
        AnalyzeRequest(request_id="request-1", pcap_path="captures/session.pcapng")


def test_analyze_request_rejects_unknown_target() -> None:
    with pytest.raises(ValidationError, match="target"):
        AnalyzeRequest(
            request_id="request-1",
            pcap_path="/captures/session.pcapng",
            target="egress",
        )


def test_hypothesis_accepts_open_ended_cause_text() -> None:
    hypothesis = Hypothesis(
        cause="A transient provider-side middlebox queue may be saturating",
        hypothesis_type="external_factor",
        observability="outside_capture",
        confidence="low",
        supporting_evidence=["RTT increased during the affected flow"],
        contradicting_evidence=[],
        missing_evidence=["A capture from the remote endpoint"],
        affected_flows=["flow-1"],
        explanation="The capture alone cannot validate the provider queue.",
        suggestion="Collect a simultaneous remote-endpoint capture.",
    )

    assert hypothesis.cause.startswith("A transient provider-side")


def test_analyze_request_accepts_windows_absolute_path_with_unicode() -> None:
    request = AnalyzeRequest(
        request_id="request-1",
        pcap_path=r"C:\captures\2026 07\测速.pcapng",
    )

    assert request.pcap_path == r"C:\captures\2026 07\测速.pcapng"


def test_diagnostic_report_keeps_target_from_input() -> None:
    report = DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=750,
        achievement_ratio_pct=75,
        target="upload",
        confidence="medium",
        coverage_summary=CoverageSummary(),
    )

    assert report.target is Target.UPLOAD


def test_analyze_response_uses_interval_list_and_named_artifact_paths() -> None:
    response = AnalyzeResponse(
        analysis_id="analysis-1",
        status="completed",
        coverage_summary=CoverageSummary(),
        interval_summary=[{"start": 0.0, "throughput_mbps": 100.0}],
        artifact_paths={"report": "/artifacts/report.json"},
    )

    assert response.interval_summary[0]["throughput_mbps"] == 100.0
    assert response.artifact_paths["report"].endswith("report.json")


def test_evidence_response_summary_is_structured() -> None:
    response = EvidenceResponse(
        analysis_id="analysis-1",
        evidence_type="retransmissions",
        summary={"retransmission_count": 3},
    )

    assert response.summary["retransmission_count"] == 3


def test_hypothesis_batch_requests_structured_evidence() -> None:
    request = EvidenceRequest(
        analysis_id="analysis-1", evidence_type="rtt_distribution"
    )

    batch = HypothesisBatch(requested_evidence=[request])
    verification = VerificationResult(requested_evidence=[request], confidence="medium")

    assert batch.requested_evidence[0].evidence_type == "rtt_distribution"
    assert verification.requested_evidence[0].analysis_id == "analysis-1"


def test_evidence_request_rejects_model_invented_type() -> None:
    with pytest.raises(ValidationError, match="evidence_type"):
        EvidenceRequest(analysis_id="analysis-1", evidence_type="custom")


def test_evidence_request_rejects_model_invented_field() -> None:
    with pytest.raises(ValidationError, match="fields"):
        EvidenceRequest(
            analysis_id="analysis-1",
            evidence_type="events",
            fields=["payload_bytes"],
        )


def test_diagnostic_report_requires_positive_bandwidth_and_evidence() -> None:
    report = DiagnosticReport(
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=750,
        achievement_ratio_pct=75,
        target="download",
        primary_cause="unresolved",
        key_evidence=[{"metric": "rtt_ms", "value": 42}],
        confidence="medium",
        coverage_summary=CoverageSummary(),
        evidence_quality={"complete": True},
    )

    assert report.primary_cause == "unresolved"
    assert report.key_evidence[0]["metric"] == "rtt_ms"

    with pytest.raises(ValidationError):
        DiagnosticReport(
            standard_bandwidth_mbps=0,
            actual_bandwidth_mbps=750,
            achievement_ratio_pct=75,
            target="download",
            primary_cause="unresolved",
            confidence="medium",
            coverage_summary=CoverageSummary(),
            evidence_quality={},
        )


def test_coverage_and_query_reject_negative_values() -> None:
    assert CoverageSummary().complete is False

    with pytest.raises(ValidationError):
        CoverageSummary(total_packets_seen=-1)

    with pytest.raises(ValidationError):
        CustomEvidenceQuery(time_start=-0.1)

    with pytest.raises(ValidationError):
        EvidenceResponse(
            analysis_id="analysis-1",
            evidence_type="rtt",
            summary={},
            total=-1,
        )


@pytest.mark.parametrize(
    "query",
    [
        CustomEvidenceQuery.model_construct(flow_ids=["f"] * 33),
        CustomEvidenceQuery.model_construct(fields=[EvidenceField.TCP_LENGTH] * 17),
        CustomEvidenceQuery.model_construct(
            predicates=[
                EvidencePredicate(field="tcp.len", operator="gt", value=0)
            ]
            * 17
        ),
        CustomEvidenceQuery.model_construct(flow_ids=["f" * 257]),
    ],
)
def test_custom_evidence_query_enforces_collection_and_string_bounds(
    query: CustomEvidenceQuery,
) -> None:
    with pytest.raises(ValidationError):
        CustomEvidenceQuery.model_validate(query.model_dump())


def test_in_predicate_rejects_more_than_32_values() -> None:
    with pytest.raises(ValidationError):
        EvidencePredicate(field="tcp.len", operator="in", value=list(range(33)))


def test_app_error_is_raisable_and_catchable() -> None:
    error = AppError(
        code="capture_not_found",
        message="Capture does not exist",
        recoverable=True,
        suggested_action="Provide an existing capture path.",
        details={"pcap_path": "/captures/missing.pcapng"},
    )

    with pytest.raises(AppError) as raised:
        raise error

    assert raised.value.code == "capture_not_found"


def test_settings_default_and_round_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPEED_ANALYZER_MODE", raising=False)
    monkeypatch.delenv("MAX_INSPECTION_ROUNDS", raising=False)

    settings = Settings.load()

    assert settings.speed_analyzer_mode == "real"
    assert settings.max_inspection_rounds == 3

    monkeypatch.setenv("MAX_INSPECTION_ROUNDS", "4")
    with pytest.raises(ValidationError):
        Settings.load()
