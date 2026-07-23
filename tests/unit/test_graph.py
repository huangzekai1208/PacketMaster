from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

import packetmaster.graph as graph_module
from packetmaster.domain import (
    Confidence,
    DiagnosticReport,
    EvidenceRequest,
    EvidenceResponse,
    Observability,
)
from packetmaster.graph import build_graph
from tests.fakes import FakeDiagnosisModel, FakeMCPClient


def _input(tmp_path: Path, **overrides: object) -> dict[str, object]:
    capture = tmp_path / "capture.pcapng"
    capture.write_bytes(b"capture")
    state: dict[str, object] = {
        "request": {
            "request_id": "graph-1",
            "pcap_path": str(capture.resolve()),
        },
        "standard_bandwidth_mbps": 1000.0,
        "actual_bandwidth_mbps": 600.0,
    }
    state.update(overrides)
    return state


@pytest.mark.parametrize(
    ("target", "expected"),
    [(None, "download"), ("upload", "upload"), ("both", "both")],
)
def test_graph_preserves_default_and_explicit_target(
    tmp_path: Path, target: str | None, expected: str
) -> None:
    mcp = FakeMCPClient()
    model = FakeDiagnosisModel()
    graph = build_graph(mcp_client=mcp, diagnosis_model=model)
    request = _input(tmp_path)
    if target is not None:
        request["request"]["target"] = target

    result = asyncio.run(graph.ainvoke(request))

    assert mcp.targets == [expected]
    assert model.targets == [expected]
    assert result["target"] == expected
    assert result["report"].target.value == expected


def test_graph_caps_evidence_loop_at_three_rounds(tmp_path: Path) -> None:
    mcp = FakeMCPClient()
    model = FakeDiagnosisModel(request_forever=True)
    graph = build_graph(mcp_client=mcp, diagnosis_model=model)

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["round_count"] == 3
    assert model.verify_calls == 3
    assert len(mcp.evidence_calls) == 3
    assert all(1 <= request.limit <= 500 for request in mcp.evidence_calls)
    assert result["report"].primary_cause == "unresolved"
    assert result["report"].confidence.value == "low"
    assert result["report"].evidence_quality["local_evidence_truncated"] is True
    assert [request.offset for request in mcp.evidence_calls] == [0, 100, 200]


def test_graph_verifies_summary_only_hypothesis(tmp_path: Path) -> None:
    model = FakeDiagnosisModel(initial_request=False)
    graph = build_graph(mcp_client=FakeMCPClient(), diagnosis_model=model)

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert model.verify_calls == 1
    assert result["report"].primary_cause == "开放式候选原因"


def test_graph_rejects_cross_analysis_evidence_request(tmp_path: Path) -> None:
    class CrossAnalysisModel(FakeDiagnosisModel):
        async def generate_hypotheses(self, context):
            batch = await super().generate_hypotheses(context)
            batch.requested_evidence = [
                EvidenceRequest(
                    analysis_id="another-analysis",
                    evidence_type="events",
                )
            ]
            return batch

    mcp = FakeMCPClient()
    graph = build_graph(mcp_client=mcp, diagnosis_model=CrossAnalysisModel())

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["error"]["code"] == "EVIDENCE_ANALYSIS_MISMATCH"
    assert mcp.evidence_calls == []
    assert result["report"].primary_cause == "unresolved"
    assert result["report"].confidence.value == "low"


def test_graph_degrades_analysis_error_to_unresolved_report(tmp_path: Path) -> None:
    graph = build_graph(
        mcp_client=FakeMCPClient(fail_analysis=True),
        diagnosis_model=FakeDiagnosisModel(),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["error"]["code"] == "ANALYSIS_FAILED"
    assert result["report"].primary_cause == "unresolved"
    assert "ANALYSIS_FAILED" in result["report"].limitations[0]


def test_graph_rejects_unknown_target_and_trace_is_payload_free(tmp_path: Path) -> None:
    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=FakeDiagnosisModel()
    )
    state = _input(tmp_path)
    state["request"]["target"] = "sideways"
    state["api_key"] = "sk-secret"
    state["payload"] = "RAW_PAYLOAD"

    result = asyncio.run(graph.ainvoke(state))

    serialized = json.dumps(result["trace"], ensure_ascii=False)
    assert result["report"].primary_cause == "unresolved"
    assert result["error"]["code"] == "INVALID_REQUEST"
    assert "sk-secret" not in serialized
    assert "RAW_PAYLOAD" not in serialized
    allowed = {
        "node",
        "round",
        "status",
        "target",
        "error_code",
        "evidence_request_count",
    }
    assert all(set(event) <= allowed for event in result["trace"])


def test_report_fallback_preserves_upload_and_bandwidth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real_report = DiagnosticReport
    calls = 0

    def flaky_report(**kwargs):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise ValueError("force fallback")
        return real_report(**kwargs)

    monkeypatch.setattr(graph_module, "DiagnosticReport", flaky_report)
    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=FakeDiagnosisModel(initial_request=False),
    )
    state = _input(tmp_path)
    state["request"]["target"] = "upload"

    result = asyncio.run(graph.ainvoke(state))

    assert result["report"].target.value == "upload"
    assert result["report"].standard_bandwidth_mbps == 1000.0
    assert result["report"].actual_bandwidth_mbps == 600.0
    assert result["error"]["code"] == "REPORT_FAILED"


def test_graph_rejects_evidence_over_utf8_byte_limit(tmp_path: Path) -> None:
    class OversizedMCP(FakeMCPClient):
        async def get_tcp_evidence(self, request):
            return EvidenceResponse(
                analysis_id=request.analysis_id,
                evidence_type=request.evidence_type,
                items=[{"evidence_id": "ev-large", "text": "汉" * 400_000}],
                total=1,
                source="fake",
                coverage_range={"offset": request.offset},
            )

    graph = build_graph(
        mcp_client=OversizedMCP(), diagnosis_model=FakeDiagnosisModel()
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["error"]["code"] == "INVALID_EVIDENCE_OUTPUT"
    assert result["report"].primary_cause == "unresolved"


def test_ready_verification_still_validates_unsafe_request(tmp_path: Path) -> None:
    class ReadyUnsafeModel(FakeDiagnosisModel):
        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            result.ready_for_report = True
            result.requested_evidence = [
                EvidenceRequest(
                    analysis_id="another-analysis",
                    evidence_type="events",
                )
            ]
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=ReadyUnsafeModel(initial_request=False),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["error"]["code"] == "EVIDENCE_ANALYSIS_MISMATCH"
    assert result["report"].primary_cause == "unresolved"


def test_incomplete_coverage_forces_unresolved_low_confidence(tmp_path: Path) -> None:
    mcp = FakeMCPClient()
    original = mcp.analyze_speed_capture

    async def incomplete(request):
        response = await original(request)
        response.coverage_summary.complete = False
        response.coverage_summary.truncated = True
        response.coverage_summary.truncation_reason = "fixture truncation"
        return response

    mcp.analyze_speed_capture = incomplete
    graph = build_graph(mcp_client=mcp, diagnosis_model=FakeDiagnosisModel())

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["report"].primary_cause == "unresolved"
    assert result["report"].confidence is Confidence.LOW
    assert all(
        item.confidence is Confidence.LOW
        for item in result["report"].candidate_causes
    )
    assert result["report"].troubleshooting_steps == []
    assert any("coverage" in item.lower() for item in result["report"].limitations)


def test_outside_capture_only_forces_unresolved_low_confidence(tmp_path: Path) -> None:
    class OutsideHighModel(FakeDiagnosisModel):
        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            result.accepted_hypotheses[0].observability = Observability.OUTSIDE_CAPTURE
            result.confidence = Confidence.HIGH
            result.accepted_hypotheses[0].suggestion = "UNVERIFIED_ACTION"
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=OutsideHighModel()
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["report"].primary_cause == "unresolved"
    assert result["report"].confidence is Confidence.LOW
    assert all(
        item.confidence is Confidence.LOW
        for item in result["report"].candidate_causes
    )
    assert result["report"].troubleshooting_steps == []
    assert any(
        "outside" in item.lower() for item in result["report"].limitations
    )


def test_low_confidence_report_keeps_only_accepted_candidates_and_steps(
    tmp_path: Path,
) -> None:
    class SelectiveLowModel(FakeDiagnosisModel):
        async def generate_hypotheses(self, context):
            batch = await super().generate_hypotheses(context)
            rejected = batch.hypotheses[0].model_copy(
                update={"cause": "rejected-cause", "suggestion": "REJECTED_STEP"}
            )
            batch.hypotheses[0].suggestion = "ACCEPTED_STEP"
            batch.hypotheses.append(rejected)
            return batch

        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            result.accepted_hypotheses = [hypotheses.hypotheses[0]]
            result.confidence = Confidence.LOW
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=SelectiveLowModel()
    )
    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert [item.cause for item in result["report"].candidate_causes] == [
        "开放式候选原因"
    ]
    assert result["report"].candidate_causes[0].confidence is Confidence.LOW
    assert result["report"].troubleshooting_steps == ["ACCEPTED_STEP"]


def test_report_key_evidence_contains_bounded_traceable_references(
    tmp_path: Path,
) -> None:
    class TraceableMCP(FakeMCPClient):
        async def get_tcp_evidence(self, request):
            self.evidence_calls.append(request)
            return EvidenceResponse(
                analysis_id=request.analysis_id,
                evidence_type=request.evidence_type,
                items=[
                    {
                        "evidence_id": f"ev-{index}",
                        "frame.number": index,
                        "frame.time_relative": index / 10,
                        "flow_id": "f-1",
                        "direction": "download",
                        "tcp.payload": "MUST_NOT_REACH_REPORT",
                    }
                    for index in range(20)
                ],
                total=20,
                truncated=True,
                source="private.sqlite",
                coverage_range={"offset": request.offset, "complete": False},
            )

    graph = build_graph(
        mcp_client=TraceableMCP(), diagnosis_model=FakeDiagnosisModel()
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    key_evidence = result["report"].key_evidence[0]
    assert key_evidence["page_offset"] == 0
    assert key_evidence["coverage_complete"] is False
    assert key_evidence["total_exact"] is True
    assert len(key_evidence["references"]) == 5
    assert key_evidence["references"][0] == {
        "evidence_id": "ev-0",
        "frame.number": 0,
        "frame.time_relative": 0.0,
        "flow_id": "f-1",
        "direction": "download",
    }
    serialized = json.dumps(key_evidence)
    assert "query_key_sha256" in key_evidence
    assert "MUST_NOT_REACH_REPORT" not in serialized
    assert "private.sqlite" not in serialized
