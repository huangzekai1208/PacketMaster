from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

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
