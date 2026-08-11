from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

import packetmaster.graph as graph_module
from packetmaster.domain import (
    DiagnosticReport,
    EvidenceRequest,
    EvidenceResponse,
    HypothesisType,
    Observability,
)
from packetmaster.errors import AppError
from packetmaster.graph import build_graph
from packetmaster.rag.contracts import (
    KnowledgeAugmentation,
    KnowledgeBundle,
    KnowledgeCitation,
    KnowledgeQuery,
    RagMode,
    RetrievalCandidate,
)
from packetmaster.rag.validation import KnowledgeCitationValidator
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


def test_graph_resumes_failed_reason_node_from_persistent_checkpoint(
    tmp_path: Path,
) -> None:
    class FailsOnceModel(FakeDiagnosisModel):
        def __init__(self) -> None:
            super().__init__()
            self.reason_attempts = 0

        async def generate_hypotheses(self, context):
            self.reason_attempts += 1
            if self.reason_attempts == 1:
                raise AppError(
                    code="MODEL_CALL_FAILED",
                    message="模型调用失败",
                    recoverable=True,
                    suggested_action="重试任务。",
                )
            return await super().generate_hypotheses(context)

    async def scenario():
        checkpoint_path = tmp_path / "checkpoints.sqlite"
        config = {"configurable": {"thread_id": "analysis-resume"}}
        mcp = FakeMCPClient()
        model = FailsOnceModel()
        async with AsyncSqliteSaver.from_conn_string(str(checkpoint_path)) as saver:
            graph = build_graph(
                mcp_client=mcp,
                diagnosis_model=model,
                checkpointer=saver,
                raise_node_errors=True,
            )
            with pytest.raises(AppError, match="模型调用失败"):
                await graph.ainvoke(_input(tmp_path), config)

        # 重新打开连接并重新编译图，模拟 Worker 退出或主机断电后恢复。
        async with AsyncSqliteSaver.from_conn_string(str(checkpoint_path)) as saver:
            graph = build_graph(
                mcp_client=mcp,
                diagnosis_model=model,
                checkpointer=saver,
                raise_node_errors=True,
            )
            result = await graph.ainvoke(None, config)
        return mcp, model, result

    mcp, model, result = asyncio.run(scenario())

    assert mcp.targets == ["download"]
    assert model.reason_attempts == 2
    assert result["report"].primary_cause == "开放式候选原因"


def test_graph_caps_evidence_loop_at_three_rounds(tmp_path: Path) -> None:
    mcp = FakeMCPClient()
    model = FakeDiagnosisModel(request_forever=True)
    graph = build_graph(mcp_client=mcp, diagnosis_model=model)

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["round_count"] == 3
    assert model.verify_calls == 3
    assert len(mcp.evidence_calls) == 3
    assert all(1 <= request.limit <= 500 for request in mcp.evidence_calls)
    assert result["report"].primary_cause == "开放式候选原因"
    assert result["report"].confidence == 65
    assert result["report"].evidence_quality["local_evidence_truncated"] is True
    assert [request.offset for request in mcp.evidence_calls] == [0, 100, 200]


def test_graph_verifies_summary_only_hypothesis(tmp_path: Path) -> None:
    model = FakeDiagnosisModel(initial_request=False)
    graph = build_graph(mcp_client=FakeMCPClient(), diagnosis_model=model)

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert model.verify_calls == 1
    assert result["report"].primary_cause == "开放式候选原因"


def _shadow_runtime(*, fail: bool = False):
    class QueryBuilder:
        def build(self, context, hypotheses):
            return KnowledgeQuery(
                query_id="shadow-query",
                analysis_id=context.analysis_id,
                query_text="吞吐不足",
            )

    class Retriever:
        async def retrieve(self, query):
            if fail:
                raise RuntimeError("retrieval failed")
            candidate = RetrievalCandidate(
                knowledge_id="rfc.window",
                version_id="rfc.window:v1",
                chunk_id="rfc.window:v1:c1",
                title="TCP 窗口",
                knowledge_type="standard",
                authority="high",
                source_name="RFC",
                content="窗口可能限制吞吐",
            )
            return KnowledgeBundle(
                query_id=query.query_id,
                results=[candidate],
                total_content_bytes=len(candidate.content.encode("utf-8")),
            )

    return SimpleNamespace(
        mode=graph_module.RagMode.SHADOW,
        query_builder=QueryBuilder(),
        retriever=Retriever(),
        degradation_reason=None,
    )


def _active_runtime():
    candidate = RetrievalCandidate(
        knowledge_id="rfc.window",
        version_id="rfc.window:v1",
        chunk_id="rfc.window:v1:c1",
        title="TCP 窗口",
        knowledge_type="standard",
        authority="high",
        source_name="RFC",
        content="窗口可能限制吞吐，需要结合当前报文验证。",
    )

    class QueryBuilder:
        def build(self, context, hypotheses):
            return KnowledgeQuery(
                query_id="active-query",
                analysis_id=context.analysis_id,
                query_text="吞吐不足",
            )

    class Retriever:
        async def retrieve(self, query):
            return KnowledgeBundle(
                query_id=query.query_id,
                results=[candidate],
                total_content_bytes=len(candidate.content.encode("utf-8")),
            )

    class Store:
        async def get_candidate(self, chunk_id):
            return candidate if chunk_id == candidate.chunk_id else None

    return SimpleNamespace(
        mode=RagMode.ACTIVE,
        query_builder=QueryBuilder(),
        retriever=Retriever(),
        citation_validator=KnowledgeCitationValidator(Store()),
        degradation_reason=None,
    )


class _AugmentingModel(FakeDiagnosisModel):
    def __init__(self, *, quote: str = "窗口可能限制吞吐") -> None:
        super().__init__(initial_request=False)
        self.quote = quote
        self.augment_calls = 0

    async def augment_hypotheses(self, context, hypotheses, knowledge):
        self.augment_calls += 1
        knowledge_cause = hypotheses.hypotheses[0].model_copy(
            update={
                "cause": "接收窗口可能限制吞吐",
                "hypothesis_type": HypothesisType.KNOWN_PATTERN,
                "observability": Observability.OUTSIDE_CAPTURE,
                "confidence": 95,
                "supporting_evidence": ["知识库中的协议机制"],
                "missing_evidence": ["需要当前报文窗口证据"],
            }
        )
        return KnowledgeAugmentation(
            hypotheses=hypotheses.model_copy(
                update={"hypotheses": [*hypotheses.hypotheses, knowledge_cause]}
            ),
            citations=[
                KnowledgeCitation(
                    knowledge_id="rfc.window",
                    version_id="rfc.window:v1",
                    chunk_id="rfc.window:v1:c1",
                    title="TCP 窗口",
                    knowledge_type="standard",
                    source_name="RFC",
                    supported_statement="窗口可能限制吞吐",
                    supporting_quote=self.quote,
                )
            ],
            limitations=["知识新增原因需要报文或外部信息验证。"],
        )


def test_shadow_rag_records_bounded_refs_without_changing_diagnosis(
    tmp_path: Path,
) -> None:
    model = FakeDiagnosisModel(initial_request=False)
    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=model,
        rag_runtime=_shadow_runtime(),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["report"].primary_cause == "开放式候选原因"
    assert result["report"].analysis_metadata["rag_mode"] == "shadow"
    rag_trace = next(
        item for item in result["trace"] if item["node"] == "retrieve_knowledge"
    )
    assert rag_trace["knowledge_count"] == 1
    assert "content" not in json.dumps(rag_trace)


def test_shadow_rag_failure_does_not_fail_base_diagnosis(tmp_path: Path) -> None:
    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=FakeDiagnosisModel(initial_request=False),
        rag_runtime=_shadow_runtime(fail=True),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result.get("error") is None
    assert result["report"].primary_cause == "开放式候选原因"
    assert "RAG_RETRIEVAL_FAILED" in result["report"].limitations[-1]


def test_active_rag_accepts_valid_citation_but_does_not_promote_external_cause(
    tmp_path: Path,
) -> None:
    model = _AugmentingModel()
    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=model,
        rag_runtime=_active_runtime(),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert model.augment_calls == 1
    assert result["report"].primary_cause == "开放式候选原因"
    assert "接收窗口可能限制吞吐" in {
        item.cause for item in result["report"].candidate_causes
    }
    assert result["report"].knowledge_citations[0]["chunk_id"] == (
        "rfc.window:v1:c1"
    )
    assert "知识新增原因需要报文或外部信息验证。" in (
        result["report"].limitations
    )


def test_active_rag_rejects_forged_quote_and_keeps_base_hypotheses(
    tmp_path: Path,
) -> None:
    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=_AugmentingModel(quote="知识切片中不存在的引文"),
        rag_runtime=_active_runtime(),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert [item.cause for item in result["report"].candidate_causes] == [
        "开放式候选原因",
        "次要候选原因",
    ]
    assert result["report"].knowledge_citations == []
    assert "RAG_CITATION_VALIDATION_FAILED" in result["report"].limitations[-1]


def test_active_rag_model_failure_does_not_fail_base_diagnosis(
    tmp_path: Path,
) -> None:
    class FailingAugmentationModel(_AugmentingModel):
        async def augment_hypotheses(self, context, hypotheses, knowledge):
            raise RuntimeError("augmentation failed")

    graph = build_graph(
        mcp_client=FakeMCPClient(),
        diagnosis_model=FailingAugmentationModel(),
        rag_runtime=_active_runtime(),
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result.get("error") is None
    assert result["report"].primary_cause == "开放式候选原因"
    assert "RAG_AUGMENTATION_FAILED" in result["report"].limitations[-1]


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
    assert result["report"].confidence == 0


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


def test_incomplete_coverage_keeps_supported_ranked_cause(tmp_path: Path) -> None:
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

    assert result["report"].primary_cause == "开放式候选原因"
    assert result["report"].confidence == 65
    assert [item.confidence for item in result["report"].candidate_causes] == [
        65,
        45,
    ]
    assert result["report"].troubleshooting_steps == []
    assert any("覆盖" in item for item in result["report"].limitations)


def test_outside_capture_supported_cause_can_be_primary(tmp_path: Path) -> None:
    class OutsideHighModel(FakeDiagnosisModel):
        async def generate_hypotheses(self, context):
            batch = await super().generate_hypotheses(context)
            for hypothesis in batch.hypotheses:
                hypothesis.observability = Observability.OUTSIDE_CAPTURE
            return batch

        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            result.candidate_hypotheses[0].confidence = 90
            result.candidate_hypotheses[0].suggestion = "UNVERIFIED_ACTION"
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=OutsideHighModel()
    )

    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert result["report"].primary_cause == "开放式候选原因"
    assert result["report"].confidence == 90
    assert [item.cause for item in result["report"].candidate_causes] == [
        "开放式候选原因",
        "次要候选原因",
    ]
    assert result["report"].troubleshooting_steps == ["UNVERIFIED_ACTION"]
    assert any(
        "报文外" in item for item in result["report"].limitations
    )


def test_report_sorts_candidates_and_selects_highest_supported_confidence(
    tmp_path: Path,
) -> None:
    class SelectiveLowModel(FakeDiagnosisModel):
        async def generate_hypotheses(self, context):
            batch = await super().generate_hypotheses(context)
            batch.hypotheses[0].suggestion = "ACCEPTED_STEP"
            batch.hypotheses[0].confidence = 55
            batch.hypotheses[1].suggestion = "TOP_STEP"
            batch.hypotheses[1].confidence = 82
            return batch

        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            result.candidate_hypotheses = hypotheses.hypotheses
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=SelectiveLowModel()
    )
    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert [item.cause for item in result["report"].candidate_causes] == [
        "次要候选原因",
        "开放式候选原因"
    ]
    assert result["report"].primary_cause == "次要候选原因"
    assert result["report"].confidence == 82
    assert result["report"].troubleshooting_steps == ["TOP_STEP", "ACCEPTED_STEP"]


def test_report_is_unresolved_only_when_all_candidates_lack_support(
    tmp_path: Path,
) -> None:
    class UnsupportedModel(FakeDiagnosisModel):
        async def verify(self, context, hypotheses, evidence):
            result = await super().verify(context, hypotheses, evidence)
            for hypothesis in result.candidate_hypotheses:
                hypothesis.supporting_evidence = []
            return result

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=UnsupportedModel()
    )
    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert len(result["report"].candidate_causes) == 2
    assert result["report"].primary_cause == "unresolved"
    assert result["report"].confidence == 0


def test_report_preserves_more_than_four_supported_candidates(
    tmp_path: Path,
) -> None:
    class BroadCandidateModel(FakeDiagnosisModel):
        async def generate_hypotheses(self, context):
            batch = await super().generate_hypotheses(context)
            for index, confidence in enumerate((35, 25, 15), start=3):
                batch.hypotheses.append(
                    batch.hypotheses[0].model_copy(
                        update={
                            "cause": f"候选原因 {index}",
                            "confidence": confidence,
                        }
                    )
                )
            return batch

    graph = build_graph(
        mcp_client=FakeMCPClient(), diagnosis_model=BroadCandidateModel()
    )
    result = asyncio.run(graph.ainvoke(_input(tmp_path)))

    assert len(result["report"].candidate_causes) == 5
    assert [
        item.confidence for item in result["report"].candidate_causes
    ] == [65, 45, 35, 25, 15]


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
