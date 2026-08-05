from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from packetmaster.errors import AppError
from packetmaster.rag.contracts import KnowledgeBundle, RetrievalCandidate
from packetmaster.rag.evaluation import (
    EvaluationCase,
    RagEvaluator,
    convert_v1_cases_to_v2_draft,
    load_evaluation_cases,
    validate_evaluation_corpus,
)
from packetmaster.rag.evaluation_contracts import EvaluationDatasetV2


def _candidate(chunk_id: str) -> RetrievalCandidate:
    knowledge_id = chunk_id.split(":")[0]
    return RetrievalCandidate(
        knowledge_id=knowledge_id,
        version_id=f"{knowledge_id}:v1",
        chunk_id=chunk_id,
        title=knowledge_id,
        knowledge_type="standard",
        authority="high",
        source_name="test",
        content=f"knowledge for {chunk_id}",
    )


class FakeRetriever:
    def __init__(self, results) -> None:
        self.results = results

    async def retrieve(self, query):
        items = self.results[query.query_id]
        return KnowledgeBundle(
            query_id=query.query_id,
            results=items,
            total_content_bytes=sum(
                len(item.content.encode("utf-8")) for item in items
            ),
        )


@pytest.mark.asyncio
async def test_evaluator_computes_retrieval_and_quality_metrics() -> None:
    cases = [
        EvaluationCase(
            case_id="q1",
            query={"query_id": "q1", "query_text": "窗口"},
            relevant_chunk_ids=["a:c1", "b:c1"],
            relevance_grades={"a:c1": 3, "b:c1": 2},
            expected_causes=["窗口限制"],
            baseline_causes=[],
            rag_causes=["窗口限制"],
            answer_citation_chunk_ids=["a:c1"],
            applicable_chunk_ids=["a:c1", "b:c1"],
        ),
        EvaluationCase(
            case_id="q2",
            query={"query_id": "q2", "query_text": "重传"},
            relevant_chunk_ids=["c:c1"],
            relevance_grades={"c:c1": 3},
            expected_causes=["链路丢包"],
            baseline_causes=["未知"],
            rag_causes=["链路丢包"],
            answer_citation_chunk_ids=["wrong:c1"],
            applicable_chunk_ids=["c:c1"],
            forbidden_conclusions=["服务端 CPU 满"],
        ),
    ]
    retriever = FakeRetriever(
        {
            "q1": [_candidate("a:c1"), _candidate("x:c1"), _candidate("b:c1")],
            "q2": [_candidate("c:c1")],
        }
    )

    report = await RagEvaluator(retriever).evaluate(cases)

    assert report.case_count == 2
    assert report.recall_at_5 == 1
    assert report.mrr == 1
    assert report.ndcg_at_5 > 0.9
    assert report.citation_accuracy == 0.5
    assert report.applicability_accuracy == 1
    assert report.cause_coverage_delta > 0
    assert report.production_ready is False


def test_load_evaluation_cases_rejects_duplicate_and_sensitive_samples(
    tmp_path: Path,
) -> None:
    path = tmp_path / "evaluation.json"
    sample = {
        "case_id": "q1",
        "query": {"query_id": "q1", "query_text": "窗口"},
        "relevant_chunk_ids": ["a:c1"],
        "relevance_grades": {"a:c1": 3},
        "expected_causes": ["窗口限制"],
        "rag_causes": ["窗口限制"],
        "answer_citation_chunk_ids": ["a:c1"],
        "applicable_chunk_ids": ["a:c1"],
    }
    path.write_text(json.dumps([sample, sample]), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        load_evaluation_cases(path)

    sample["query"]["pcap_path"] = "/Users/private/capture.pcapng"
    path.write_text(json.dumps([sample]), encoding="utf-8")
    with pytest.raises(ValueError, match="sensitive"):
        load_evaluation_cases(path)


def test_production_gate_requires_at_least_fifty_cases() -> None:
    case = EvaluationCase(
        case_id="q1",
        query={"query_id": "q1", "query_text": "窗口"},
        relevant_chunk_ids=["a:c1"],
        relevance_grades={"a:c1": 3},
        expected_causes=["窗口限制"],
        rag_causes=["窗口限制"],
        answer_citation_chunk_ids=["a:c1"],
        applicable_chunk_ids=["a:c1"],
    )

    assert RagEvaluator.production_gate([case], perfect_metrics=True) is False


def test_validate_evaluation_corpus_rejects_missing_relevant_chunks() -> None:
    case = EvaluationCase(
        case_id="q1",
        query={"query_id": "q1", "query_text": "窗口"},
        relevant_chunk_ids=["a:c1", "b:c1"],
        relevance_grades={"a:c1": 3, "b:c1": 2},
        expected_causes=["窗口限制"],
    )

    with pytest.raises(AppError) as raised:
        validate_evaluation_corpus([case], {"a:c1", "unused:c1"})

    assert raised.value.code == "EVALUATION_CORPUS_MISMATCH"
    assert raised.value.details == {
        "labeled_chunk_count": 2,
        "available_chunk_count": 2,
        "missing_chunk_count": 1,
        "missing_chunk_ids": ["b:c1"],
    }


def test_v1_production_thresholds_are_frozen() -> None:
    passing = {
        "recall_at_5": 0.85,
        "citation_accuracy": 0.95,
        "applicability_accuracy": 0.95,
        "cause_coverage_delta": 0.01,
        "unsupported_conclusion_rate": 0.0,
        "p95_latency_seconds": 2.0,
    }

    assert RagEvaluator._passes(50, passing) is True
    for key, failing_value in {
        "recall_at_5": 0.849,
        "citation_accuracy": 0.949,
        "applicability_accuracy": 0.949,
        "cause_coverage_delta": 0.0,
        "unsupported_conclusion_rate": 0.001,
        "p95_latency_seconds": 2.001,
    }.items():
        metrics = {**passing, key: failing_value}
        assert RagEvaluator._passes(50, metrics) is False, key


def test_v1_conversion_produces_an_explicitly_incomplete_v2_draft() -> None:
    case = EvaluationCase(
        case_id="q1",
        query={"query_id": "q1", "query_text": "窗口"},
        relevant_chunk_ids=["knowledge.tcp:v1:chunk-1"],
        relevance_grades={"knowledge.tcp:v1:chunk-1": 3},
        expected_causes=["窗口限制"],
        answer_citation_chunk_ids=["knowledge.tcp:v1:chunk-1"],
    )

    draft = convert_v1_cases_to_v2_draft(
        [case],
        dataset_id="rag.tcp.v2",
        version=2,
        policy_id="rag-production",
        created_at=datetime(2026, 7, 31, tzinfo=UTC),
    )

    assert draft["cases"][0]["relevant_chunk_ids"] == case.relevant_chunk_ids
    assert draft["cases"][0]["critical"] is None
    assert draft["cases"][0]["expected_facts"] == []
    assert draft["manifest"]["reviewed_by"] == []
    with pytest.raises(ValidationError):
        EvaluationDatasetV2.model_validate(draft)
