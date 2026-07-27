from __future__ import annotations

import json
from pathlib import Path

import pytest

from packetmaster.rag.contracts import KnowledgeBundle, RetrievalCandidate
from packetmaster.rag.evaluation import (
    EvaluationCase,
    RagEvaluator,
    load_evaluation_cases,
)


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
