from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from packetmaster.rag.evaluation_contracts import (
    EvaluationCaseResult,
    EvaluationDatasetV2,
    EvaluationIdentity,
    EvaluationOutcome,
    GateDecision,
    canonical_fingerprint,
    load_evaluation_dataset_v2,
    production_system_fingerprint,
)


def _dataset() -> dict[str, object]:
    return {
        "schema_version": 2,
        "manifest": {
            "dataset_id": "rag.tcp.v2",
            "version": 1,
            "language": "zh-CN",
            "domain": "TCP",
            "created_at": "2026-07-31T00:00:00Z",
            "created_by": "annotator",
            "reviewed_by": ["reviewer"],
            "change_summary": "initial labels",
            "annotation_guideline_version": "guideline-v2",
            "policy_id": "rag-production",
            "allowed_knowledge_ids": ["knowledge.tcp"],
            "external_judge_allowed": False,
        },
        "cases": [
            {
                "case_id": "eval.tcp.001",
                "query": {
                    "query_id": "eval.tcp.001",
                    "query_text": "为什么 seq 为 0？",
                },
                "relevant_chunk_ids": ["knowledge.tcp:v1:chunk-1"],
                "relevance_grades": {"knowledge.tcp:v1:chunk-1": 3},
                "critical": True,
                "question_type": "protocol",
                "expected_facts": ["相对序列号"],
                "expected_causes": ["Wireshark 显示行为"],
                "forbidden_conclusions": ["真实序列号固定为零"],
                "applicable_chunk_ids": ["knowledge.tcp:v1:chunk-1"],
                "approved_citation_chunk_ids": ["knowledge.tcp:v1:chunk-1"],
                "annotated_by": "annotator",
                "reviewed_by": "reviewer",
                "label_change_reason": "initial labels",
            }
        ],
    }


def test_v2_dataset_has_stable_canonical_fingerprint() -> None:
    dataset = EvaluationDatasetV2.model_validate(_dataset())
    reordered = EvaluationDatasetV2.model_validate(
        json.loads(json.dumps(_dataset(), sort_keys=True))
    )

    assert canonical_fingerprint(dataset) == canonical_fingerprint(reordered)
    changed = dataset.model_copy(
        update={"manifest": dataset.manifest.model_copy(update={"version": 2})}
    )
    assert canonical_fingerprint(dataset) != canonical_fingerprint(changed)


def test_v2_dataset_rejects_unreviewed_or_inconsistent_labels() -> None:
    value = _dataset()
    value["cases"][0]["reviewed_by"] = "annotator"
    with pytest.raises(ValidationError, match="must be different"):
        EvaluationDatasetV2.model_validate(value)

    value = _dataset()
    value["cases"][0]["relevance_grades"] = {}
    with pytest.raises(ValidationError):
        EvaluationDatasetV2.model_validate(value)


def test_v2_dataset_rejects_sensitive_content(tmp_path: Path) -> None:
    value = _dataset()
    value["cases"][0]["query"]["query_text"] = "读取 /Users/example/capture"
    path = tmp_path / "evaluation.json"
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")

    with pytest.raises(ValueError, match="sensitive"):
        load_evaluation_dataset_v2(path)


def test_case_result_rejects_a_rank_that_disagrees_with_trace() -> None:
    with pytest.raises(ValidationError, match="does not match"):
        EvaluationCaseResult(
            run_id="run-1",
            case_id="case-1",
            variant="reranked",
            retrieved_chunk_ids=["a:c1", "b:c1"],
            relevant_chunk_ids=["b:c1"],
            relevant_ranks={"b:c1": 1},
            latency_seconds=0.1,
        )


def test_gate_decision_rejects_passing_with_a_blocking_failure() -> None:
    with pytest.raises(ValidationError, match="blocking failures"):
        GateDecision(
            run_id="run-1",
            outcome=EvaluationOutcome.PASSED,
            policy_fingerprint="a" * 64,
            checks=[
                {
                    "check_id": "recall-at-5",
                    "passed": False,
                    "blocking": True,
                    "actual": "0.80",
                    "expected": ">= 0.85",
                }
            ],
            decided_at="2026-07-31T00:00:00Z",
        )


def test_production_fingerprint_excludes_dataset_policy_and_judge() -> None:
    values = {
        "dataset_fingerprint": "a" * 64,
        "corpus_fingerprint": "b" * 64,
        "chunking_fingerprint": "c" * 64,
        "embedding_fingerprint": "d" * 64,
        "retrieval_fingerprint": "e" * 64,
        "reranker_fingerprint": "f" * 64,
        "generation_fingerprint": "1" * 64,
        "judge_fingerprint": "2" * 64,
        "policy_fingerprint": "3" * 64,
        "code_revision": "6a2287e",
    }
    first = EvaluationIdentity(**values)
    evaluation_change = EvaluationIdentity(
        **{
            **values,
            "dataset_fingerprint": "9" * 64,
            "judge_fingerprint": "8" * 64,
            "policy_fingerprint": "7" * 64,
        }
    )
    production_change = EvaluationIdentity(
        **{**values, "retrieval_fingerprint": "6" * 64}
    )

    assert production_system_fingerprint(first) == production_system_fingerprint(
        evaluation_change
    )
    assert production_system_fingerprint(first) != production_system_fingerprint(
        production_change
    )
