from __future__ import annotations

import math

import pytest

from packetmaster.rag.evaluation_contracts import (
    EvaluationCaseResult,
    EvaluationCaseV2,
    EvaluationVariant,
)
from packetmaster.rag.evaluation_metrics import RetrievalMetricsEvaluator
from packetmaster.rag.evaluation_retrieval import (
    EvaluationRetrievalTrace,
    RetrievalTraceItem,
    RetrievalVariantTrace,
)


def _case(
    case_id: str,
    relevant: list[str],
    *,
    critical: bool,
    question_type: str,
) -> EvaluationCaseV2:
    return EvaluationCaseV2(
        case_id=case_id,
        query={"query_id": case_id, "query_text": "TCP"},
        relevant_chunk_ids=relevant,
        relevance_grades={
            chunk_id: 3 - index for index, chunk_id in enumerate(relevant)
        },
        critical=critical,
        question_type=question_type,
        expected_facts=["TCP fact"],
        applicable_chunk_ids=relevant,
        annotated_by="annotator",
        reviewed_by="reviewer",
        label_change_reason="initial",
    )


def _result(
    case: EvaluationCaseV2,
    variant: EvaluationVariant,
    ids: list[str],
    *,
    degraded: bool = False,
    latency: float = 0.1,
) -> EvaluationCaseResult:
    ranks = {
        chunk_id: ids.index(chunk_id) + 1
        for chunk_id in case.relevant_chunk_ids
        if chunk_id in ids
    }
    return EvaluationCaseResult(
        run_id="run-1",
        case_id=case.case_id,
        variant=variant,
        retrieved_chunk_ids=ids,
        relevant_chunk_ids=case.relevant_chunk_ids,
        relevant_ranks=ranks,
        latency_seconds=latency,
        failure_labels=["INFRASTRUCTURE"] if degraded else [],
    )


def _trace(
    case: EvaluationCaseV2,
    by_variant: dict[EvaluationVariant, list[str]],
    *,
    final: list[str],
    reranker_degraded: bool = False,
) -> EvaluationRetrievalTrace:
    return EvaluationRetrievalTrace(
        query_id=case.case_id,
        variants=[
            RetrievalVariantTrace(
                variant=variant,
                degraded=(
                    reranker_degraded
                    if variant is EvaluationVariant.RERANKED
                    else False
                ),
                items=[
                    RetrievalTraceItem(chunk_id=chunk_id, rank=index + 1)
                    for index, chunk_id in enumerate(by_variant[variant])
                ],
            )
            for variant in EvaluationVariant
        ],
        final_chunk_ids=final,
        provider_calls={"embedding-query": 1, "reranker": 1},
    )


def test_metrics_match_hand_calculated_multi_k_values() -> None:
    first = _case(
        "case-1", ["relevant-a", "relevant-b"], critical=True, question_type="tcp"
    )
    second = _case(
        "case-2", ["relevant-c"], critical=False, question_type="wireshark"
    )
    cases = [first, second]
    rankings = {
        "case-1": {
            EvaluationVariant.BM25: ["relevant-a", "x", "relevant-b"],
            EvaluationVariant.VECTOR: ["x", "relevant-b"],
            EvaluationVariant.RRF: ["x", "relevant-a", "relevant-b"],
            EvaluationVariant.RERANKED: ["relevant-b", "relevant-a", "x"],
        },
        "case-2": {
            EvaluationVariant.BM25: [],
            EvaluationVariant.VECTOR: ["relevant-c"],
            EvaluationVariant.RRF: ["x", "relevant-c"],
            EvaluationVariant.RERANKED: ["relevant-c", "x"],
        },
    }
    results = [
        _result(case, variant, rankings[case.case_id][variant])
        for case in cases
        for variant in EvaluationVariant
    ]
    traces = [
        _trace(
            case,
            rankings[case.case_id],
            final=[rankings[case.case_id][EvaluationVariant.RERANKED][0]],
        )
        for case in cases
    ]

    report = RetrievalMetricsEvaluator().evaluate(
        cases,
        results,
        traces,
        case_dimensions={
            "case-1": {"knowledge_type": "runbook", "contains_image": True},
            "case-2": {"knowledge_type": "runbook", "contains_image": False},
        },
    )

    by_variant = {item.variant: item for item in report.variants}
    bm25 = by_variant[EvaluationVariant.BM25]
    assert bm25.recall_at_5 == pytest.approx(0.5)
    assert bm25.micro_recall_at_20 == pytest.approx(2 / 3)
    assert bm25.hit_rate_at_5 == pytest.approx(0.5)
    assert bm25.mrr_at_20 == pytest.approx(0.5)
    assert bm25.no_result_rate == pytest.approx(0.5)
    reranked = by_variant[EvaluationVariant.RERANKED]
    assert reranked.recall_at_5 == 1.0
    assert reranked.mrr_at_20 == 1.0
    assert reranked.ndcg_at_5 > by_variant[EvaluationVariant.RRF].ndcg_at_5
    assert report.context_relevant_retention == pytest.approx(2 / 3)
    assert report.reranker_comparison.improved_case_ids == ["case-1", "case-2"]
    assert report.groups["critical:true"][0].case_count == 1
    assert set(report.groups) == {
        "contains_image:false",
        "contains_image:true",
        "critical:false",
        "critical:true",
        "knowledge_type:runbook",
        "question_type:tcp",
        "question_type:wireshark",
    }
    assert report.provider_call_counts == {"embedding-query": 2, "reranker": 2}


def test_metrics_record_reranker_degradation_and_latency_percentiles() -> None:
    case = _case("case-1", ["relevant"], critical=True, question_type="tcp")
    rankings = {variant: ["relevant"] for variant in EvaluationVariant}
    results = [
        _result(
            case,
            variant,
            rankings[variant],
            degraded=variant is EvaluationVariant.RERANKED,
            latency=0.25,
        )
        for variant in EvaluationVariant
    ]
    trace = _trace(
        case,
        rankings,
        final=["relevant"],
        reranker_degraded=True,
    )

    report = RetrievalMetricsEvaluator().evaluate([case], results, [trace])

    reranked = next(
        item for item in report.variants if item.variant is EvaluationVariant.RERANKED
    )
    assert reranked.degraded_rate == 1.0
    assert reranked.p50_latency_seconds == 0.25
    assert reranked.p95_latency_seconds == 0.25
    assert report.reranker_comparison.degraded_case_ids == ["case-1"]


def test_metrics_require_exact_case_variant_and_trace_coverage() -> None:
    case = _case("case-1", ["relevant"], critical=True, question_type="tcp")

    with pytest.raises(ValueError, match="every case and variant"):
        RetrievalMetricsEvaluator().evaluate([case], [], [])


def test_dcg_calculation_never_produces_non_finite_metrics() -> None:
    case = _case("case-1", ["relevant"], critical=True, question_type="tcp")
    rankings = {variant: ["relevant"] for variant in EvaluationVariant}
    results = [
        _result(case, variant, rankings[variant]) for variant in EvaluationVariant
    ]
    report = RetrievalMetricsEvaluator().evaluate(
        [case], results, [_trace(case, rankings, final=["relevant"])]
    )

    for variant in report.variants:
        assert math.isfinite(variant.ndcg_at_20)
