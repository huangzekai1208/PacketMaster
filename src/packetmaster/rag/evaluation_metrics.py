"""Deterministic retrieval metrics computed from persisted evaluation traces."""

from __future__ import annotations

import math
import statistics
from collections import defaultdict

from pydantic import Field

from packetmaster.rag.contracts import Identifier, RagContract
from packetmaster.rag.evaluation_contracts import (
    EvaluationCaseResult,
    EvaluationCaseV2,
    EvaluationVariant,
)
from packetmaster.rag.evaluation_retrieval import EvaluationRetrievalTrace


class VariantMetricReport(RagContract):
    variant: EvaluationVariant
    case_count: int = Field(ge=1)
    recall_at_5: float = Field(ge=0, le=1)
    recall_at_8: float = Field(ge=0, le=1)
    recall_at_20: float = Field(ge=0, le=1)
    micro_recall_at_20: float = Field(ge=0, le=1)
    hit_rate_at_5: float = Field(ge=0, le=1)
    hit_rate_at_8: float = Field(ge=0, le=1)
    hit_rate_at_20: float = Field(ge=0, le=1)
    mrr_at_20: float = Field(ge=0, le=1)
    ndcg_at_5: float = Field(ge=0, le=1)
    ndcg_at_8: float = Field(ge=0, le=1)
    ndcg_at_20: float = Field(ge=0, le=1)
    critical_recall_at_20: float | None = Field(default=None, ge=0, le=1)
    average_relevant_rank: float | None = Field(default=None, ge=1)
    worst_relevant_rank: int | None = Field(default=None, ge=1)
    no_result_rate: float = Field(ge=0, le=1)
    degraded_rate: float = Field(ge=0, le=1)
    p50_latency_seconds: float = Field(ge=0)
    p95_latency_seconds: float = Field(ge=0)


class RerankerComparison(RagContract):
    improved_case_ids: list[Identifier] = Field(default_factory=list)
    unchanged_case_ids: list[Identifier] = Field(default_factory=list)
    regressed_case_ids: list[Identifier] = Field(default_factory=list)
    degraded_case_ids: list[Identifier] = Field(default_factory=list)


class RetrievalEvaluationReportV2(RagContract):
    case_count: int = Field(ge=1)
    variants: list[VariantMetricReport] = Field(min_length=4, max_length=4)
    groups: dict[str, list[VariantMetricReport]] = Field(default_factory=dict)
    reranker_comparison: RerankerComparison
    context_relevant_retention: float = Field(ge=0, le=1)
    provider_call_counts: dict[Identifier, int] = Field(default_factory=dict)


def _dcg(grades: list[int]) -> float:
    return sum(
        (2**grade - 1) / math.log2(index + 2)
        for index, grade in enumerate(grades)
    )


def _percentile(values: list[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * percentile) - 1)
    return ordered[index]


def _best_rank(result: EvaluationCaseResult, *, limit: int) -> int | None:
    ranks = [rank for rank in result.relevant_ranks.values() if rank <= limit]
    return min(ranks) if ranks else None


class RetrievalMetricsEvaluator:
    def evaluate(
        self,
        cases: list[EvaluationCaseV2],
        results: list[EvaluationCaseResult],
        traces: list[EvaluationRetrievalTrace],
        case_dimensions: dict[str, dict[str, str | bool]] | None = None,
    ) -> RetrievalEvaluationReportV2:
        if not cases:
            raise ValueError("at least one evaluation case is required")
        case_by_id = {case.case_id: case for case in cases}
        if len(case_by_id) != len(cases):
            raise ValueError("evaluation cases must be unique")
        result_map = {(item.case_id, item.variant): item for item in results}
        expected = {
            (case.case_id, variant)
            for case in cases
            for variant in EvaluationVariant
        }
        if set(result_map) != expected:
            raise ValueError("results must cover every case and variant exactly")
        trace_map = {trace.query_id: trace for trace in traces}
        if set(trace_map) != set(case_by_id):
            raise ValueError("traces must cover every evaluation case exactly")
        variant_reports = [
            self._variant_metrics(
                variant,
                cases,
                [result_map[(case.case_id, variant)] for case in cases],
            )
            for variant in EvaluationVariant
        ]
        groups: dict[str, list[VariantMetricReport]] = {}
        grouped: dict[str, list[EvaluationCaseV2]] = defaultdict(list)
        for case in cases:
            grouped[f"question_type:{case.question_type}"].append(case)
            grouped[f"critical:{str(case.critical).lower()}"].append(case)
            for key, value in (case_dimensions or {}).get(case.case_id, {}).items():
                grouped[f"{key}:{str(value).lower()}"].append(case)
        for name, group_cases in sorted(grouped.items()):
            groups[name] = [
                self._variant_metrics(
                    variant,
                    group_cases,
                    [result_map[(case.case_id, variant)] for case in group_cases],
                )
                for variant in EvaluationVariant
            ]
        retained = 0
        relevant_total = 0
        for case in cases:
            final_ids = set(trace_map[case.case_id].final_chunk_ids)
            relevant = set(case.relevant_chunk_ids)
            retained += len(final_ids & relevant)
            relevant_total += len(relevant)
        provider_calls: dict[str, int] = defaultdict(int)
        for trace in traces:
            for provider, count in trace.provider_calls.items():
                provider_calls[provider] += count
        return RetrievalEvaluationReportV2(
            case_count=len(cases),
            variants=variant_reports,
            groups=groups,
            reranker_comparison=self._compare_reranker(cases, result_map, trace_map),
            context_relevant_retention=(
                retained / relevant_total if relevant_total else 1.0
            ),
            provider_call_counts=dict(provider_calls),
        )

    @staticmethod
    def _variant_metrics(
        variant: EvaluationVariant,
        cases: list[EvaluationCaseV2],
        results: list[EvaluationCaseResult],
    ) -> VariantMetricReport:
        recalls: dict[int, list[float]] = {5: [], 8: [], 20: []}
        hits: dict[int, list[float]] = {5: [], 8: [], 20: []}
        ndcgs: dict[int, list[float]] = {5: [], 8: [], 20: []}
        reciprocal_ranks: list[float] = []
        critical_recalls: list[float] = []
        observed_ranks: list[int] = []
        micro_hits = 0
        micro_total = 0
        for case, result in zip(cases, results, strict=True):
            relevant = set(case.relevant_chunk_ids)
            micro_total += len(relevant)
            ids = result.retrieved_chunk_ids
            for limit in (5, 8, 20):
                found = relevant & set(ids[:limit])
                recall = len(found) / len(relevant)
                recalls[limit].append(recall)
                hits[limit].append(float(bool(found)))
                grades = [
                    case.relevance_grades.get(chunk_id, 0)
                    for chunk_id in ids[:limit]
                ]
                ideal = sorted(
                    case.relevance_grades.values(), reverse=True
                )[:limit]
                ideal_dcg = _dcg(ideal)
                ndcgs[limit].append(_dcg(grades) / ideal_dcg if ideal_dcg else 0.0)
                if limit == 20:
                    micro_hits += len(found)
                    if case.critical:
                        critical_recalls.append(recall)
            first = _best_rank(result, limit=20)
            reciprocal_ranks.append(1 / first if first else 0.0)
            observed_ranks.extend(
                rank for rank in result.relevant_ranks.values() if rank <= 20
            )
        latencies = [item.latency_seconds for item in results]
        return VariantMetricReport(
            variant=variant,
            case_count=len(cases),
            recall_at_5=statistics.fmean(recalls[5]),
            recall_at_8=statistics.fmean(recalls[8]),
            recall_at_20=statistics.fmean(recalls[20]),
            micro_recall_at_20=micro_hits / micro_total if micro_total else 1.0,
            hit_rate_at_5=statistics.fmean(hits[5]),
            hit_rate_at_8=statistics.fmean(hits[8]),
            hit_rate_at_20=statistics.fmean(hits[20]),
            mrr_at_20=statistics.fmean(reciprocal_ranks),
            ndcg_at_5=statistics.fmean(ndcgs[5]),
            ndcg_at_8=statistics.fmean(ndcgs[8]),
            ndcg_at_20=statistics.fmean(ndcgs[20]),
            critical_recall_at_20=(
                statistics.fmean(critical_recalls) if critical_recalls else None
            ),
            average_relevant_rank=(
                statistics.fmean(observed_ranks) if observed_ranks else None
            ),
            worst_relevant_rank=max(observed_ranks) if observed_ranks else None,
            no_result_rate=sum(not item.retrieved_chunk_ids for item in results)
            / len(results),
            degraded_rate=sum(
                "INFRASTRUCTURE" in item.failure_labels for item in results
            )
            / len(results),
            p50_latency_seconds=statistics.median(latencies),
            p95_latency_seconds=_percentile(latencies, 0.95),
        )

    @staticmethod
    def _compare_reranker(
        cases: list[EvaluationCaseV2],
        result_map: dict[tuple[str, EvaluationVariant], EvaluationCaseResult],
        trace_map: dict[str, EvaluationRetrievalTrace],
    ) -> RerankerComparison:
        improved: list[str] = []
        unchanged: list[str] = []
        regressed: list[str] = []
        degraded: list[str] = []
        for case in cases:
            reranked_trace = trace_map[case.case_id].variant(
                EvaluationVariant.RERANKED
            )
            if reranked_trace.degraded:
                degraded.append(case.case_id)
                continue
            before = _best_rank(
                result_map[(case.case_id, EvaluationVariant.RRF)], limit=20
            )
            after = _best_rank(
                result_map[(case.case_id, EvaluationVariant.RERANKED)], limit=20
            )
            before_value = before if before is not None else 21
            after_value = after if after is not None else 21
            if after_value < before_value:
                improved.append(case.case_id)
            elif after_value > before_value:
                regressed.append(case.case_id)
            else:
                unchanged.append(case.case_id)
        return RerankerComparison(
            improved_case_ids=improved,
            unchanged_case_ids=unchanged,
            regressed_case_ids=regressed,
            degraded_case_ids=degraded,
        )
