"""离线 RAG 标注评估集、可复现指标与 active 门禁计算。"""

from __future__ import annotations

import json
import math
import re
import time
from datetime import datetime
from pathlib import Path

from pydantic import Field, model_validator

from packetmaster.errors import AppError
from packetmaster.rag.base import KnowledgeRetriever
from packetmaster.rag.contracts import Identifier, KnowledgeQuery, RagContract

_SENSITIVE = re.compile(
    r"(?:api[_-]?key|authorization|token|password|payload|pcap[_-]?path|"
    r"[A-Za-z]:[\\/]|/(?:Users|home|private|tmp|var)/)",
    re.IGNORECASE,
)


class EvaluationCase(RagContract):
    case_id: Identifier
    query: KnowledgeQuery
    relevant_chunk_ids: list[Identifier] = Field(min_length=1, max_length=32)
    relevance_grades: dict[Identifier, int] = Field(min_length=1, max_length=32)
    expected_causes: list[str] = Field(min_length=1, max_length=32)
    baseline_causes: list[str] = Field(default_factory=list, max_length=32)
    rag_causes: list[str] = Field(default_factory=list, max_length=32)
    answer_citation_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    applicable_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    forbidden_conclusions: list[str] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def validate_labels(self) -> EvaluationCase:
        if self.query.query_id != self.case_id:
            raise ValueError("evaluation case_id and query_id must match")
        if set(self.relevance_grades) != set(self.relevant_chunk_ids):
            raise ValueError("relevance grades must cover exactly the relevant chunks")
        if any(not 0 <= value <= 3 for value in self.relevance_grades.values()):
            raise ValueError("relevance grades must be between 0 and 3")
        return self


class EvaluationReport(RagContract):
    case_count: int = Field(ge=0)
    recall_at_5: float = Field(ge=0, le=1)
    mrr: float = Field(ge=0, le=1)
    ndcg_at_5: float = Field(ge=0, le=1)
    citation_accuracy: float = Field(ge=0, le=1)
    applicability_accuracy: float = Field(ge=0, le=1)
    baseline_cause_coverage: float = Field(ge=0, le=1)
    rag_cause_coverage: float = Field(ge=0, le=1)
    cause_coverage_delta: float = Field(ge=-1, le=1)
    unsupported_conclusion_rate: float = Field(ge=0, le=1)
    p95_latency_seconds: float = Field(ge=0)
    average_context_bytes: float = Field(ge=0)
    production_ready: bool = False


def _coverage(expected: list[str], observed: list[str]) -> float:
    expected_set = {item.strip().casefold() for item in expected}
    observed_set = {item.strip().casefold() for item in observed}
    return len(expected_set & observed_set) / len(expected_set) if expected_set else 1.0


def _dcg(grades: list[int]) -> float:
    return sum(
        (2**grade - 1) / math.log2(index + 2)
        for index, grade in enumerate(grades)
    )


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, math.ceil(len(ordered) * 0.95) - 1)
    return ordered[index]


def load_evaluation_cases(path: Path) -> list[EvaluationCase]:
    raw = path.read_text(encoding="utf-8")
    if _SENSITIVE.search(raw):
        raise ValueError("evaluation dataset contains sensitive fields or paths")
    value = json.loads(raw)
    if not isinstance(value, list) or not value:
        raise ValueError("evaluation dataset must be a non-empty JSON array")
    cases = [EvaluationCase.model_validate(item) for item in value]
    identifiers = [item.case_id for item in cases]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("evaluation dataset contains duplicate case IDs")
    return cases


def validate_evaluation_corpus(
    cases: list[EvaluationCase], available_chunk_ids: set[str]
) -> None:
    """Reject labels that do not belong to the current approved corpus."""
    relevant = {
        chunk_id for case in cases for chunk_id in case.relevant_chunk_ids
    }
    missing = sorted(relevant - available_chunk_ids)
    if not missing:
        return
    raise AppError(
        code="EVALUATION_CORPUS_MISMATCH",
        message="评测标注切片与当前正式知识库不匹配",
        recoverable=True,
        suggested_action="请切换到对应知识快照，或人工迁移标注切片后重试。",
        details={
            "labeled_chunk_count": len(relevant),
            "available_chunk_count": len(available_chunk_ids),
            "missing_chunk_count": len(missing),
            "missing_chunk_ids": missing[:10],
        },
    )


def convert_v1_cases_to_v2_draft(
    cases: list[EvaluationCase],
    *,
    dataset_id: str,
    version: int,
    policy_id: str,
    created_at: datetime,
) -> dict[str, object]:
    """Copy known V1 labels without inventing V2 review decisions."""
    if not cases:
        raise ValueError("at least one evaluation case is required")
    knowledge_ids = sorted(
        {
            chunk_id.split(":v", 1)[0]
            for case in cases
            for chunk_id in case.relevant_chunk_ids
        }
    )
    return {
        "schema_version": 2,
        "manifest": {
            "dataset_id": dataset_id,
            "version": version,
            "language": "zh-CN",
            "domain": "TODO",
            "created_at": created_at.isoformat(),
            "created_by": "TODO",
            "reviewed_by": [],
            "change_summary": "TODO: review labels migrated from V1",
            "annotation_guideline_version": "TODO",
            "policy_id": policy_id,
            "allowed_knowledge_ids": knowledge_ids,
            "external_judge_allowed": False,
        },
        "cases": [
            {
                "case_id": case.case_id,
                "query": case.query.model_dump(mode="json"),
                "relevant_chunk_ids": case.relevant_chunk_ids,
                "relevance_grades": case.relevance_grades,
                "critical": None,
                "question_type": "TODO",
                "expected_facts": [],
                "expected_causes": case.expected_causes,
                "forbidden_conclusions": case.forbidden_conclusions,
                "applicable_chunk_ids": (
                    case.applicable_chunk_ids or case.relevant_chunk_ids
                ),
                "applicability_note": "TODO",
                "reference_answer": None,
                "approved_citation_chunk_ids": case.answer_citation_chunk_ids,
                "annotated_by": "",
                "reviewed_by": "",
                "label_change_reason": "TODO: manually review migrated labels",
            }
            for case in cases
        ],
    }


class RagEvaluator:
    def __init__(self, retriever: KnowledgeRetriever) -> None:
        self.retriever = retriever

    async def evaluate(self, cases: list[EvaluationCase]) -> EvaluationReport:
        if not cases:
            raise ValueError("at least one evaluation case is required")
        recalls: list[float] = []
        reciprocal_ranks: list[float] = []
        ndcgs: list[float] = []
        citations_valid = 0
        citations_total = 0
        applicable_hits = 0
        relevant_hits = 0
        baseline_coverages: list[float] = []
        rag_coverages: list[float] = []
        forbidden_hits = 0
        rag_conclusions = 0
        latencies: list[float] = []
        context_sizes: list[int] = []
        for case in cases:
            started = time.perf_counter()
            bundle = await self.retriever.retrieve(case.query)
            latencies.append(time.perf_counter() - started)
            context_sizes.append(bundle.total_content_bytes)
            ids = [item.chunk_id for item in bundle.results[:5]]
            relevant = set(case.relevant_chunk_ids)
            hits = [identifier for identifier in ids if identifier in relevant]
            recalls.append(len(hits) / len(relevant))
            first = next(
                (
                    index
                    for index, identifier in enumerate(ids, 1)
                    if identifier in relevant
                ),
                None,
            )
            reciprocal_ranks.append(1 / first if first else 0.0)
            grades = [case.relevance_grades.get(identifier, 0) for identifier in ids]
            ideal = sorted(case.relevance_grades.values(), reverse=True)[:5]
            ideal_dcg = _dcg(ideal)
            ndcgs.append(_dcg(grades) / ideal_dcg if ideal_dcg else 0.0)
            citations_total += len(case.answer_citation_chunk_ids)
            citations_valid += sum(
                identifier in relevant
                for identifier in case.answer_citation_chunk_ids
            )
            relevant_hits += len(hits)
            applicable = set(case.applicable_chunk_ids or case.relevant_chunk_ids)
            applicable_hits += sum(identifier in applicable for identifier in hits)
            baseline_coverages.append(
                _coverage(case.expected_causes, case.baseline_causes)
            )
            rag_coverages.append(_coverage(case.expected_causes, case.rag_causes))
            forbidden = {item.casefold() for item in case.forbidden_conclusions}
            rag_values = {item.casefold() for item in case.rag_causes}
            forbidden_hits += len(forbidden & rag_values)
            rag_conclusions += len(rag_values)
        baseline_coverage = sum(baseline_coverages) / len(cases)
        rag_coverage = sum(rag_coverages) / len(cases)
        metrics = {
            "recall_at_5": sum(recalls) / len(cases),
            "mrr": sum(reciprocal_ranks) / len(cases),
            "ndcg_at_5": sum(ndcgs) / len(cases),
            "citation_accuracy": (
                citations_valid / citations_total if citations_total else 0.0
            ),
            "applicability_accuracy": (
                applicable_hits / relevant_hits if relevant_hits else 0.0
            ),
            "baseline_cause_coverage": baseline_coverage,
            "rag_cause_coverage": rag_coverage,
            "cause_coverage_delta": rag_coverage - baseline_coverage,
            "unsupported_conclusion_rate": (
                forbidden_hits / rag_conclusions if rag_conclusions else 0.0
            ),
            "p95_latency_seconds": _p95(latencies),
            "average_context_bytes": sum(context_sizes) / len(cases),
        }
        ready = self._passes(len(cases), metrics)
        return EvaluationReport(
            case_count=len(cases), **metrics, production_ready=ready
        )

    @staticmethod
    def _passes(case_count: int, metrics: dict[str, float]) -> bool:
        return bool(
            case_count >= 50
            and metrics["recall_at_5"] >= 0.85
            and metrics["citation_accuracy"] >= 0.95
            and metrics["applicability_accuracy"] >= 0.95
            and metrics["cause_coverage_delta"] > 0
            and metrics["unsupported_conclusion_rate"] <= 0
            and metrics["p95_latency_seconds"] <= 2
        )

    @staticmethod
    def production_gate(
        cases: list[EvaluationCase], *, perfect_metrics: bool = False
    ) -> bool:
        if not perfect_metrics:
            return False
        return len(cases) >= 50
