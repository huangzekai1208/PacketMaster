"""Structured retrieval ablation traces and evaluation result conversion."""

from __future__ import annotations

import time
from typing import Protocol

from pydantic import Field, model_validator

from packetmaster.rag.contracts import (
    Identifier,
    KnowledgeBundle,
    KnowledgeQuery,
    RagContract,
)
from packetmaster.rag.evaluation_contracts import (
    EvaluationCaseResult,
    EvaluationCaseV2,
    EvaluationVariant,
)


class RetrievalTraceItem(RagContract):
    chunk_id: Identifier
    rank: int = Field(ge=1, le=100)
    score: float | None = None
    keyword_rank: int | None = Field(default=None, ge=1, le=100)
    vector_rank: int | None = Field(default=None, ge=1, le=100)
    fusion_score: float | None = Field(default=None, ge=0)
    business_score: float | None = Field(default=None, ge=0)


class RetrievalVariantTrace(RagContract):
    variant: EvaluationVariant
    executed: bool = True
    degraded: bool = False
    items: list[RetrievalTraceItem] = Field(default_factory=list, max_length=100)
    warnings: list[str] = Field(default_factory=list, max_length=32)


class EvaluationRetrievalTrace(RagContract):
    query_id: Identifier
    variants: list[RetrievalVariantTrace] = Field(min_length=4, max_length=4)
    final_chunk_ids: list[Identifier] = Field(default_factory=list, max_length=8)
    excluded_reasons: dict[Identifier, str] = Field(
        default_factory=dict, max_length=100
    )
    provider_calls: dict[Identifier, int] = Field(default_factory=dict, max_length=16)
    truncated: bool = False

    @model_validator(mode="after")
    def require_four_variants(self) -> EvaluationRetrievalTrace:
        variants = [item.variant for item in self.variants]
        if set(variants) != set(EvaluationVariant) or len(set(variants)) != 4:
            raise ValueError("retrieval trace requires each evaluation variant once")
        return self

    def variant(self, value: EvaluationVariant) -> RetrievalVariantTrace:
        return next(item for item in self.variants if item.variant is value)


class TraceableRetriever(Protocol):
    async def retrieve_with_trace(
        self, query: KnowledgeQuery
    ) -> tuple[KnowledgeBundle, EvaluationRetrievalTrace]: ...


class EvaluationRetrievalRunner:
    def __init__(self, retriever: TraceableRetriever) -> None:
        self.retriever = retriever

    async def evaluate_case(
        self, run_id: str, case: EvaluationCaseV2
    ) -> tuple[KnowledgeBundle, EvaluationRetrievalTrace, list[EvaluationCaseResult]]:
        started = time.perf_counter()
        bundle, trace = await self.retriever.retrieve_with_trace(case.query)
        latency_seconds = time.perf_counter() - started
        relevant = set(case.relevant_chunk_ids)
        results: list[EvaluationCaseResult] = []
        for variant in trace.variants:
            chunk_ids = [item.chunk_id for item in variant.items]
            ranks = {
                chunk_id: chunk_ids.index(chunk_id) + 1
                for chunk_id in case.relevant_chunk_ids
                if chunk_id in chunk_ids
            }
            labels: list[str] = []
            if not relevant & set(chunk_ids):
                labels.append(f"{variant.variant.value.upper()}_MISS")
            if variant.degraded:
                labels.append("INFRASTRUCTURE")
            results.append(
                EvaluationCaseResult(
                    run_id=run_id,
                    case_id=case.case_id,
                    variant=variant.variant,
                    retrieved_chunk_ids=chunk_ids,
                    relevant_chunk_ids=case.relevant_chunk_ids,
                    relevant_ranks=ranks,
                    latency_seconds=latency_seconds,
                    warnings=variant.warnings,
                    failure_labels=labels,
                )
            )
        return bundle, trace, results
