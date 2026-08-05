"""有界的关键词/向量混合检索与可解释的确定性排序。"""

from __future__ import annotations

import asyncio
from collections import defaultdict

from packetmaster.errors import AppError
from packetmaster.rag.base import EmbeddingProvider, KnowledgeStore, Reranker
from packetmaster.rag.contracts import (
    AuthorityLevel,
    CaseProfile,
    KnowledgeBundle,
    KnowledgeQuery,
    KnowledgeType,
    RetrievalCandidate,
)
from packetmaster.rag.evaluation_contracts import EvaluationVariant
from packetmaster.rag.evaluation_retrieval import (
    EvaluationRetrievalTrace,
    RetrievalTraceItem,
    RetrievalVariantTrace,
)

_AUTHORITY_BOOST = {
    AuthorityLevel.HIGH: 0.08,
    AuthorityLevel.MEDIUM_HIGH: 0.06,
    AuthorityLevel.MEDIUM: 0.03,
    AuthorityLevel.LOW: 0.0,
}


class HybridKnowledgeRetriever:
    def __init__(
        self,
        store: KnowledgeStore,
        embedding_provider: EmbeddingProvider,
        *,
        reranker: Reranker | None = None,
        keyword_top_k: int = 20,
        vector_top_k: int = 20,
        vector_timeout_seconds: float = 1.25,
        reranker_candidate_top_k: int = 20,
        reranker_timeout_seconds: float = 1.5,
        final_top_k: int = 8,
        max_context_bytes: int = 24_576,
        timeout_seconds: float = 2.0,
        rrf_k: int = 60,
        fail_on_vector_error: bool = False,
    ) -> None:
        if not 1 <= keyword_top_k <= 100 or not 1 <= vector_top_k <= 100:
            raise ValueError("retrieval candidate limits must be between 1 and 100")
        if not 1 <= reranker_candidate_top_k <= 100:
            raise ValueError("reranker candidate limit must be between 1 and 100")
        if not 1 <= final_top_k <= 8 or max_context_bytes < 1:
            raise ValueError("invalid final retrieval limits")
        if (
            timeout_seconds <= 0
            or vector_timeout_seconds <= 0
            or reranker_timeout_seconds <= 0
            or rrf_k < 1
        ):
            raise ValueError("timeout and rrf_k must be positive")
        self.store = store
        self.embedding_provider = embedding_provider
        self.reranker = reranker
        self.keyword_top_k = keyword_top_k
        self.vector_top_k = vector_top_k
        self.vector_timeout_seconds = vector_timeout_seconds
        self.reranker_candidate_top_k = reranker_candidate_top_k
        self.reranker_timeout_seconds = reranker_timeout_seconds
        self.final_top_k = final_top_k
        self.max_context_bytes = min(max_context_bytes, 24_576)
        self.timeout_seconds = timeout_seconds
        self.rrf_k = rrf_k
        self.fail_on_vector_error = fail_on_vector_error

    async def retrieve(self, query: KnowledgeQuery) -> KnowledgeBundle:
        bundle, _ = await self.retrieve_with_trace(query)
        return bundle

    async def retrieve_with_trace(
        self, query: KnowledgeQuery
    ) -> tuple[KnowledgeBundle, EvaluationRetrievalTrace]:
        try:
            return await asyncio.wait_for(
                self._retrieve_with_trace(query), timeout=self.timeout_seconds
            )
        except TimeoutError as exc:
            raise AppError(
                code="RAG_RETRIEVAL_TIMEOUT",
                message="知识检索超时",
                recoverable=True,
                suggested_action="本次诊断将跳过 RAG，请检查知识索引性能。",
            ) from exc

    async def _retrieve_with_trace(
        self, query: KnowledgeQuery
    ) -> tuple[KnowledgeBundle, EvaluationRetrievalTrace]:
        # 关键词和向量召回互不依赖，并发执行可控制外部 embedding 的额外延迟。
        keyword_task = asyncio.create_task(
            self.store.keyword_search(query, limit=self.keyword_top_k)
        )
        vector_task = asyncio.create_task(self._bounded_vector_search(query))
        keyword_result, vector_result = await asyncio.gather(
            keyword_task, vector_task, return_exceptions=True
        )
        warnings: list[str] = []
        if isinstance(keyword_result, BaseException):
            if isinstance(keyword_result, AppError):
                warnings.append(f"关键词检索降级：{keyword_result.code}")
            else:
                warnings.append("关键词检索降级：KEYWORD_RETRIEVAL_FAILED")
            keyword: list[RetrievalCandidate] = []
        else:
            keyword = keyword_result
        if isinstance(vector_result, BaseException):
            if self.fail_on_vector_error and isinstance(vector_result, AppError):
                raise vector_result
            if isinstance(vector_result, AppError):
                warnings.append(f"向量检索降级：{vector_result.code}")
            else:
                warnings.append("向量检索降级：VECTOR_RETRIEVAL_FAILED")
            vector: list[RetrievalCandidate] = []
        else:
            vector = vector_result
        merged = self._merge(keyword, vector, query)
        if self.reranker is None:
            candidates = merged[: self.reranker_candidate_top_k]
        else:
            candidates = sorted(
                merged, key=lambda item: (-item.fusion_score, item.chunk_id)
            )[: self.reranker_candidate_top_k]
        ranked, reranker_executed, reranker_degraded = await self._rerank(
            query, candidates, warnings
        )
        selected, truncated, excluded = self._select(ranked)
        total_bytes = sum(len(item.content.encode("utf-8")) for item in selected)
        bundle = KnowledgeBundle(
            query_id=query.query_id,
            results=selected,
            total_content_bytes=total_bytes,
            truncated=truncated,
            warnings=warnings,
        )
        trace = EvaluationRetrievalTrace(
            query_id=query.query_id,
            variants=[
                RetrievalVariantTrace(
                    variant=EvaluationVariant.BM25,
                    items=self._trace_items(keyword, EvaluationVariant.BM25),
                    degraded=any("关键词检索降级" in item for item in warnings),
                    warnings=[
                        item for item in warnings if "关键词检索降级" in item
                    ],
                ),
                RetrievalVariantTrace(
                    variant=EvaluationVariant.VECTOR,
                    items=self._trace_items(vector, EvaluationVariant.VECTOR),
                    degraded=any("向量检索降级" in item for item in warnings),
                    warnings=[item for item in warnings if "向量检索降级" in item],
                ),
                RetrievalVariantTrace(
                    variant=EvaluationVariant.RRF,
                    items=self._trace_items(merged, EvaluationVariant.RRF),
                ),
                RetrievalVariantTrace(
                    variant=EvaluationVariant.RERANKED,
                    executed=reranker_executed,
                    degraded=reranker_degraded,
                    items=self._trace_items(ranked, EvaluationVariant.RERANKED),
                    warnings=[
                        item for item in warnings if "模型重排序降级" in item
                    ],
                ),
            ],
            final_chunk_ids=[item.chunk_id for item in selected],
            excluded_reasons=excluded,
            provider_calls={
                "embedding-query": 1,
                "reranker": int(reranker_executed or reranker_degraded),
            },
            truncated=truncated,
        )
        return bundle, trace

    async def _rerank(
        self,
        query: KnowledgeQuery,
        candidates: list[RetrievalCandidate],
        warnings: list[str],
    ) -> tuple[list[RetrievalCandidate], bool, bool]:
        if self.reranker is None or len(candidates) < 2:
            return candidates, False, False
        documents = [f"{item.title}\n{item.content}" for item in candidates]
        try:
            results = await asyncio.wait_for(
                self.reranker.rerank(
                    query.query_text, documents, top_n=len(documents)
                ),
                timeout=self.reranker_timeout_seconds,
            )
        except TimeoutError:
            warnings.append("模型重排序降级：RERANK_TIMEOUT")
            return candidates, False, True
        except Exception as exc:
            if isinstance(exc, AppError):
                warnings.append(f"模型重排序降级：{exc.code}")
            else:
                warnings.append("模型重排序降级：RERANK_FAILED")
            return candidates, False, True
        return (
            [
                candidates[index].model_copy(update={"rerank_score": score})
                for index, score in results
            ],
            True,
            False,
        )

    async def _vector_search(self, query: KnowledgeQuery) -> list[RetrievalCandidate]:
        vector = await self.embedding_provider.embed_query(query.query_text)
        return await self.store.vector_search(query, vector, limit=self.vector_top_k)

    async def _bounded_vector_search(
        self, query: KnowledgeQuery
    ) -> list[RetrievalCandidate]:
        try:
            return await asyncio.wait_for(
                self._vector_search(query), timeout=self.vector_timeout_seconds
            )
        except TimeoutError as exc:
            raise AppError(
                code="VECTOR_RETRIEVAL_TIMEOUT",
                message="向量检索超时",
                recoverable=True,
                suggested_action="本次将退化到 BM25 召回，请检查 Embedding 服务。",
            ) from exc

    def _merge(
        self,
        keyword: list[RetrievalCandidate],
        vector: list[RetrievalCandidate],
        query: KnowledgeQuery,
    ) -> list[RetrievalCandidate]:
        values: dict[str, RetrievalCandidate] = {}
        ranks: dict[str, dict[str, int]] = defaultdict(dict)
        for rank, item in enumerate(keyword, start=1):
            values[item.chunk_id] = item
            ranks[item.chunk_id]["keyword"] = rank
        for rank, item in enumerate(vector, start=1):
            values.setdefault(item.chunk_id, item)
            ranks[item.chunk_id]["vector"] = rank
        merged: list[RetrievalCandidate] = []
        for chunk_id, item in values.items():
            # 不适用的操作系统、工具或环境标签不参与后续排序。
            if not self._environment_matches(item, query):
                continue
            keyword_rank = ranks[chunk_id].get("keyword")
            vector_rank = ranks[chunk_id].get("vector")
            fusion = sum(
                1 / (self.rrf_k + rank)
                for rank in (keyword_rank, vector_rank)
                if rank is not None
            )
            case_boost = self._case_similarity(item, query)
            # RRF 后先应用确定性业务加权，模型 reranker 再处理截断后的候选池。
            pre_rerank = fusion + _AUTHORITY_BOOST[item.authority] + case_boost
            merged.append(
                item.model_copy(
                    update={
                        "keyword_rank": keyword_rank,
                        "vector_rank": vector_rank,
                        "fusion_score": fusion,
                        "rerank_score": pre_rerank,
                    }
                )
            )
        merged.sort(key=lambda item: (-item.rerank_score, item.chunk_id))
        return merged

    @staticmethod
    def _environment_matches(item: RetrievalCandidate, query: KnowledgeQuery) -> bool:
        tags = {
            key.casefold(): value.casefold()
            for key, value in query.environment_tags.items()
        }
        operating_system = tags.get("operating_system")
        if operating_system and item.applicability.operating_systems:
            allowed = {
                value.casefold() for value in item.applicability.operating_systems
            }
            if operating_system not in allowed:
                return False
        tool = tags.get("tool")
        if tool and item.applicability.tools:
            if tool not in {value.casefold() for value in item.applicability.tools}:
                return False
        applicability_tags = {
            key.casefold(): value.casefold()
            for key, value in item.applicability.tags.items()
        }
        return all(
            key not in applicability_tags or applicability_tags[key] == value
            for key, value in tags.items()
        )

    def _case_similarity(
        self, item: RetrievalCandidate, query: KnowledgeQuery
    ) -> float:
        if item.knowledge_type is not KnowledgeType.CASE:
            return 0.0
        getter = getattr(self.store, "get_case_profile", None)
        if getter is None:
            return 0.0
        profile: CaseProfile | None = getter(item.version_id)
        if profile is None:
            return 0.0
        score = 0.0
        if profile.direction is query.direction:
            score += 0.08
        if query.achievement_ratio_pct is not None:
            distance = abs(profile.achievement_ratio_pct - query.achievement_ratio_pct)
            score += max(0.0, 0.08 * (1 - distance / 100))
        shared = set(profile.tcp_features) & set(query.global_features)
        if shared:
            matches = 0.0
            for key in shared:
                left = profile.tcp_features[key]
                right = query.global_features[key]
                if isinstance(left, int | float) and isinstance(right, int | float):
                    scale = max(abs(float(left)), abs(float(right)), 1.0)
                    matches += max(0.0, 1 - abs(float(left) - float(right)) / scale)
                elif left == right:
                    matches += 1
            score += 0.08 * matches / len(shared)
        return score

    def _select(
        self, candidates: list[RetrievalCandidate]
    ) -> tuple[list[RetrievalCandidate], bool, dict[str, str]]:
        by_type: dict[KnowledgeType, list[RetrievalCandidate]] = defaultdict(list)
        for item in candidates:
            by_type[item.knowledge_type].append(item)
        ordered: list[RetrievalCandidate] = []
        for item in candidates:
            if item is by_type[item.knowledge_type][0]:
                ordered.append(item)
        ordered.extend(item for item in candidates if item not in ordered)
        selected: list[RetrievalCandidate] = []
        excluded: dict[str, str] = {}
        total_bytes = 0
        for item in ordered:
            if len(selected) >= self.final_top_k:
                excluded[item.chunk_id] = "final_top_k"
                continue
            size = len(item.content.encode("utf-8"))
            if total_bytes + size > self.max_context_bytes:
                excluded[item.chunk_id] = "context_budget"
                continue
            selected.append(item)
            total_bytes += size
        truncated = len(selected) < len(candidates)
        return selected, truncated, excluded

    @staticmethod
    def _trace_items(
        candidates: list[RetrievalCandidate], variant: EvaluationVariant
    ) -> list[RetrievalTraceItem]:
        items: list[RetrievalTraceItem] = []
        for rank, item in enumerate(candidates[:100], start=1):
            score: float | None = None
            business_score: float | None = None
            if variant is EvaluationVariant.VECTOR:
                score = item.rerank_score
            elif variant is EvaluationVariant.RRF:
                score = item.fusion_score
                business_score = item.rerank_score
            elif variant is EvaluationVariant.RERANKED:
                score = item.rerank_score
            items.append(
                RetrievalTraceItem(
                    chunk_id=item.chunk_id,
                    rank=rank,
                    score=score,
                    keyword_rank=item.keyword_rank,
                    vector_rank=item.vector_rank,
                    fusion_score=(
                        item.fusion_score
                        if variant
                        in {EvaluationVariant.RRF, EvaluationVariant.RERANKED}
                        else None
                    ),
                    business_score=business_score,
                )
            )
        return items
