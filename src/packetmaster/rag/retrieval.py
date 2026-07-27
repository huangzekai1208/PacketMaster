"""Bounded hybrid keyword/vector retrieval with deterministic reranking."""

from __future__ import annotations

import asyncio
from collections import defaultdict

from packetmaster.errors import AppError
from packetmaster.rag.base import EmbeddingProvider, KnowledgeStore
from packetmaster.rag.contracts import (
    AuthorityLevel,
    CaseProfile,
    KnowledgeBundle,
    KnowledgeQuery,
    KnowledgeType,
    RetrievalCandidate,
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
        keyword_top_k: int = 20,
        vector_top_k: int = 20,
        final_top_k: int = 8,
        max_context_bytes: int = 24_576,
        timeout_seconds: float = 2.0,
        rrf_k: int = 60,
    ) -> None:
        if not 1 <= keyword_top_k <= 100 or not 1 <= vector_top_k <= 100:
            raise ValueError("retrieval candidate limits must be between 1 and 100")
        if not 1 <= final_top_k <= 8 or max_context_bytes < 1:
            raise ValueError("invalid final retrieval limits")
        if timeout_seconds <= 0 or rrf_k < 1:
            raise ValueError("timeout and rrf_k must be positive")
        self.store = store
        self.embedding_provider = embedding_provider
        self.keyword_top_k = keyword_top_k
        self.vector_top_k = vector_top_k
        self.final_top_k = final_top_k
        self.max_context_bytes = min(max_context_bytes, 24_576)
        self.timeout_seconds = timeout_seconds
        self.rrf_k = rrf_k

    async def retrieve(self, query: KnowledgeQuery) -> KnowledgeBundle:
        try:
            return await asyncio.wait_for(
                self._retrieve(query), timeout=self.timeout_seconds
            )
        except TimeoutError as exc:
            raise AppError(
                code="RAG_RETRIEVAL_TIMEOUT",
                message="知识检索超时",
                recoverable=True,
                suggested_action="本次诊断将跳过 RAG，请检查知识索引性能。",
            ) from exc

    async def _retrieve(self, query: KnowledgeQuery) -> KnowledgeBundle:
        keyword_task = asyncio.create_task(
            self.store.keyword_search(query, limit=self.keyword_top_k)
        )
        vector_task = asyncio.create_task(self._vector_search(query))
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
            if isinstance(vector_result, AppError):
                warnings.append(f"向量检索降级：{vector_result.code}")
            else:
                warnings.append("向量检索降级：VECTOR_RETRIEVAL_FAILED")
            vector: list[RetrievalCandidate] = []
        else:
            vector = vector_result
        merged = self._merge(keyword, vector, query)
        selected, truncated = self._select(merged)
        total_bytes = sum(len(item.content.encode("utf-8")) for item in selected)
        return KnowledgeBundle(
            query_id=query.query_id,
            results=selected,
            total_content_bytes=total_bytes,
            truncated=truncated,
            warnings=warnings,
        )

    async def _vector_search(
        self, query: KnowledgeQuery
    ) -> list[RetrievalCandidate]:
        vector = await self.embedding_provider.embed_query(query.query_text)
        return await self.store.vector_search(
            query, vector, limit=self.vector_top_k
        )

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
            rerank = fusion + _AUTHORITY_BOOST[item.authority] + case_boost
            merged.append(
                item.model_copy(
                    update={
                        "keyword_rank": keyword_rank,
                        "vector_rank": vector_rank,
                        "fusion_score": fusion,
                        "rerank_score": rerank,
                    }
                )
            )
        merged.sort(key=lambda item: (-item.rerank_score, item.chunk_id))
        return merged

    @staticmethod
    def _environment_matches(
        item: RetrievalCandidate, query: KnowledgeQuery
    ) -> bool:
        tags = {
            key.casefold(): value.casefold()
            for key, value in query.environment_tags.items()
        }
        operating_system = tags.get("operating_system")
        if operating_system and item.applicability.operating_systems:
            allowed = {
                value.casefold()
                for value in item.applicability.operating_systems
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
            distance = abs(
                profile.achievement_ratio_pct - query.achievement_ratio_pct
            )
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
    ) -> tuple[list[RetrievalCandidate], bool]:
        by_type: dict[KnowledgeType, list[RetrievalCandidate]] = defaultdict(list)
        for item in candidates:
            by_type[item.knowledge_type].append(item)
        ordered: list[RetrievalCandidate] = []
        for item in candidates:
            if item is by_type[item.knowledge_type][0]:
                ordered.append(item)
        ordered.extend(item for item in candidates if item not in ordered)
        selected: list[RetrievalCandidate] = []
        parent_counts: dict[str, int] = defaultdict(int)
        total_bytes = 0
        for item in ordered:
            if len(selected) >= self.final_top_k:
                break
            if parent_counts[item.knowledge_id] >= 2:
                continue
            size = len(item.content.encode("utf-8"))
            if total_bytes + size > self.max_context_bytes:
                continue
            selected.append(item)
            parent_counts[item.knowledge_id] += 1
            total_bytes += size
        truncated = len(selected) < len(candidates)
        return selected, truncated
