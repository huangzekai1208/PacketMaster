"""RAG 应用层依赖的 embedding Provider 与知识存储协议。"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from packetmaster.rag.contracts import (
    KnowledgeBundle,
    KnowledgeQuery,
    RetrievalCandidate,
)


@runtime_checkable
class EmbeddingProvider(Protocol):
    @property
    def model_name(self) -> str: ...

    @property
    def dimension(self) -> int: ...

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]: ...

    async def embed_query(self, text: str) -> list[float]: ...


@runtime_checkable
class Reranker(Protocol):
    @property
    def model_name(self) -> str: ...

    async def rerank(
        self, query: str, documents: Sequence[str], *, top_n: int
    ) -> list[tuple[int, float]]: ...


@runtime_checkable
class KnowledgeStore(Protocol):
    async def keyword_search(
        self, query: KnowledgeQuery, *, limit: int
    ) -> list[RetrievalCandidate]: ...

    async def vector_search(
        self,
        query: KnowledgeQuery,
        vector: Sequence[float],
        *,
        limit: int,
    ) -> list[RetrievalCandidate]: ...

    async def get_candidate(self, chunk_id: str) -> RetrievalCandidate | None: ...


@runtime_checkable
class KnowledgeRetriever(Protocol):
    async def retrieve(self, query: KnowledgeQuery) -> KnowledgeBundle: ...
