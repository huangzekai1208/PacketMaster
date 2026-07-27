from __future__ import annotations

import math
from pathlib import Path

import pytest

from packetmaster.errors import AppError
from packetmaster.rag.contracts import KnowledgeQuery
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.embedding import (
    EmbeddingIndexer,
    LocalEmbeddingProvider,
    normalize_vector,
)
from tests.unit.test_rag_database import _draft_models


class FakeEmbeddingProvider:
    model_name = "fake-multilingual-e5"
    dimension = 2

    def __init__(self) -> None:
        self.document_inputs: list[str] = []
        self.query_inputs: list[str] = []

    async def embed_documents(self, texts):
        self.document_inputs.extend(texts)
        return [
            [1.0, 0.0] if "零窗口" in text else [0.0, 1.0]
            for text in texts
        ]

    async def embed_query(self, text):
        self.query_inputs.append(text)
        return [1.0, 0.0] if "零窗口" in text else [0.0, 1.0]


def _store(tmp_path: Path) -> SQLiteKnowledgeStore:
    database = KnowledgeDatabase(tmp_path / "knowledge.sqlite")
    database.initialize()
    return SQLiteKnowledgeStore(
        database,
        embedding_model="fake-multilingual-e5",
        embedding_dimension=2,
    )


@pytest.mark.asyncio
async def test_indexer_builds_vectors_and_vector_search_ranks_semantic_match(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)
    provider = FakeEmbeddingProvider()

    indexed = await EmbeddingIndexer(store, provider).index_version(version.version_id)
    store.publish_version(version.version_id, approved_by="reviewer")
    query_vector = await provider.embed_query("零窗口导致吞吐下降")
    results = await store.vector_search(
        KnowledgeQuery(query_id="query-1", query_text="零窗口导致吞吐下降"),
        query_vector,
        limit=10,
    )

    assert indexed == len(chunks)
    assert provider.document_inputs == [chunk.content for chunk in chunks]
    assert results[0].chunk_id == chunks[0].chunk_id
    assert results[0].vector_rank == 1
    assert results[0].rerank_score > results[1].rerank_score

    calls_before_resume = len(provider.document_inputs)
    resumed = await EmbeddingIndexer(store, provider).index_version(
        version.version_id
    )
    assert resumed == 0
    assert len(provider.document_inputs) == calls_before_resume


@pytest.mark.asyncio
async def test_indexer_rejects_non_finite_and_wrong_dimension_vectors(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)

    class BadProvider(FakeEmbeddingProvider):
        async def embed_documents(self, texts):
            return [[math.nan, 0.0] for _ in texts]

    with pytest.raises(AppError, match="invalid") as raised:
        await EmbeddingIndexer(store, BadProvider()).index_version(version.version_id)
    assert raised.value.code == "INVALID_EMBEDDING_OUTPUT"


def test_vector_normalization_rejects_empty_zero_and_non_finite_values() -> None:
    for vector in ([], [0.0, 0.0], [1.0, math.inf]):
        with pytest.raises(ValueError):
            normalize_vector(vector, expected_dimension=2)


@pytest.mark.asyncio
async def test_local_e5_provider_adds_query_and_passage_prefixes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = LocalEmbeddingProvider(dimension=2)
    captured: list[list[str]] = []

    def fake_encode(texts):
        captured.append(list(texts))
        return [[1.0, 0.0] for _ in texts]

    monkeypatch.setattr(provider, "_encode", fake_encode)

    await provider.embed_documents(["知识正文"])
    await provider.embed_query("查询内容")

    assert captured == [["passage: 知识正文"], ["query: 查询内容"]]


@pytest.mark.asyncio
async def test_vector_search_rejects_dimension_mismatch(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(AppError, match="dimension") as raised:
        await store.vector_search(
            KnowledgeQuery(query_id="query-1", query_text="窗口限制"),
            [1.0, 0.0, 0.0],
            limit=5,
        )
    assert raised.value.code == "INVALID_QUERY_VECTOR"
