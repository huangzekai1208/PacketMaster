from __future__ import annotations

import json
import math
from pathlib import Path

import pytest

import packetmaster.rag.embedding as embedding_module
from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.contracts import KnowledgeImage, KnowledgeQuery
from packetmaster.rag.database import (
    KnowledgeDatabase,
    SQLiteKnowledgeStore,
    StoredEmbedding,
)
from packetmaster.rag.embedding import (
    DashScopeEmbeddingProvider,
    DashScopeMultimodalEmbeddingProvider,
    EmbeddingIndexer,
    build_embedding_provider,
    encode_vector,
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
async def test_dashscope_provider_uses_compatible_api_and_response_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = DashScopeEmbeddingProvider(
        "text-embedding-v4",
        api_key="secret",
        dimension=2,
        base_url="https://example.invalid/compatible-mode/v1/",
        timeout_seconds=1,
        max_retries=0,
    )
    captured: dict[str, object] = {}

    def fake_request(texts):
        captured["texts"] = list(texts)
        return [[0.0, 1.0], [1.0, 0.0]]

    monkeypatch.setattr(provider, "_request", fake_request)

    result = await provider.embed_documents(["first", "second"])

    assert provider.model_name == "text-embedding-v4"
    assert provider.dimension == 2
    assert provider._endpoint == "https://example.invalid/compatible-mode/v1/embeddings"
    assert captured["texts"] == ["first", "second"]
    assert result == [[0.0, 1.0], [1.0, 0.0]]


def test_dashscope_request_uses_bearer_auth_and_orders_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = DashScopeEmbeddingProvider(
        "text-embedding-v4",
        api_key="secret",
        dimension=2,
        base_url="https://example.invalid/compatible-mode/v1",
        timeout_seconds=1,
        max_retries=0,
    )
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        @staticmethod
        def read() -> bytes:
            return json.dumps(
                {
                    "data": [
                        {"index": 1, "embedding": [0.0, 1.0]},
                        {"index": 0, "embedding": [1.0, 0.0]},
                    ]
                }
            ).encode("utf-8")

    def fake_urlopen(request, *, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(embedding_module, "urlopen", fake_urlopen)

    assert provider._request(["first", "second"]) == [[1.0, 0.0], [0.0, 1.0]]
    assert captured == {
        "url": "https://example.invalid/compatible-mode/v1/embeddings",
        "authorization": "Bearer secret",
        "payload": {"model": "text-embedding-v4", "input": ["first", "second"]},
        "timeout": 1,
    }


def test_dashscope_provider_requires_an_api_key() -> None:
    with pytest.raises(AppError) as raised:
        DashScopeEmbeddingProvider(
            "text-embedding-v4",
            api_key=None,
            dimension=1024,
            base_url="https://example.invalid/v1",
            timeout_seconds=1,
            max_retries=0,
        )
    assert raised.value.code == "EMBEDDING_AUTH_MISSING"


def test_embedding_provider_factory_uses_provider_defaults() -> None:
    provider = build_embedding_provider(Settings(embedding_api_key="secret"))

    assert isinstance(provider, DashScopeMultimodalEmbeddingProvider)
    assert (provider.model_name, provider.dimension) == ("qwen3-vl-embedding", 2560)


def test_multimodal_provider_sends_text_and_image_in_native_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = DashScopeMultimodalEmbeddingProvider(
        "qwen3-vl-embedding",
        api_key="secret",
        dimension=2,
        base_url="https://example.invalid/multimodal-embedding",
        timeout_seconds=1,
        max_retries=0,
    )
    captured: dict[str, object] = {}

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        @staticmethod
        def read() -> bytes:
            return json.dumps(
                {"output": {"embeddings": [{"embedding": [1.0, 0.0]}]}}
            ).encode("utf-8")

    def fake_urlopen(request, *, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(embedding_module, "urlopen", fake_urlopen)

    assert provider._request_contents(
        [{"text": "下载测速拓扑", "image": "data:image/png;base64,AAAA"}]
    ) == [[1.0, 0.0]]
    assert captured == {
        "url": "https://example.invalid/multimodal-embedding",
        "authorization": "Bearer secret",
        "payload": {
            "model": "qwen3-vl-embedding",
            "input": {
                "contents": [
                    {"text": "下载测速拓扑", "image": "data:image/png;base64,AAAA"}
                ]
            },
        },
        "timeout": 1,
    }


@pytest.mark.asyncio
async def test_indexer_uses_multimodal_provider_for_chunk_media(tmp_path: Path) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    image = KnowledgeImage(
        source_ref="images/topology.png",
        alt_text="测速拓扑",
        mime_type="image/png",
        data_url="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
        content_hash="d" * 64,
    )
    chunks[0] = chunks[0].model_copy(update={"media": [image]})
    store.save_draft(document, version, chunks, case_profile=case)

    class MultimodalProvider(FakeEmbeddingProvider):
        multimodal_inputs: list[tuple[str, list[KnowledgeImage]]]

        def __init__(self) -> None:
            super().__init__()
            self.multimodal_inputs = []

        async def embed_multimodal_documents(self, documents):
            self.multimodal_inputs.extend(
                (text, list(media)) for text, media in documents
            )
            return [[1.0, 0.0] for _ in documents]

    provider = MultimodalProvider()
    assert await EmbeddingIndexer(store, provider).index_version(version.version_id) == 2
    assert provider.document_inputs == []
    assert provider.multimodal_inputs[0] == (chunks[0].content, [image])


@pytest.mark.asyncio
async def test_indexer_rejects_media_when_provider_is_text_only(tmp_path: Path) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    image = KnowledgeImage(
        source_ref="images/topology.png",
        alt_text="测速拓扑",
        mime_type="image/png",
        data_url="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ",
        content_hash="d" * 64,
    )
    chunks[0] = chunks[0].model_copy(update={"media": [image]})
    store.save_draft(document, version, chunks, case_profile=case)

    with pytest.raises(AppError) as raised:
        await EmbeddingIndexer(store, FakeEmbeddingProvider()).index_version(
            version.version_id
        )
    assert raised.value.code == "EMBEDDING_MULTIMODAL_UNSUPPORTED"


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


@pytest.mark.asyncio
async def test_independent_store_refreshes_vector_cache_after_generation_change(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)
    await EmbeddingIndexer(store, FakeEmbeddingProvider()).index_version(
        version.version_id
    )
    store.publish_version(version.version_id, approved_by="reviewer")
    reader = SQLiteKnowledgeStore(
        store.database,
        embedding_model="fake-multilingual-e5",
        embedding_dimension=2,
    )
    query = KnowledgeQuery(query_id="query-1", query_text="零窗口")

    first = await reader.vector_search(query, [1.0, 0.0], limit=2)
    store.save_embeddings(
        version.version_id,
        [
            StoredEmbedding(
                chunk_id=chunks[0].chunk_id,
                model_name="fake-multilingual-e5",
                dimension=2,
                vector=encode_vector([0.0, 1.0]),
                content_hash=chunks[0].content_hash,
            ),
            StoredEmbedding(
                chunk_id=chunks[1].chunk_id,
                model_name="fake-multilingual-e5",
                dimension=2,
                vector=encode_vector([1.0, 0.0]),
                content_hash=chunks[1].content_hash,
            ),
        ],
    )
    refreshed = await reader.vector_search(query, [1.0, 0.0], limit=2)

    assert first[0].chunk_id == chunks[0].chunk_id
    assert refreshed[0].chunk_id == chunks[1].chunk_id


@pytest.mark.asyncio
async def test_failed_force_rebuild_preserves_previous_complete_index(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)
    provider = FakeEmbeddingProvider()
    await EmbeddingIndexer(store, provider, batch_size=1).index_version(
        version.version_id
    )
    before = store.indexed_chunk_ids(
        version.version_id,
        model_name=provider.model_name,
        dimension=provider.dimension,
    )
    with store.database.connect() as connection:
        vectors_before = {
            row["chunk_id"]: bytes(row["vector"])
            for row in connection.execute(
                "SELECT chunk_id, vector FROM knowledge_embeddings"
            )
        }

    class FailingRebuildProvider(FakeEmbeddingProvider):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0

        async def embed_documents(self, texts):
            self.calls += 1
            if self.calls == 2:
                raise ValueError("forced rebuild failed")
            return [[0.0, 1.0] for _ in texts]

    with pytest.raises(AppError) as raised:
        await EmbeddingIndexer(
            store, FailingRebuildProvider(), batch_size=1
        ).index_version(version.version_id, force=True)

    after = store.indexed_chunk_ids(
        version.version_id,
        model_name=provider.model_name,
        dimension=provider.dimension,
    )
    with store.database.connect() as connection:
        vectors_after = {
            row["chunk_id"]: bytes(row["vector"])
            for row in connection.execute(
                "SELECT chunk_id, vector FROM knowledge_embeddings"
            )
        }
    assert raised.value.code == "INVALID_EMBEDDING_OUTPUT"
    assert after == before == {chunk.chunk_id for chunk in chunks}
    assert vectors_after == vectors_before
