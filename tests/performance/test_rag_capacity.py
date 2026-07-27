from __future__ import annotations

import asyncio
import math
import time
from pathlib import Path

import pytest

from packetmaster.rag.contracts import KnowledgeQuery
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.embedding import encode_vector
from packetmaster.rag.retrieval import HybridKnowledgeRetriever
from tests.unit.test_rag_database import _draft_models

pytestmark = pytest.mark.performance


class _Provider:
    model_name = "capacity-fake"
    dimension = 2

    async def embed_query(self, text):
        return [1.0, 0.0]

    async def embed_documents(self, texts):
        return [[1.0, 0.0] for _ in texts]


def test_twenty_five_thousand_chunk_retrieval_p95_is_below_two_seconds(
    tmp_path: Path,
) -> None:
    database = KnowledgeDatabase(tmp_path / "knowledge.sqlite")
    database.initialize()
    store = SQLiteKnowledgeStore(
        database, embedding_model="capacity-fake", embedding_dimension=2
    )
    document, version, chunks, case = _draft_models()
    first = chunks[0].model_copy(
        update={"content": "零窗口限制吞吐 capacity-0"}
    )
    store.save_draft(document, version, [first], case_profile=case)
    vector = encode_vector([1.0, 0.0])
    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            WITH RECURSIVE sequence(value) AS (
                VALUES(1) UNION ALL SELECT value + 1 FROM sequence
                WHERE value < 24999
            )
            INSERT INTO knowledge_chunks (
                chunk_id, knowledge_id, version_id, chunk_index,
                heading_path_json, source_location, content, content_hash, status
            )
            SELECT 'case.window.001:v1:capacity-' || value, ?, ?, value,
                   '[]', '', '零窗口限制吞吐 capacity-' || value, ?, 'draft'
            FROM sequence
            """,
            (document.knowledge_id, version.version_id, first.content_hash),
        )
        connection.execute(
            """
            INSERT INTO knowledge_embeddings (
                chunk_id, model_name, dimension, vector, content_hash, created_at
            )
            SELECT chunk_id, 'capacity-fake', 2, ?, content_hash,
                   '2026-07-27T00:00:00+00:00'
            FROM knowledge_chunks WHERE version_id = ?
            """,
            (vector, version.version_id),
        )
    store.publish_version(version.version_id, approved_by="performance-gate")
    retriever = HybridKnowledgeRetriever(
        store, _Provider(), timeout_seconds=2.0
    )
    query = KnowledgeQuery(
        query_id="capacity-query", query_text="零窗口限制吞吐", keywords=["零窗口"]
    )

    async def measure() -> list[float]:
        await retriever.retrieve(query)
        durations = []
        for _ in range(20):
            started = time.perf_counter()
            bundle = await retriever.retrieve(query)
            durations.append(time.perf_counter() - started)
            assert bundle.results
            assert bundle.total_content_bytes <= 24_576
        return durations

    durations = asyncio.run(measure())
    p95 = sorted(durations)[max(0, math.ceil(len(durations) * 0.95) - 1)]
    assert p95 <= 2.0
