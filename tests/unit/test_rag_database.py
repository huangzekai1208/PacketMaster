from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from packetmaster.errors import AppError
from packetmaster.rag.contracts import (
    CaseProfile,
    KnowledgeApplicability,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeStatus,
    KnowledgeVersion,
)
from packetmaster.rag.database import (
    KnowledgeDatabase,
    SQLiteKnowledgeStore,
    StoredEmbedding,
)


def _draft_models() -> tuple[
    KnowledgeDocument, KnowledgeVersion, list[KnowledgeChunk], CaseProfile
]:
    applicability = KnowledgeApplicability(
        directions=["download"], tags={"tool": "iperf3"}
    )
    document = KnowledgeDocument(
        knowledge_id="case.window.001",
        title="接收端窗口限制案例",
        knowledge_type="case",
        language="zh-CN",
        authority="medium_high",
        status="draft",
        summary="下载测速受接收窗口限制。",
        applicability=applicability,
    )
    version = KnowledgeVersion(
        version_id="case.window.001:v1",
        knowledge_id=document.knowledge_id,
        version_number=1,
        source_name="已关闭故障单",
        source_location="case 001",
        content_hash="a" * 64,
        status="draft",
        created_at=datetime(2026, 7, 27, tzinfo=UTC),
    )
    chunks = [
        KnowledgeChunk(
            chunk_id=f"case.window.001:v1:chunk-{index}",
            knowledge_id=document.knowledge_id,
            version_id=version.version_id,
            chunk_index=index,
            heading_path=[heading],
            source_location=f"case 001 / {heading}",
            content=content,
            content_hash=hash_character * 64,
            status="draft",
        )
        for index, (heading, content, hash_character) in enumerate(
            (
                ("现象", "下载吞吐明显偏低并持续出现接收端零窗口。", "b"),
                ("处置", "提升接收端处理能力后窗口恢复，复测吞吐达标。", "c"),
            )
        )
    ]
    case = CaseProfile(
        direction="download",
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=20,
        achievement_ratio_pct=2,
        tcp_features={"zero_window_count": 8},
        confirmed_primary_cause="接收端处理能力不足导致窗口耗尽",
        resolution="提升接收端处理能力并复测确认。",
        applicability=applicability,
    )
    return document, version, chunks, case


def _database(tmp_path: Path) -> KnowledgeDatabase:
    database = KnowledgeDatabase(tmp_path / "knowledge.sqlite")
    database.initialize()
    return database


def test_knowledge_database_initializes_idempotently_with_fts5(tmp_path: Path) -> None:
    database = _database(tmp_path)
    database.initialize()

    with database.connect() as connection:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]
        fts = connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'knowledge_chunks_fts'"
        ).fetchone()

    assert version == 1
    assert str(journal_mode).lower() == "wal"
    assert fts is not None


def test_save_draft_round_trips_without_entering_search(tmp_path: Path) -> None:
    database = _database(tmp_path)
    store = SQLiteKnowledgeStore(database)
    document, version, chunks, case = _draft_models()

    store.save_draft(document, version, chunks, case_profile=case)

    assert store.get_document(document.knowledge_id) == document
    assert store.get_version(version.version_id) == version
    assert store.get_chunks(version.version_id) == chunks
    assert store.get_case_profile(version.version_id) == case
    assert store.list_documents()[0] == [document]

    results = store.keyword_search_sync(
        KnowledgeQuery(query_id="query-1", query_text="零窗口"), limit=10
    )
    assert results == []


def test_publish_requires_complete_matching_embeddings(tmp_path: Path) -> None:
    database = _database(tmp_path)
    store = SQLiteKnowledgeStore(database)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)

    with pytest.raises(AppError, match="embedding") as missing:
        store.publish_version(version.version_id, approved_by="reviewer")
    assert missing.value.code == "KNOWLEDGE_INDEX_INCOMPLETE"

    store.save_embeddings(
        version.version_id,
        [
            StoredEmbedding(
                chunk_id=chunks[0].chunk_id,
                model_name="fake-embedding",
                dimension=2,
                vector=b"12345678",
                content_hash="f" * 64,
            )
        ],
    )
    with pytest.raises(AppError, match="hash") as mismatch:
        store.publish_version(version.version_id, approved_by="reviewer")
    assert mismatch.value.code == "KNOWLEDGE_INDEX_INCOMPLETE"


@pytest.mark.asyncio
async def test_published_knowledge_is_searchable_and_disable_removes_it(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    store = SQLiteKnowledgeStore(database)
    document, version, chunks, case = _draft_models()
    store.save_draft(document, version, chunks, case_profile=case)
    store.save_embeddings(
        version.version_id,
        [
            StoredEmbedding(
                chunk_id=chunk.chunk_id,
                model_name="fake-embedding",
                dimension=2,
                vector=b"12345678",
                content_hash=chunk.content_hash,
            )
            for chunk in chunks
        ],
    )

    store.publish_version(version.version_id, approved_by="reviewer")

    approved = store.get_document(document.knowledge_id)
    assert approved is not None
    assert approved.status is KnowledgeStatus.APPROVED
    assert approved.current_version_id == version.version_id
    results = await store.keyword_search(
        KnowledgeQuery(
            query_id="query-1",
            direction="download",
            query_text="接收端 零窗口",
            keywords=["零窗口"],
        ),
        limit=10,
    )
    assert results
    assert all(item.status is KnowledgeStatus.APPROVED for item in results)
    assert results[0].knowledge_id == document.knowledge_id

    store.disable_version(version.version_id, actor="reviewer", reason="已过期")

    assert await store.keyword_search(
        KnowledgeQuery(query_id="query-2", query_text="零窗口"), limit=10
    ) == []
    disabled = store.get_document(document.knowledge_id)
    assert disabled is not None
    assert disabled.status is KnowledgeStatus.DISABLED


def test_save_draft_is_atomic_and_rejects_cross_version_chunks(tmp_path: Path) -> None:
    database = _database(tmp_path)
    store = SQLiteKnowledgeStore(database)
    document, version, chunks, case = _draft_models()
    bad_chunk = chunks[0].model_copy(update={"version_id": "other:v1"})

    with pytest.raises(ValueError, match="version"):
        store.save_draft(document, version, [bad_chunk], case_profile=case)

    assert store.get_document(document.knowledge_id) is None


def test_database_does_not_define_capture_or_secret_columns(tmp_path: Path) -> None:
    database = _database(tmp_path)
    with database.connect() as connection:
        definitions = " ".join(
            str(row[0])
            for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
        ).lower()

    assert "pcap_path" not in definitions
    assert "payload" not in definitions
    assert "api_key" not in definitions
    assert "absolute_path" not in definitions
