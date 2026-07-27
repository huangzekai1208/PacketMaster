from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from packetmaster.config import Settings
from packetmaster.rag.base import EmbeddingProvider, KnowledgeRetriever, KnowledgeStore
from packetmaster.rag.contracts import (
    AuthorityLevel,
    CaseProfile,
    KnowledgeApplicability,
    KnowledgeBundle,
    KnowledgeChunk,
    KnowledgeCitation,
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeStatus,
    KnowledgeType,
    KnowledgeVersion,
    RagMode,
    RetrievalCandidate,
)


def _applicability() -> KnowledgeApplicability:
    return KnowledgeApplicability(
        directions=["download"],
        operating_systems=["Windows"],
        tags={"tool": "iperf3"},
    )


def _document() -> KnowledgeDocument:
    return KnowledgeDocument(
        knowledge_id="kb.tcp.window",
        title="TCP 接收窗口限制",
        knowledge_type="standard",
        language="zh-CN",
        authority="high",
        status="approved",
        summary="接收窗口与带宽时延积共同限制单流吞吐。",
        applicability=_applicability(),
        current_version_id="kb.tcp.window:v1",
    )


def _version() -> KnowledgeVersion:
    return KnowledgeVersion(
        version_id="kb.tcp.window:v1",
        knowledge_id="kb.tcp.window",
        version_number=1,
        source_name="RFC 7323",
        source_location="section 2.2",
        content_hash="a" * 64,
        status="approved",
        created_at=datetime(2026, 7, 27, tzinfo=UTC),
        approved_at=datetime(2026, 7, 27, tzinfo=UTC),
        approved_by="reviewer-1",
    )


def _candidate() -> RetrievalCandidate:
    return RetrievalCandidate(
        knowledge_id="kb.tcp.window",
        version_id="kb.tcp.window:v1",
        chunk_id="kb.tcp.window:v1:chunk-1",
        title="TCP 接收窗口限制",
        knowledge_type="standard",
        authority="high",
        source_name="RFC 7323",
        source_location="section 2.2",
        applicability=_applicability(),
        content="接收窗口需要覆盖链路带宽时延积，否则会限制吞吐。",
        keyword_rank=1,
        vector_rank=2,
        fusion_score=0.03,
        rerank_score=0.92,
    )


def test_rag_contracts_accept_versioned_approved_knowledge() -> None:
    document = _document()
    version = _version()
    chunk = KnowledgeChunk(
        chunk_id="kb.tcp.window:v1:chunk-1",
        knowledge_id=document.knowledge_id,
        version_id=version.version_id,
        chunk_index=0,
        heading_path=["TCP 扩展", "窗口缩放"],
        source_location="section 2.2",
        content="接收窗口需要覆盖链路带宽时延积。",
        content_hash="b" * 64,
        status="approved",
    )

    assert document.knowledge_type is KnowledgeType.STANDARD
    assert document.authority is AuthorityLevel.HIGH
    assert version.status is KnowledgeStatus.APPROVED
    assert chunk.version_id == version.version_id

    with pytest.raises(ValidationError, match="current version"):
        KnowledgeDocument.model_validate(
            {**document.model_dump(), "current_version_id": None}
        )


def test_rag_contracts_reject_extra_fields_and_invalid_hash() -> None:
    with pytest.raises(ValidationError, match="extra"):
        KnowledgeDocument.model_validate(
            {**_document().model_dump(), "raw_capture_path": "/captures/a.pcapng"}
        )

    with pytest.raises(ValidationError, match="content_hash"):
        KnowledgeVersion.model_validate(
            {**_version().model_dump(), "content_hash": "not-a-sha256"}
        )


def test_source_location_rejects_local_absolute_paths() -> None:
    for source_location in (
        "/Users/operator/private/rfc.md",
        r"C:\Users\operator\private\case.md",
    ):
        with pytest.raises(ValidationError, match="source_location"):
            KnowledgeVersion.model_validate(
                {**_version().model_dump(), "source_location": source_location}
            )


def test_case_profile_bounds_structured_diagnosis_features() -> None:
    case = CaseProfile(
        direction="download",
        standard_bandwidth_mbps=1000,
        actual_bandwidth_mbps=20,
        achievement_ratio_pct=2,
        tcp_features={"retransmission_ratio": 0.12, "zero_window_count": 4},
        confirmed_primary_cause="接收端窗口耗尽",
        resolution="调整接收端处理能力后复测恢复。",
        applicability=_applicability(),
    )

    assert case.direction.value == "download"
    with pytest.raises(ValidationError, match="tcp_features"):
        CaseProfile.model_validate(
            {**case.model_dump(), "tcp_features": {f"metric-{i}": i for i in range(65)}}
        )


def test_query_and_bundle_enforce_result_and_context_bounds() -> None:
    query = KnowledgeQuery(
        query_id="query-1",
        analysis_id="analysis-1",
        direction="download",
        achievement_ratio_pct=2,
        query_text="下载吞吐低，出现 Zero Window",
        keywords=["zero_window", "receive window"],
        candidate_causes=["接收端处理能力不足"],
        global_features={"zero_window_count": 4},
        environment_tags={"operating_system": "Windows"},
    )
    bundle = KnowledgeBundle(
        query_id=query.query_id,
        results=[_candidate()],
        total_content_bytes=len(_candidate().content.encode("utf-8")),
    )

    assert bundle.results[0].knowledge_type is KnowledgeType.STANDARD
    assert bundle.results[0].status is KnowledgeStatus.APPROVED
    with pytest.raises(ValidationError, match="results"):
        KnowledgeBundle(
            query_id=query.query_id,
            results=[_candidate()] * 9,
            total_content_bytes=1,
        )
    with pytest.raises(ValidationError, match="total_content_bytes"):
        KnowledgeBundle(
            query_id=query.query_id,
            results=[_candidate()],
            total_content_bytes=24_577,
        )


def test_retrieval_candidate_rejects_unapproved_knowledge() -> None:
    with pytest.raises(ValidationError, match="approved"):
        RetrievalCandidate.model_validate(
            {**_candidate().model_dump(), "status": "draft"}
        )


def test_citation_identifies_supported_statement_and_exact_chunk() -> None:
    citation = KnowledgeCitation(
        knowledge_id="kb.tcp.window",
        version_id="kb.tcp.window:v1",
        chunk_id="kb.tcp.window:v1:chunk-1",
        title="TCP 接收窗口限制",
        knowledge_type="standard",
        source_name="RFC 7323",
        source_location="section 2.2",
        supported_statement="接收窗口不足可能限制单流吞吐。",
        supporting_quote="接收窗口需要覆盖链路带宽时延积",
    )

    assert citation.chunk_id.endswith("chunk-1")
    with pytest.raises(ValidationError, match="supported_statement"):
        KnowledgeCitation.model_validate(
            {**citation.model_dump(), "supported_statement": ""}
        )


def test_settings_default_to_disabled_shadow_rag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "RAG_ENABLED",
        "RAG_MODE",
        "KNOWLEDGE_DATABASE_PATH",
        "EMBEDDING_PROVIDER",
        "EMBEDDING_MODEL",
        "EMBEDDING_MODEL_PATH",
        "RAG_KEYWORD_TOP_K",
        "RAG_VECTOR_TOP_K",
        "RAG_FINAL_TOP_K",
        "RAG_MAX_CONTEXT_BYTES",
        "RAG_TIMEOUT_SECONDS",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = Settings.load()

    assert settings.rag_enabled is False
    assert settings.rag_mode is RagMode.SHADOW
    assert settings.effective_rag_mode is RagMode.OFF
    assert settings.rag_final_top_k == 8
    assert settings.rag_max_context_bytes == 24_576


def test_settings_parse_active_rag_and_reject_unsafe_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("RAG_ENABLED", "true")
    monkeypatch.setenv("RAG_MODE", "active")

    settings = Settings.load()

    assert settings.effective_rag_mode is RagMode.ACTIVE

    monkeypatch.setenv("RAG_FINAL_TOP_K", "9")
    with pytest.raises(ValidationError, match="RAG_FINAL_TOP_K|rag_final_top_k"):
        Settings.load()


def test_sensitive_rag_paths_are_excluded_from_settings_dump(tmp_path) -> None:
    settings = Settings(
        knowledge_database_path=tmp_path / "private" / "knowledge.sqlite",
        embedding_model_path=tmp_path / "private" / "embedding-model",
    )

    dumped = settings.model_dump(mode="json")
    rendered = repr(settings)

    assert "knowledge_database_path" not in dumped
    assert "embedding_model_path" not in dumped
    assert str(tmp_path) not in rendered


def test_rag_abstractions_are_runtime_checkable() -> None:
    assert getattr(EmbeddingProvider, "_is_runtime_protocol", False)
    assert getattr(KnowledgeStore, "_is_runtime_protocol", False)
    assert getattr(KnowledgeRetriever, "_is_runtime_protocol", False)
