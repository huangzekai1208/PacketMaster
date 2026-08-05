"""Deterministic evaluation identity and corpus/index preflight checks."""

from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.contracts import RagContract
from packetmaster.rag.database import KnowledgeDatabase
from packetmaster.rag.evaluation_contracts import (
    EvaluationDatasetV2,
    EvaluationIdentity,
    canonical_fingerprint,
)
from packetmaster.rag.evaluation_policy import (
    EvaluationPolicy,
    policy_fingerprint,
)
from packetmaster.rag.importer import KnowledgeImporter

_PROMPT_NAMES = (
    "chat_answer.md",
    "chat_verify.md",
    "general_chat.md",
    "knowledge_augmentation.md",
)


class EvaluationSnapshot(RagContract):
    identity: EvaluationIdentity
    approved_chunk_count: int = Field(ge=1)
    indexed_chunk_count: int = Field(ge=1)
    fts_chunk_count: int = Field(ge=1)


def _safe_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.scheme not in {"http", "https"}
        or not parsed.netloc
    ):
        raise ValueError("model endpoint must not contain credentials or query data")
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"


def _prompt_hashes(prompt_dir: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for name in _PROMPT_NAMES:
        content = prompt_dir.joinpath(name).read_bytes()
        values[name] = hashlib.sha256(content).hexdigest()
    return values


def _git_identity(root: Path) -> tuple[str, bool]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    dirty = bool(
        subprocess.run(
            ["git", "status", "--porcelain"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    )
    return revision, dirty


def _corpus_and_coverage(
    database: KnowledgeDatabase, *, model_name: str, dimension: int
) -> tuple[list[dict[str, object]], int, int]:
    with database.connect() as connection:
        rows = connection.execute(
            """
            SELECT d.knowledge_id, d.current_version_id AS version_id,
                   v.content_hash AS version_content_hash,
                   c.chunk_id, c.chunk_index, c.content_hash, c.media_json,
                   e.chunk_id IS NOT NULL
                     AND e.model_name = ?
                     AND e.dimension = ?
                     AND e.content_hash = c.content_hash AS indexed
            FROM knowledge_documents d
            JOIN knowledge_versions v ON v.version_id = d.current_version_id
            JOIN knowledge_chunks c ON c.version_id = d.current_version_id
            LEFT JOIN knowledge_embeddings e ON e.chunk_id = c.chunk_id
            WHERE d.status = 'approved' AND v.status = 'approved'
              AND c.status = 'approved'
            ORDER BY d.knowledge_id, c.chunk_index, c.chunk_id
            """,
            (model_name, dimension),
        ).fetchall()
        fts_ids = {
            str(row[0])
            for row in connection.execute(
                "SELECT chunk_id FROM knowledge_chunks_fts"
            ).fetchall()
        }
    snapshot: list[dict[str, object]] = []
    indexed_count = 0
    approved_ids: set[str] = set()
    for row in rows:
        media = json.loads(str(row["media_json"]))
        media_hashes = sorted(
            str(item["content_hash"])
            for item in media
            if isinstance(item, dict) and item.get("content_hash")
        )
        indexed_count += int(bool(row["indexed"]))
        chunk_id = str(row["chunk_id"])
        approved_ids.add(chunk_id)
        snapshot.append(
            {
                "knowledge_id": str(row["knowledge_id"]),
                "version_id": str(row["version_id"]),
                "version_content_hash": str(row["version_content_hash"]),
                "chunk_id": chunk_id,
                "chunk_index": int(row["chunk_index"]),
                "content_hash": str(row["content_hash"]),
                "media_hashes": media_hashes,
            }
        )
    return snapshot, indexed_count, len(approved_ids & fts_ids)


def build_evaluation_snapshot(
    *,
    database: KnowledgeDatabase,
    settings: Settings,
    dataset: EvaluationDatasetV2,
    policy: EvaluationPolicy,
    prompt_dir: Path,
    repository_root: Path | None = None,
    code_revision: str | None = None,
    dirty: bool | None = None,
    judge_config: dict[str, object] | None = None,
) -> EvaluationSnapshot:
    corpus, indexed_count, fts_count = _corpus_and_coverage(
        database,
        model_name=settings.effective_embedding_model,
        dimension=settings.effective_embedding_dimension,
    )
    if not corpus:
        raise AppError(
            code="EVALUATION_CORPUS_MISMATCH",
            message="当前没有可用于评测的正式知识切片",
            recoverable=True,
            suggested_action="请先审核发布知识并完成索引。",
        )
    approved_ids = {str(item["chunk_id"]) for item in corpus}
    labeled_ids = {
        chunk_id for case in dataset.cases for chunk_id in case.relevant_chunk_ids
    }
    missing_labels = sorted(labeled_ids - approved_ids)
    if missing_labels:
        raise AppError(
            code="EVALUATION_CORPUS_MISMATCH",
            message="V2 评测标注切片与当前正式知识库不匹配",
            recoverable=True,
            suggested_action="请切换知识快照或人工迁移标注。",
            details={
                "missing_chunk_count": len(missing_labels),
                "missing_chunk_ids": missing_labels[:10],
            },
        )
    if indexed_count != len(corpus):
        raise AppError(
            code="EVALUATION_INDEX_INCOMPLETE",
            message="当前 Embedding Profile 未完整覆盖正式知识",
            recoverable=True,
            suggested_action="请完成全部正式切片的向量重建后重试。",
            details={
                "approved_chunk_count": len(corpus),
                "indexed_chunk_count": indexed_count,
            },
        )
    if fts_count != len(corpus):
        raise AppError(
            code="EVALUATION_INDEX_INCOMPLETE",
            message="当前 BM25 索引与正式知识快照不一致",
            recoverable=True,
            suggested_action="请重建正式知识的 FTS5 索引后重试。",
            details={
                "approved_chunk_count": len(corpus),
                "fts_chunk_count": fts_count,
            },
        )
    if code_revision is None or dirty is None:
        if repository_root is None:
            raise ValueError("repository root is required for Git identity")
        detected_revision, detected_dirty = _git_identity(repository_root)
        code_revision = code_revision or detected_revision
        dirty = detected_dirty if dirty is None else dirty
    importer = KnowledgeImporter()
    chunking = {
        "implementation_version": 1,
        "target_chunk_chars": importer.target_chunk_chars,
        "max_chunk_chars": importer.max_chunk_chars,
        "overlap_chars": importer.overlap_chars,
        "max_image_bytes": importer.max_image_bytes,
        "markdown_image_policy": "local-descendant-png-jpeg-webp-v1",
    }
    embedding = {
        "provider": settings.embedding_provider,
        "model": settings.effective_embedding_model,
        "dimension": settings.effective_embedding_dimension,
        "endpoint": _safe_endpoint(
            settings.embedding_multimodal_base_url
            if settings.effective_embedding_model == "qwen3-vl-embedding"
            else settings.embedding_base_url
        ),
        "normalization": "l2",
        "preprocessing_version": "packetmaster-multimodal-v1",
    }
    retrieval = {
        "keyword_algorithm": "sqlite-fts5-bm25",
        "keyword_top_k": settings.rag_keyword_top_k,
        "vector_top_k": settings.rag_vector_top_k,
        "vector_timeout_seconds": settings.rag_vector_timeout_seconds,
        "rrf_k": 60,
        "authority_boost_version": 1,
        "reranker_candidate_top_k": settings.reranker_candidate_top_k,
        "reranker_timeout_seconds": settings.reranker_timeout_seconds,
        "final_top_k": settings.rag_final_top_k,
        "max_context_bytes": settings.rag_max_context_bytes,
        "total_timeout_seconds": settings.rag_timeout_seconds,
    }
    reranker = {
        "enabled": settings.reranker_enabled,
        "provider": "dashscope" if settings.reranker_enabled else "none",
        "model": settings.reranker_model if settings.reranker_enabled else "none",
        "endpoint": (
            _safe_endpoint(settings.reranker_base_url)
            if settings.reranker_enabled
            else "none"
        ),
        "max_document_chars": settings.reranker_max_document_chars,
        "document_format_version": 1,
    }
    generation = {
        "provider": "openai-compatible",
        "model": settings.model_name,
        "endpoint": (
            _safe_endpoint(settings.model_base_url)
            if settings.model_base_url
            else "provider-default"
        ),
        "structured_output_method": settings.model_structured_output_method,
        "prompt_hashes": _prompt_hashes(prompt_dir),
    }
    judge = judge_config or {"enabled": False, "version": 1}
    identity = EvaluationIdentity(
        dataset_fingerprint=canonical_fingerprint(dataset),
        corpus_fingerprint=canonical_fingerprint({"chunks": corpus}),
        chunking_fingerprint=canonical_fingerprint(chunking),
        embedding_fingerprint=canonical_fingerprint(embedding),
        retrieval_fingerprint=canonical_fingerprint(retrieval),
        reranker_fingerprint=canonical_fingerprint(reranker),
        generation_fingerprint=canonical_fingerprint(generation),
        judge_fingerprint=canonical_fingerprint(judge),
        policy_fingerprint=policy_fingerprint(policy),
        code_revision=code_revision,
        dirty=bool(dirty),
    )
    return EvaluationSnapshot(
        identity=identity,
        approved_chunk_count=len(corpus),
        indexed_chunk_count=indexed_count,
        fts_chunk_count=fts_count,
    )
