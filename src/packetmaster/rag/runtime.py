"""RAG 运行时构建与 active 模式评估门禁控制。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.contracts import RagMode
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.embedding import build_embedding_provider
from packetmaster.rag.query import KnowledgeQueryBuilder
from packetmaster.rag.retrieval import HybridKnowledgeRetriever
from packetmaster.rag.validation import KnowledgeCitationValidator


@dataclass(frozen=True)
class RagRuntime:
    mode: RagMode
    store: Any
    retriever: Any
    query_builder: KnowledgeQueryBuilder
    citation_validator: KnowledgeCitationValidator
    degradation_reason: str | None = None


class _UnavailableStore:
    async def get_candidate(self, chunk_id: str):
        return None


class _UnavailableRetriever:
    def __init__(self, code: str) -> None:
        self.code = code

    async def retrieve(self, query):
        from packetmaster.errors import AppError

        raise AppError(
            code=self.code,
            message="RAG 运行时不可用",
            recoverable=True,
            suggested_action="基础诊断将继续，请检查知识库健康状态。",
        )


def _unavailable_runtime(code: str) -> RagRuntime:
    store = _UnavailableStore()
    return RagRuntime(
        mode=RagMode.SHADOW,
        store=store,
        retriever=_UnavailableRetriever(code),
        query_builder=KnowledgeQueryBuilder(),
        citation_validator=KnowledgeCitationValidator(store),
        degradation_reason=code,
    )


def build_rag_runtime(settings: Settings) -> RagRuntime | None:
    requested_mode = settings.effective_rag_mode
    if requested_mode is RagMode.OFF:
        return None
    database = KnowledgeDatabase(settings.knowledge_database_path)
    try:
        database.initialize()
    except Exception:
        return _unavailable_runtime("RAG_DATABASE_UNAVAILABLE")
    try:
        provider = build_embedding_provider(settings)
        store = SQLiteKnowledgeStore(
            database,
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
    except AppError as exc:
        return _unavailable_runtime(exc.code)
    except Exception:
        return _unavailable_runtime("RAG_DATABASE_UNAVAILABLE")
    mode = requested_mode
    degradation_reason = None
    if mode is RagMode.ACTIVE and not store.active_gate_passed():
        mode = RagMode.SHADOW
        degradation_reason = "RAG_ACTIVE_GATE_NOT_PASSED"
    retriever = HybridKnowledgeRetriever(
        store,
        provider,
        keyword_top_k=settings.rag_keyword_top_k,
        vector_top_k=settings.rag_vector_top_k,
        final_top_k=settings.rag_final_top_k,
        max_context_bytes=settings.rag_max_context_bytes,
        timeout_seconds=settings.rag_timeout_seconds,
        fail_on_vector_error=True,
    )
    return RagRuntime(
        mode=mode,
        store=store,
        retriever=retriever,
        query_builder=KnowledgeQueryBuilder(),
        citation_validator=KnowledgeCitationValidator(store),
        degradation_reason=degradation_reason,
    )
