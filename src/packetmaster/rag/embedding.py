"""Local multilingual embedding provider and version indexer."""

from __future__ import annotations

import asyncio
import math
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from packetmaster.errors import AppError
from packetmaster.rag.base import EmbeddingProvider
from packetmaster.rag.database import SQLiteKnowledgeStore, StoredEmbedding


def normalize_vector(
    vector: Sequence[float], *, expected_dimension: int | None = None
) -> list[float]:
    values = [float(item) for item in vector]
    if not values or (
        expected_dimension is not None and len(values) != expected_dimension
    ):
        raise ValueError("embedding vector dimension is invalid")
    if any(not math.isfinite(item) for item in values):
        raise ValueError("embedding vector contains a non-finite value")
    norm = math.sqrt(sum(item * item for item in values))
    if norm <= 0:
        raise ValueError("embedding vector norm must be positive")
    return [item / norm for item in values]


def encode_vector(vector: Sequence[float]) -> bytes:
    return struct.pack(f"<{len(vector)}f", *vector)


def decode_vector(value: bytes, dimension: int) -> tuple[float, ...]:
    if dimension < 1 or len(value) != dimension * 4:
        raise ValueError("stored embedding vector size is invalid")
    return struct.unpack(f"<{dimension}f", value)


class LocalEmbeddingProvider:
    """Lazy sentence-transformers provider; base installs do not import it."""

    def __init__(
        self,
        model_name: str = "intfloat/multilingual-e5-small",
        *,
        model_path: Path | None = None,
        dimension: int = 384,
    ) -> None:
        self._model_name = model_name
        self.model_path = model_path
        self._dimension = dimension
        self._model: Any | None = None

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    def _load(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise AppError(
                code="RAG_DEPENDENCY_MISSING",
                message="本地 Embedding 依赖尚未安装",
                recoverable=True,
                suggested_action="请安装 PacketMaster 的 rag 可选依赖。",
            ) from exc
        model_source = str(self.model_path) if self.model_path else self.model_name
        try:
            self._model = SentenceTransformer(model_source)
        except Exception as exc:
            raise AppError(
                code="EMBEDDING_MODEL_UNAVAILABLE",
                message="无法加载本地 Embedding 模型",
                recoverable=True,
                suggested_action="请检查联网状态或 EMBEDDING_MODEL_PATH。",
            ) from exc
        model_dimension = self._model.get_sentence_embedding_dimension()
        if model_dimension != self.dimension:
            raise AppError(
                code="EMBEDDING_DIMENSION_MISMATCH",
                message="Embedding 模型维度与配置不一致",
                recoverable=True,
                suggested_action="请重建知识向量索引并校正模型配置。",
            )
        return self._model

    def _encode(self, texts: Sequence[str]) -> list[list[float]]:
        model = self._load()
        values = model.encode(
            list(texts),
            normalize_embeddings=True,
            convert_to_numpy=True,
            show_progress_bar=False,
        )
        return [[float(item) for item in row] for row in values]

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        passages = [f"passage: {text}" for text in texts]
        return await asyncio.to_thread(self._encode, passages)

    async def embed_query(self, text: str) -> list[float]:
        rows = await asyncio.to_thread(self._encode, [f"query: {text}"])
        return rows[0]


class EmbeddingIndexer:
    def __init__(
        self,
        store: SQLiteKnowledgeStore,
        provider: EmbeddingProvider,
        *,
        batch_size: int = 32,
    ) -> None:
        if not 1 <= batch_size <= 256:
            raise ValueError("embedding batch_size must be between 1 and 256")
        self.store = store
        self.provider = provider
        self.batch_size = batch_size

    async def index_version(self, version_id: str, *, force: bool = False) -> int:
        chunks = self.store.get_chunks(version_id)
        if not chunks:
            raise AppError(
                code="KNOWLEDGE_NOT_FOUND",
                message="知识版本不存在或没有切片",
                recoverable=True,
                suggested_action="请先导入有效知识草稿。",
            )
        indexed = (
            set()
            if force
            else self.store.indexed_chunk_ids(
                version_id,
                model_name=self.provider.model_name,
                dimension=self.provider.dimension,
            )
        )
        pending = [chunk for chunk in chunks if chunk.chunk_id not in indexed]
        completed = 0
        staged: list[StoredEmbedding] = []
        try:
            for start in range(0, len(pending), self.batch_size):
                batch = pending[start : start + self.batch_size]
                texts = [chunk.content for chunk in batch]
                vectors = await self.provider.embed_documents(texts)
                if len(vectors) != len(batch):
                    raise ValueError("embedding result count does not match input")
                records: list[StoredEmbedding] = []
                for chunk, vector in zip(batch, vectors, strict=True):
                    normalized = normalize_vector(
                        vector, expected_dimension=self.provider.dimension
                    )
                    records.append(
                        StoredEmbedding(
                            chunk_id=chunk.chunk_id,
                            model_name=self.provider.model_name,
                            dimension=self.provider.dimension,
                            vector=encode_vector(normalized),
                            content_hash=chunk.content_hash,
                        )
                    )
                if force:
                    staged.extend(records)
                else:
                    self.store.save_embeddings(version_id, records)
                completed += len(records)
            if force and staged:
                self.store.save_embeddings(version_id, staged)
        except AppError:
            raise
        except (TypeError, ValueError, OverflowError) as exc:
            raise AppError(
                code="INVALID_EMBEDDING_OUTPUT",
                message="Embedding Provider returned invalid vectors",
                recoverable=True,
                suggested_action="请检查 Embedding 模型和维度配置。",
            ) from exc
        return completed
