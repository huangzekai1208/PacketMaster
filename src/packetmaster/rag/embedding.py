"""DashScope embedding Provider 与知识版本向量索引器。"""

from __future__ import annotations

import asyncio
import json
import math
import struct
from collections.abc import Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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


class DashScopeEmbeddingProvider:
    """DashScope's OpenAI-compatible embedding endpoint."""

    def __init__(
        self,
        model_name: str,
        *,
        api_key: str | None,
        dimension: int,
        base_url: str,
        timeout_seconds: float,
        max_retries: int,
    ) -> None:
        if not api_key:
            raise AppError(
                code="EMBEDDING_AUTH_MISSING",
                message="DashScope Embedding API Key 未配置",
                recoverable=True,
                suggested_action="请配置 EMBEDDING_API_KEY 后重试。",
            )
        self._model_name = model_name
        self._api_key = api_key
        self._dimension = dimension
        self._endpoint = f"{base_url.rstrip('/')}/embeddings"
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def dimension(self) -> int:
        return self._dimension

    def _request(self, texts: Sequence[str]) -> list[list[float]]:
        # 走 DashScope 的 OpenAI 兼容 /embeddings 接口，Key 仅存在于请求头。
        payload = json.dumps(
            {"model": self.model_name, "input": list(texts)}, ensure_ascii=False
        ).encode("utf-8")
        request = Request(
            self._endpoint,
            data=payload,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self._timeout_seconds) as response:
                body = json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise AppError(
                    code="EMBEDDING_AUTH_FAILED",
                    message="DashScope Embedding 鉴权失败",
                    recoverable=True,
                    suggested_action="请检查 EMBEDDING_API_KEY 的有效性和模型权限。",
                ) from exc
            if exc.code == 429 or exc.code >= 500:
                raise _RetryableEmbeddingError() from exc
            raise AppError(
                code="EMBEDDING_SERVICE_UNAVAILABLE",
                message="DashScope Embedding 服务请求失败",
                recoverable=True,
                suggested_action="请检查模型配置或稍后重试。",
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise _RetryableEmbeddingError() from exc
        try:
            data = body["data"]
            ordered = sorted(data, key=lambda item: int(item["index"]))
            vectors = [
                [float(value) for value in item["embedding"]] for item in ordered
            ]
            if len(vectors) != len(texts):
                raise ValueError("embedding result count does not match input")
            return [
                normalize_vector(vector, expected_dimension=self.dimension)
                for vector in vectors
            ]
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise AppError(
                code="INVALID_EMBEDDING_OUTPUT",
                message="DashScope Embedding 返回了无效向量",
                recoverable=True,
                suggested_action="请检查模型和 EMBEDDING_DIMENSION 配置。",
            ) from exc

    async def _embed(self, texts: Sequence[str]) -> list[list[float]]:
        # 网络类瞬态错误有限重试；鉴权和输出格式错误不重试，避免无意义请求。
        for attempt in range(self._max_retries + 1):
            try:
                return await asyncio.to_thread(self._request, texts)
            except _RetryableEmbeddingError as exc:
                if attempt == self._max_retries:
                    raise AppError(
                        code="EMBEDDING_SERVICE_UNAVAILABLE",
                        message="DashScope Embedding 服务暂时不可用",
                        recoverable=True,
                        suggested_action="请稍后重试并检查网络、配额和服务状态。",
                    ) from exc
                await asyncio.sleep(0.25 * (2**attempt))
        raise AssertionError("unreachable")

    async def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        return await self._embed(texts)

    async def embed_query(self, text: str) -> list[float]:
        return (await self._embed([text]))[0]


class _RetryableEmbeddingError(Exception):
    pass


def build_embedding_provider(settings: Any) -> EmbeddingProvider:
    """构造 DashScope Provider，调用方不会获得或记录 API Key。"""
    key = settings.embedding_api_key
    return DashScopeEmbeddingProvider(
        settings.effective_embedding_model,
        api_key=key.get_secret_value() if key else None,
        dimension=settings.effective_embedding_dimension,
        base_url=settings.embedding_base_url,
        timeout_seconds=settings.embedding_timeout_seconds,
        max_retries=settings.embedding_max_retries,
    )


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
        # force 时先收集完整新向量，全部成功后再写入，避免版本只更新一半。
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
