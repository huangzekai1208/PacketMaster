"""DashScope qwen3-rerank Provider。"""

from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Sequence
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from packetmaster.errors import AppError
from packetmaster.rag.base import Reranker


class _RetryableRerankError(Exception):
    pass


class DashScopeReranker:
    def __init__(
        self,
        model_name: str,
        *,
        api_key: str | None,
        base_url: str,
        timeout_seconds: float,
        max_retries: int,
        max_document_chars: int,
    ) -> None:
        if not api_key:
            raise AppError(
                code="RERANK_AUTH_MISSING",
                message="DashScope Reranker API Key 未配置",
                recoverable=True,
                suggested_action="请配置 RERANK_API_KEY 或 EMBEDDING_API_KEY 后重试。",
            )
        if timeout_seconds <= 0 or max_retries < 0 or max_document_chars < 1:
            raise ValueError("invalid reranker limits")
        self._model_name = model_name
        self._api_key = api_key
        self._endpoint = f"{base_url.rstrip('/')}/reranks"
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._max_document_chars = max_document_chars

    @property
    def model_name(self) -> str:
        return self._model_name

    def _request(
        self, query: str, documents: Sequence[str], *, top_n: int
    ) -> list[tuple[int, float]]:
        bounded = [document[: self._max_document_chars] for document in documents]
        payload = json.dumps(
            {
                "model": self.model_name,
                "query": query,
                "documents": bounded,
                "top_n": top_n,
            },
            ensure_ascii=False,
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
                    code="RERANK_AUTH_FAILED",
                    message="DashScope Reranker 鉴权失败",
                    recoverable=True,
                    suggested_action="请检查 RERANK_API_KEY、模型权限和服务地域。",
                ) from exc
            if exc.code == 429 or exc.code >= 500:
                raise _RetryableRerankError() from exc
            raise AppError(
                code="RERANK_SERVICE_UNAVAILABLE",
                message="DashScope Reranker 请求失败",
                recoverable=True,
                suggested_action="请检查模型、端点或稍后重试。",
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise _RetryableRerankError() from exc
        try:
            results = body["results"]
            ranked = [
                (int(item["index"]), float(item["relevance_score"])) for item in results
            ]
            indices = [index for index, _ in ranked]
            if (
                len(ranked) != top_n
                or len(set(indices)) != len(indices)
                or any(index < 0 or index >= len(documents) for index in indices)
                or any(not math.isfinite(score) or score < 0 for _, score in ranked)
            ):
                raise ValueError("invalid rerank results")
            return ranked
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise AppError(
                code="INVALID_RERANK_OUTPUT",
                message="DashScope Reranker 返回了无效结果",
                recoverable=True,
                suggested_action="请检查 qwen3-rerank 模型和接口配置。",
            ) from exc

    async def rerank(
        self, query: str, documents: Sequence[str], *, top_n: int
    ) -> list[tuple[int, float]]:
        if not documents or not 1 <= top_n <= len(documents):
            raise ValueError("invalid rerank input")
        for attempt in range(self._max_retries + 1):
            try:
                return await asyncio.to_thread(
                    self._request, query, documents, top_n=top_n
                )
            except _RetryableRerankError as exc:
                if attempt == self._max_retries:
                    raise AppError(
                        code="RERANK_SERVICE_UNAVAILABLE",
                        message="DashScope Reranker 服务暂时不可用",
                        recoverable=True,
                        suggested_action=(
                            "本次将回退到 RRF 排序，请检查网络和服务状态。"
                        ),
                    ) from exc
                await asyncio.sleep(0.25 * (2**attempt))
        raise AssertionError("unreachable")


def build_reranker(settings: Any) -> Reranker | None:
    if not settings.reranker_enabled:
        return None
    key = settings.effective_reranker_api_key
    return DashScopeReranker(
        settings.reranker_model,
        api_key=key.get_secret_value() if key else None,
        base_url=settings.reranker_base_url,
        timeout_seconds=settings.reranker_timeout_seconds,
        max_retries=settings.reranker_max_retries,
        max_document_chars=settings.reranker_max_document_chars,
    )
