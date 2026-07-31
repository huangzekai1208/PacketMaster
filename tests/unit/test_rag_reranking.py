from __future__ import annotations

import json

import pytest

import packetmaster.rag.reranking as reranking_module
from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.reranking import DashScopeReranker, build_reranker


def _provider(api_key: str | None = "secret") -> DashScopeReranker:
    return DashScopeReranker(
        "qwen3-rerank",
        api_key=api_key,
        base_url="https://example.invalid/compatible-api/v1/",
        timeout_seconds=1,
        max_retries=0,
        max_document_chars=10,
    )


def test_dashscope_reranker_uses_compatible_api_and_bounded_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider()
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
                    "results": [
                        {"index": 1, "relevance_score": 0.9},
                        {"index": 0, "relevance_score": 0.4},
                    ]
                }
            ).encode("utf-8")

    def fake_urlopen(request, *, timeout):
        captured["url"] = request.full_url
        captured["authorization"] = request.get_header("Authorization")
        captured["payload"] = json.loads(request.data)
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr(reranking_module, "urlopen", fake_urlopen)

    result = provider._request(
        "TCP 首部", ["first document", "second document"], top_n=2
    )

    assert result == [(1, 0.9), (0, 0.4)]
    assert captured == {
        "url": "https://example.invalid/compatible-api/v1/reranks",
        "authorization": "Bearer secret",
        "payload": {
            "model": "qwen3-rerank",
            "query": "TCP 首部",
            "documents": ["first docu", "second doc"],
            "top_n": 2,
        },
        "timeout": 1,
    }


def test_dashscope_reranker_rejects_invalid_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _provider()

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        @staticmethod
        def read() -> bytes:
            return json.dumps(
                {"results": [{"index": 1, "relevance_score": 1.0}]}
            ).encode("utf-8")

    monkeypatch.setattr(
        reranking_module, "urlopen", lambda request, *, timeout: Response()
    )

    with pytest.raises(AppError) as raised:
        provider._request("query", ["one"], top_n=1)
    assert raised.value.code == "INVALID_RERANK_OUTPUT"


def test_reranker_requires_api_key() -> None:
    with pytest.raises(AppError) as raised:
        _provider(api_key=None)
    assert raised.value.code == "RERANK_AUTH_MISSING"


def test_reranker_factory_reuses_embedding_key_and_can_be_disabled() -> None:
    provider = build_reranker(Settings(embedding_api_key="shared-secret"))

    assert isinstance(provider, DashScopeReranker)
    assert provider.model_name == "qwen3-rerank"
    assert (
        build_reranker(
            Settings(embedding_api_key="shared-secret", reranker_enabled=False)
        )
        is None
    )
