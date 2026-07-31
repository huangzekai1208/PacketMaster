from __future__ import annotations

import asyncio

import pytest

from packetmaster.errors import AppError
from packetmaster.rag.contracts import (
    CaseProfile,
    KnowledgeApplicability,
    KnowledgeQuery,
    RetrievalCandidate,
)
from packetmaster.rag.retrieval import HybridKnowledgeRetriever


def _candidate(
    chunk_id: str,
    *,
    knowledge_id: str | None = None,
    knowledge_type: str = "standard",
    authority: str = "high",
    content: str = "TCP 窗口与带宽时延积会影响吞吐。",
    applicability: KnowledgeApplicability | None = None,
) -> RetrievalCandidate:
    parent = knowledge_id or chunk_id.split(":")[0]
    return RetrievalCandidate(
        knowledge_id=parent,
        version_id=f"{parent}:v1",
        chunk_id=chunk_id,
        title=parent,
        knowledge_type=knowledge_type,
        authority=authority,
        source_name="测试知识",
        source_location="section 1",
        applicability=applicability or KnowledgeApplicability(),
        content=content,
    )


class FakeStore:
    def __init__(self, keyword, vector, cases=None) -> None:
        self.keyword = keyword
        self.vector = vector
        self.cases = cases or {}

    async def keyword_search(self, query, *, limit):
        return self.keyword[:limit]

    async def vector_search(self, query, vector, *, limit):
        return self.vector[:limit]

    async def get_candidate(self, chunk_id):
        candidates = [*self.keyword, *self.vector]
        return next(
            (item for item in candidates if item.chunk_id == chunk_id),
            None,
        )

    def get_case_profile(self, version_id):
        return self.cases.get(version_id)


class FakeProvider:
    model_name = "fake"
    dimension = 2

    async def embed_query(self, text):
        return [1.0, 0.0]

    async def embed_documents(self, texts):
        return [[1.0, 0.0] for _ in texts]


class FakeReranker:
    model_name = "fake-reranker"

    def __init__(self, order: list[int] | None = None) -> None:
        self.order = order
        self.calls: list[tuple[str, list[str], int]] = []

    async def rerank(self, query, documents, *, top_n):
        self.calls.append((query, list(documents), top_n))
        order = self.order or list(range(len(documents)))
        return [(index, 1.0 - rank * 0.01) for rank, index in enumerate(order)]


@pytest.mark.asyncio
async def test_hybrid_retrieval_uses_rrf_and_merges_duplicate_chunks() -> None:
    shared = _candidate("window:v1:shared")
    keyword_only = _candidate("rfc:v1:keyword")
    vector_only = _candidate("case:v1:vector", knowledge_type="case")
    retriever = HybridKnowledgeRetriever(
        FakeStore([shared, keyword_only], [vector_only, shared]),
        FakeProvider(),
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="零窗口导致吞吐低")
    )

    assert bundle.results[0].chunk_id == shared.chunk_id
    assert bundle.results[0].keyword_rank == 1
    assert bundle.results[0].vector_rank == 2
    assert len({item.chunk_id for item in bundle.results}) == len(bundle.results)


@pytest.mark.asyncio
async def test_environment_mismatch_is_filtered() -> None:
    windows = _candidate(
        "windows:v1:c1",
        applicability=KnowledgeApplicability(operating_systems=["Windows"]),
    )
    linux = _candidate(
        "linux:v1:c1",
        applicability=KnowledgeApplicability(operating_systems=["Linux"]),
    )
    retriever = HybridKnowledgeRetriever(
        FakeStore([windows, linux], [linux, windows]), FakeProvider()
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(
            query_id="q1",
            query_text="窗口限制",
            environment_tags={"operating_system": "Windows"},
        )
    )

    assert [item.knowledge_id for item in bundle.results] == ["windows"]


@pytest.mark.asyncio
async def test_case_similarity_boosts_matching_case() -> None:
    matching = _candidate("match:v1:c1", knowledge_type="case", authority="medium")
    other = _candidate("other:v1:c1", knowledge_type="case", authority="medium")
    cases = {
        matching.version_id: CaseProfile(
            direction="download",
            standard_bandwidth_mbps=1000,
            actual_bandwidth_mbps=20,
            achievement_ratio_pct=2,
            tcp_features={"zero_window_count": 8},
            confirmed_primary_cause="接收端处理不足",
            resolution="优化接收端",
        ),
        other.version_id: CaseProfile(
            direction="upload",
            standard_bandwidth_mbps=1000,
            actual_bandwidth_mbps=800,
            achievement_ratio_pct=80,
            confirmed_primary_cause="发送端限制",
            resolution="优化发送端",
        ),
    }
    retriever = HybridKnowledgeRetriever(
        FakeStore([other, matching], [other, matching], cases), FakeProvider()
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(
            query_id="q1",
            direction="download",
            achievement_ratio_pct=2,
            query_text="零窗口",
            global_features={"zero_window_count": 8},
        )
    )

    assert bundle.results[0].knowledge_id == "match"


@pytest.mark.asyncio
async def test_final_results_enforce_byte_budget() -> None:
    same_parent = [
        _candidate(
            f"parent:v1:c{index}",
            knowledge_id="parent",
            content="x" * 100,
        )
        for index in range(4)
    ]
    other = _candidate("other:v1:c1", content="y" * 100)
    retriever = HybridKnowledgeRetriever(
        FakeStore([*same_parent, other], []),
        FakeProvider(),
        final_top_k=8,
        max_context_bytes=250,
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="窗口限制")
    )

    assert bundle.total_content_bytes <= 250
    assert bundle.truncated is True


@pytest.mark.asyncio
async def test_model_reranks_rrf_candidate_pool_before_final_selection() -> None:
    candidates = [
        _candidate(
            f"doc-{index}:v1:c1",
            authority="low" if index == 0 else "high",
        )
        for index in range(5)
    ]
    reranker = FakeReranker(order=[2, 1, 0])
    retriever = HybridKnowledgeRetriever(
        FakeStore(candidates, []),
        FakeProvider(),
        reranker=reranker,
        reranker_candidate_top_k=3,
        final_top_k=3,
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="TCP 首部字段")
    )

    assert [item.chunk_id for item in bundle.results] == [
        candidates[2].chunk_id,
        candidates[1].chunk_id,
        candidates[0].chunk_id,
    ]
    assert len(reranker.calls[0][1]) == 3
    assert reranker.calls[0][2] == 3
    assert bundle.results[0].rerank_score == 1.0


@pytest.mark.asyncio
async def test_reranker_failure_falls_back_to_rrf_with_warning() -> None:
    class FailingReranker(FakeReranker):
        async def rerank(self, query, documents, *, top_n):
            raise AppError(
                code="RERANK_SERVICE_UNAVAILABLE",
                message="failed",
                recoverable=True,
                suggested_action="fallback",
            )

    first = _candidate("first:v1:c1")
    second = _candidate("second:v1:c1")
    retriever = HybridKnowledgeRetriever(
        FakeStore([first, second], [first, second]),
        FakeProvider(),
        reranker=FailingReranker(),
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="窗口限制")
    )

    assert [item.chunk_id for item in bundle.results] == [
        first.chunk_id,
        second.chunk_id,
    ]
    assert bundle.warnings == ["模型重排序降级：RERANK_SERVICE_UNAVAILABLE"]


@pytest.mark.asyncio
async def test_reranker_timeout_falls_back_before_total_retrieval_timeout() -> None:
    class SlowReranker(FakeReranker):
        async def rerank(self, query, documents, *, top_n):
            await asyncio.sleep(0.05)
            return await super().rerank(query, documents, top_n=top_n)

    candidates = [_candidate("first:v1:c1"), _candidate("second:v1:c1")]
    retriever = HybridKnowledgeRetriever(
        FakeStore(candidates, candidates),
        FakeProvider(),
        reranker=SlowReranker(),
        reranker_timeout_seconds=0.001,
        timeout_seconds=0.1,
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="窗口限制")
    )

    assert bundle.results
    assert bundle.warnings == ["模型重排序降级：RERANK_TIMEOUT"]


@pytest.mark.asyncio
async def test_same_knowledge_can_fill_requested_final_slots_after_reranking() -> None:
    candidates = [
        _candidate(f"parent:v1:c{index}", knowledge_id="parent") for index in range(6)
    ]
    retriever = HybridKnowledgeRetriever(
        FakeStore(candidates, []), FakeProvider(), final_top_k=5
    )

    bundle = await retriever.retrieve(KnowledgeQuery(query_id="q1", query_text="TCP"))

    assert len(bundle.results) == 5
    assert {item.knowledge_id for item in bundle.results} == {"parent"}


@pytest.mark.asyncio
async def test_vector_failure_degrades_to_keyword_with_warning() -> None:
    class FailingStore(FakeStore):
        async def vector_search(self, query, vector, *, limit):
            raise AppError(
                code="VECTOR_FAILED",
                message="failed",
                recoverable=True,
                suggested_action="retry",
            )

    retriever = HybridKnowledgeRetriever(
        FailingStore([_candidate("rfc:v1:c1")], []), FakeProvider()
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="窗口限制")
    )

    assert bundle.results
    assert "VECTOR_FAILED" in bundle.warnings[0]


@pytest.mark.asyncio
async def test_vector_timeout_degrades_to_keyword_with_warning() -> None:
    class SlowProvider(FakeProvider):
        async def embed_query(self, text):
            await asyncio.sleep(0.05)
            return await super().embed_query(text)

    retriever = HybridKnowledgeRetriever(
        FakeStore([_candidate("rfc:v1:c1")], []),
        SlowProvider(),
        vector_timeout_seconds=0.001,
        timeout_seconds=0.1,
    )

    bundle = await retriever.retrieve(
        KnowledgeQuery(query_id="q1", query_text="窗口限制")
    )

    assert bundle.results
    assert bundle.warnings == ["向量检索降级：VECTOR_RETRIEVAL_TIMEOUT"]


@pytest.mark.asyncio
async def test_retrieval_timeout_has_stable_error() -> None:
    class SlowStore(FakeStore):
        async def keyword_search(self, query, *, limit):
            await asyncio.sleep(0.05)
            return []

    retriever = HybridKnowledgeRetriever(
        SlowStore([], []), FakeProvider(), timeout_seconds=0.001
    )

    with pytest.raises(AppError) as raised:
        await retriever.retrieve(KnowledgeQuery(query_id="q1", query_text="窗口"))
    assert raised.value.code == "RAG_RETRIEVAL_TIMEOUT"
