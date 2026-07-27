from __future__ import annotations

import pytest

from packetmaster.rag.contracts import (
    KnowledgeApplicability,
    KnowledgeBundle,
    KnowledgeCitation,
    KnowledgeQuery,
    RetrievalCandidate,
)
from packetmaster.rag.validation import KnowledgeCitationValidator


def _candidate(**updates) -> RetrievalCandidate:
    values = {
        "knowledge_id": "rfc.window",
        "version_id": "rfc.window:v1",
        "chunk_id": "rfc.window:v1:c1",
        "title": "TCP 窗口",
        "knowledge_type": "standard",
        "authority": "high",
        "source_name": "RFC 7323",
        "source_location": "section 2.2",
        "applicability": KnowledgeApplicability(
            operating_systems=["Windows", "Linux"]
        ),
        "content": "接收窗口需要覆盖链路带宽时延积，否则可能限制吞吐。",
    }
    values.update(updates)
    return RetrievalCandidate.model_validate(values)


def _citation(**updates) -> KnowledgeCitation:
    values = {
        "knowledge_id": "rfc.window",
        "version_id": "rfc.window:v1",
        "chunk_id": "rfc.window:v1:c1",
        "title": "TCP 窗口",
        "knowledge_type": "standard",
        "source_name": "RFC 7323",
        "source_location": "section 2.2",
        "supported_statement": "接收窗口不足可能限制吞吐。",
        "supporting_quote": "接收窗口需要覆盖链路带宽时延积",
    }
    values.update(updates)
    return KnowledgeCitation.model_validate(values)


class FakeStore:
    def __init__(self, candidate) -> None:
        self.candidate = candidate

    async def get_candidate(self, chunk_id):
        if self.candidate and self.candidate.chunk_id == chunk_id:
            return self.candidate
        return None


def _bundle(candidate: RetrievalCandidate) -> KnowledgeBundle:
    return KnowledgeBundle(
        query_id="q1",
        results=[candidate],
        total_content_bytes=len(candidate.content.encode("utf-8")),
    )


@pytest.mark.asyncio
async def test_valid_citation_must_match_bundle_store_and_exact_quote() -> None:
    candidate = _candidate()
    result = await KnowledgeCitationValidator(FakeStore(candidate)).validate(
        [_citation()],
        _bundle(candidate),
        KnowledgeQuery(
            query_id="q1",
            query_text="窗口限制",
            environment_tags={"operating_system": "Windows"},
        ),
    )

    assert result.valid_citations == [_citation()]
    assert result.rejected == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("citation", "reason"),
    [
        (_citation(chunk_id="rfc.window:v1:invented"), "not_in_retrieval_bundle"),
        (_citation(version_id="rfc.window:v2"), "identity_mismatch"),
        (_citation(supporting_quote="正文中不存在的引句"), "unsupported_quote"),
    ],
)
async def test_invalid_or_fabricated_citations_are_rejected(citation, reason) -> None:
    candidate = _candidate()
    result = await KnowledgeCitationValidator(FakeStore(candidate)).validate(
        [citation],
        _bundle(candidate),
        KnowledgeQuery(query_id="q1", query_text="窗口限制"),
    )

    assert result.valid_citations == []
    assert result.rejected[0].reason == reason


@pytest.mark.asyncio
async def test_disabled_or_environment_mismatched_knowledge_is_rejected() -> None:
    candidate = _candidate(
        applicability=KnowledgeApplicability(operating_systems=["Linux"])
    )
    query = KnowledgeQuery(
        query_id="q1",
        query_text="窗口限制",
        environment_tags={"operating_system": "Windows"},
    )

    mismatch = await KnowledgeCitationValidator(FakeStore(candidate)).validate(
        [_citation()], _bundle(candidate), query
    )
    no_environment = query.model_copy(update={"environment_tags": {}})
    disabled = await KnowledgeCitationValidator(FakeStore(None)).validate(
        [_citation()], _bundle(_candidate()), no_environment
    )

    assert mismatch.rejected[0].reason == "environment_mismatch"
    assert disabled.rejected[0].reason == "version_not_active"


@pytest.mark.asyncio
async def test_packet_conflict_is_preserved_but_not_accepted_as_support() -> None:
    candidate = _candidate()
    result = await KnowledgeCitationValidator(FakeStore(candidate)).validate(
        [_citation()],
        _bundle(candidate),
        KnowledgeQuery(query_id="q1", query_text="窗口限制"),
        packet_conflicts={candidate.chunk_id: "当前报文窗口始终充足"},
    )

    assert result.valid_citations == []
    assert result.conflicts[0].packet_evidence == "当前报文窗口始终充足"
