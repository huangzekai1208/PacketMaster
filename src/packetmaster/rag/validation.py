"""对模型产出的知识引用进行确定性校验与冲突识别。"""

from __future__ import annotations

import re

from pydantic import Field

from packetmaster.rag.base import KnowledgeStore
from packetmaster.rag.contracts import (
    Identifier,
    KnowledgeBundle,
    KnowledgeCitation,
    KnowledgeQuery,
    RagContract,
    RetrievalCandidate,
)


class CitationRejection(RagContract):
    chunk_id: Identifier
    reason: str = Field(min_length=1, max_length=128)


class CitationConflict(RagContract):
    citation: KnowledgeCitation
    packet_evidence: str = Field(min_length=1, max_length=1_000)


class CitationValidationResult(RagContract):
    valid_citations: list[KnowledgeCitation] = Field(
        default_factory=list, max_length=32
    )
    rejected: list[CitationRejection] = Field(default_factory=list, max_length=32)
    conflicts: list[CitationConflict] = Field(default_factory=list, max_length=32)


def _normalized_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def _environment_matches(
    candidate: RetrievalCandidate, query: KnowledgeQuery
) -> bool:
    operating_system = query.environment_tags.get("operating_system")
    if operating_system and candidate.applicability.operating_systems:
        allowed = {
            value.casefold() for value in candidate.applicability.operating_systems
        }
        if operating_system.casefold() not in allowed:
            return False
    tool = query.environment_tags.get("tool")
    if tool and candidate.applicability.tools:
        if tool.casefold() not in {
            value.casefold() for value in candidate.applicability.tools
        }:
            return False
    return True


class KnowledgeCitationValidator:
    def __init__(self, store: KnowledgeStore) -> None:
        self.store = store

    async def validate(
        self,
        citations: list[KnowledgeCitation],
        bundle: KnowledgeBundle,
        query: KnowledgeQuery,
        *,
        packet_conflicts: dict[str, str] | None = None,
    ) -> CitationValidationResult:
        if bundle.query_id != query.query_id:
            raise ValueError("knowledge bundle and query ID must match")
        retrieved = {item.chunk_id: item for item in bundle.results}
        valid: list[KnowledgeCitation] = []
        rejected: list[CitationRejection] = []
        conflicts: list[CitationConflict] = []
        for citation in citations[:32]:
            candidate = retrieved.get(citation.chunk_id)
            if candidate is None:
                rejected.append(
                    CitationRejection(
                        chunk_id=citation.chunk_id,
                        reason="not_in_retrieval_bundle",
                    )
                )
                continue
            identity = (
                citation.knowledge_id == candidate.knowledge_id
                and citation.version_id == candidate.version_id
                and citation.title == candidate.title
                and citation.knowledge_type is candidate.knowledge_type
                and citation.source_name == candidate.source_name
                and citation.source_location == candidate.source_location
            )
            if not identity:
                rejected.append(
                    CitationRejection(
                        chunk_id=citation.chunk_id, reason="identity_mismatch"
                    )
                )
                continue
            active = await self.store.get_candidate(citation.chunk_id)
            if active is None or active.version_id != citation.version_id:
                rejected.append(
                    CitationRejection(
                        chunk_id=citation.chunk_id, reason="version_not_active"
                    )
                )
                continue
            if not _environment_matches(candidate, query):
                rejected.append(
                    CitationRejection(
                        chunk_id=citation.chunk_id, reason="environment_mismatch"
                    )
                )
                continue
            quote = _normalized_text(citation.supporting_quote)
            if quote not in _normalized_text(candidate.content):
                rejected.append(
                    CitationRejection(
                        chunk_id=citation.chunk_id, reason="unsupported_quote"
                    )
                )
                continue
            conflict = (packet_conflicts or {}).get(citation.chunk_id)
            if conflict:
                conflicts.append(
                    CitationConflict(citation=citation, packet_evidence=conflict)
                )
                continue
            valid.append(citation)
        return CitationValidationResult(
            valid_citations=valid,
            rejected=rejected,
            conflicts=conflicts,
        )
