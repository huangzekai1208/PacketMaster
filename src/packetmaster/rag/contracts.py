"""Strict contracts shared by RAG storage, retrieval, models, and interfaces."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from packetmaster.domain import HypothesisBatch, Target
from packetmaster.platform import is_absolute_path


class RagMode(StrEnum):
    OFF = "off"
    SHADOW = "shadow"
    ACTIVE = "active"


class KnowledgeType(StrEnum):
    STANDARD = "standard"
    VENDOR = "vendor"
    RUNBOOK = "runbook"
    CASE = "case"


class KnowledgeStatus(StrEnum):
    DRAFT = "draft"
    APPROVED = "approved"
    DISABLED = "disabled"
    SUPERSEDED = "superseded"


class AuthorityLevel(StrEnum):
    HIGH = "high"
    MEDIUM_HIGH = "medium_high"
    MEDIUM = "medium"
    LOW = "low"


class RagContract(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


Identifier = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$"),
]
ShortText = Annotated[str, Field(min_length=1, max_length=128)]
FeatureValue = str | int | float | bool | None


class KnowledgeApplicability(RagContract):
    directions: list[Target] = Field(default_factory=list, max_length=3)
    operating_systems: list[ShortText] = Field(default_factory=list, max_length=16)
    link_types: list[ShortText] = Field(default_factory=list, max_length=16)
    tools: list[ShortText] = Field(default_factory=list, max_length=16)
    devices: list[ShortText] = Field(default_factory=list, max_length=32)
    tags: dict[ShortText, ShortText] = Field(default_factory=dict, max_length=32)


class KnowledgeDocument(RagContract):
    knowledge_id: Identifier
    title: str = Field(min_length=1, max_length=256)
    knowledge_type: KnowledgeType
    language: str = Field(default="zh-CN", min_length=2, max_length=32)
    authority: AuthorityLevel
    status: KnowledgeStatus = KnowledgeStatus.DRAFT
    summary: str = Field(default="", max_length=2_000)
    applicability: KnowledgeApplicability = Field(
        default_factory=KnowledgeApplicability
    )
    current_version_id: Identifier | None = None

    @model_validator(mode="after")
    def require_current_approved_version(self) -> KnowledgeDocument:
        if (
            self.status is KnowledgeStatus.APPROVED
            and self.current_version_id is None
        ):
            raise ValueError("approved knowledge requires a current version")
        return self


class KnowledgeVersion(RagContract):
    version_id: Identifier
    knowledge_id: Identifier
    version_number: int = Field(ge=1)
    source_name: str = Field(min_length=1, max_length=256)
    source_location: str = Field(default="", max_length=512)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: KnowledgeStatus = KnowledgeStatus.DRAFT
    created_at: datetime
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    approved_at: datetime | None = None
    approved_by: ShortText | None = None
    supersedes_version_id: Identifier | None = None

    @field_validator("source_location")
    @classmethod
    def reject_local_source_path(cls, value: str) -> str:
        if value and is_absolute_path(value):
            raise ValueError("source_location must not contain a local absolute path")
        return value

    @model_validator(mode="after")
    def validate_lifecycle(self) -> KnowledgeVersion:
        if self.valid_from and self.valid_to and self.valid_to <= self.valid_from:
            raise ValueError("valid_to must be later than valid_from")
        if self.status is KnowledgeStatus.APPROVED and (
            self.approved_at is None or self.approved_by is None
        ):
            raise ValueError("approved knowledge requires approver and approval time")
        return self


class KnowledgeChunk(RagContract):
    chunk_id: Identifier
    knowledge_id: Identifier
    version_id: Identifier
    chunk_index: int = Field(ge=0)
    heading_path: list[str] = Field(default_factory=list, max_length=16)
    source_location: str = Field(default="", max_length=512)
    content: str = Field(min_length=1, max_length=8_000)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    status: KnowledgeStatus = KnowledgeStatus.DRAFT

    @field_validator("heading_path")
    @classmethod
    def bound_heading_values(cls, value: list[str]) -> list[str]:
        if any(not heading or len(heading) > 256 for heading in value):
            raise ValueError("heading_path values must contain 1 to 256 characters")
        return value

    @field_validator("source_location")
    @classmethod
    def reject_local_source_path(cls, value: str) -> str:
        if value and is_absolute_path(value):
            raise ValueError("source_location must not contain a local absolute path")
        return value


class CaseProfile(RagContract):
    direction: Target = Target.DOWNLOAD
    standard_bandwidth_mbps: float = Field(gt=0)
    actual_bandwidth_mbps: float = Field(gt=0)
    achievement_ratio_pct: float = Field(ge=0)
    tcp_features: dict[ShortText, FeatureValue] = Field(
        default_factory=dict, max_length=64
    )
    anomaly_summaries: list[str] = Field(default_factory=list, max_length=32)
    confirmed_primary_cause: str = Field(min_length=1, max_length=2_000)
    candidate_causes: list[str] = Field(default_factory=list, max_length=32)
    supporting_evidence: list[str] = Field(default_factory=list, max_length=64)
    contradicting_evidence: list[str] = Field(default_factory=list, max_length=64)
    external_factors: list[str] = Field(default_factory=list, max_length=32)
    resolution: str = Field(min_length=1, max_length=4_000)
    applicability: KnowledgeApplicability = Field(
        default_factory=KnowledgeApplicability
    )

    @field_validator(
        "anomaly_summaries",
        "candidate_causes",
        "supporting_evidence",
        "contradicting_evidence",
        "external_factors",
    )
    @classmethod
    def bound_list_text(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 1_000 for item in value):
            raise ValueError("case list values must contain 1 to 1000 characters")
        return value


class KnowledgeQuery(RagContract):
    query_id: Identifier
    analysis_id: Identifier | None = None
    direction: Target = Target.DOWNLOAD
    achievement_ratio_pct: float | None = Field(default=None, ge=0)
    query_text: str = Field(min_length=1, max_length=4_000)
    keywords: list[ShortText] = Field(default_factory=list, max_length=64)
    candidate_causes: list[str] = Field(default_factory=list, max_length=32)
    missing_evidence: list[str] = Field(default_factory=list, max_length=32)
    global_features: dict[ShortText, FeatureValue] = Field(
        default_factory=dict, max_length=64
    )
    environment_tags: dict[ShortText, ShortText] = Field(
        default_factory=dict, max_length=32
    )
    knowledge_types: list[KnowledgeType] = Field(default_factory=list, max_length=4)

    @field_validator("candidate_causes", "missing_evidence")
    @classmethod
    def bound_query_list_text(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 1_000 for item in value):
            raise ValueError("query list values must contain 1 to 1000 characters")
        return value


class RetrievalCandidate(RagContract):
    knowledge_id: Identifier
    version_id: Identifier
    chunk_id: Identifier
    title: str = Field(min_length=1, max_length=256)
    knowledge_type: KnowledgeType
    authority: AuthorityLevel
    status: KnowledgeStatus = KnowledgeStatus.APPROVED
    source_name: str = Field(min_length=1, max_length=256)
    source_location: str = Field(default="", max_length=512)
    applicability: KnowledgeApplicability = Field(
        default_factory=KnowledgeApplicability
    )
    content: str = Field(min_length=1, max_length=8_000)
    keyword_rank: int | None = Field(default=None, ge=1, le=100)
    vector_rank: int | None = Field(default=None, ge=1, le=100)
    fusion_score: float = Field(default=0.0, ge=0)
    rerank_score: float = Field(default=0.0, ge=0)

    @field_validator("source_location")
    @classmethod
    def reject_local_source_path(cls, value: str) -> str:
        if value and is_absolute_path(value):
            raise ValueError("source_location must not contain a local absolute path")
        return value

    @field_validator("status")
    @classmethod
    def require_approved_status(cls, value: KnowledgeStatus) -> KnowledgeStatus:
        if value is not KnowledgeStatus.APPROVED:
            raise ValueError("retrieval candidates must be approved")
        return value


class KnowledgeBundle(RagContract):
    query_id: Identifier
    results: list[RetrievalCandidate] = Field(default_factory=list, max_length=8)
    total_content_bytes: int = Field(default=0, ge=0, le=24_576)
    truncated: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("warnings")
    @classmethod
    def bound_warnings(cls, value: list[str]) -> list[str]:
        if any(not warning or len(warning) > 512 for warning in value):
            raise ValueError("warnings must contain 1 to 512 characters")
        return value

    @model_validator(mode="after")
    def validate_content_size(self) -> KnowledgeBundle:
        actual = sum(len(item.content.encode("utf-8")) for item in self.results)
        if actual != self.total_content_bytes:
            raise ValueError("total_content_bytes must match encoded result content")
        return self


class KnowledgeCitation(RagContract):
    knowledge_id: Identifier
    version_id: Identifier
    chunk_id: Identifier
    title: str = Field(min_length=1, max_length=256)
    knowledge_type: KnowledgeType
    source_name: str = Field(min_length=1, max_length=256)
    source_location: str = Field(default="", max_length=512)
    supported_statement: str = Field(min_length=1, max_length=1_000)
    supporting_quote: str = Field(min_length=1, max_length=1_000)
    applicability_note: str = Field(default="", max_length=1_000)

    @field_validator("source_location")
    @classmethod
    def reject_local_source_path(cls, value: str) -> str:
        if value and is_absolute_path(value):
            raise ValueError("source_location must not contain a local absolute path")
        return value


class KnowledgeAugmentation(RagContract):
    hypotheses: HypothesisBatch
    citations: list[KnowledgeCitation] = Field(default_factory=list, max_length=32)
    limitations: list[str] = Field(default_factory=list, max_length=32)

    @field_validator("limitations")
    @classmethod
    def bound_limitations(cls, value: list[str]) -> list[str]:
        if any(not item or len(item) > 1_000 for item in value):
            raise ValueError("limitations must contain 1 to 1000 characters")
        return value
