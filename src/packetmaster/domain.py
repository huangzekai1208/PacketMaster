"""Pydantic contracts shared by the CLI, MCP server, and diagnostic graph."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from packetmaster.platform import is_absolute_path


class Target(StrEnum):
    DOWNLOAD = "download"
    UPLOAD = "upload"
    BOTH = "both"


class AnalysisStatus(StrEnum):
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"


class EvidenceOperator(StrEnum):
    EQ = "eq"
    NE = "ne"
    GT = "gt"
    GTE = "gte"
    LT = "lt"
    LTE = "lte"
    IN = "in"
    EXISTS = "exists"


class HypothesisType(StrEnum):
    KNOWN_PATTERN = "known_pattern"
    DATA_DISCOVERED = "data_discovered"
    EXTERNAL_FACTOR = "external_factor"


class Observability(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    OUTSIDE_CAPTURE = "outside_capture"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ContractModel(BaseModel):
    """Strict base class for all stable inter-component contracts."""

    model_config = ConfigDict(extra="forbid")


class AnalyzeRequest(ContractModel):
    request_id: str = Field(pattern=r"^[A-Za-z0-9._-]+$")
    pcap_path: str
    target: Target = Target.DOWNLOAD
    aggregation_interval_seconds: int = Field(default=1, ge=1, le=60)
    build_evidence_index: bool = True

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        if not value.strip("."):
            raise ValueError("request_id must contain a non-dot character")
        return value

    @field_validator("pcap_path")
    @classmethod
    def validate_absolute_pcap_path(cls, value: str) -> str:
        if not is_absolute_path(value):
            raise ValueError("pcap_path must be an absolute path")
        return value


class CoverageSummary(ContractModel):
    input_size_bytes: int = Field(default=0, ge=0)
    total_packets_seen: int = Field(default=0, ge=0)
    tcp_packets_seen: int = Field(default=0, ge=0)
    speed_packets_analyzed: int = Field(default=0, ge=0)
    analyzed_bytes: int = Field(default=0, ge=0)
    analyzed_duration_seconds: float = Field(default=0.0, ge=0)
    complete: bool = True
    truncated: bool = False
    truncation_reason: str | None = None


class AnalyzeResponse(ContractModel):
    analysis_id: str
    status: AnalysisStatus
    target: Target = Target.DOWNLOAD
    coverage_summary: CoverageSummary
    flow_summary: dict[str, Any] = Field(default_factory=dict)
    tcp_summary: dict[str, Any] = Field(default_factory=dict)
    interval_summary: list[dict[str, Any]] = Field(default_factory=list)
    syn_options: dict[str, Any] = Field(default_factory=dict)
    available_evidence: list[str] = Field(default_factory=list)
    resource_usage: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    artifact_paths: dict[str, Any] = Field(default_factory=dict)


class EvidencePredicate(ContractModel):
    field: str
    operator: EvidenceOperator
    value: Any = None


class CustomEvidenceQuery(ContractModel):
    flow_ids: list[str] = Field(default_factory=list)
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    predicates: list[EvidencePredicate] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)


class EvidenceRequest(ContractModel):
    analysis_id: str
    evidence_type: str
    flow_id: str | None = None
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    fields: list[str] = Field(default_factory=list)
    query: CustomEvidenceQuery | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


class EvidenceResponse(ContractModel):
    analysis_id: str
    evidence_type: str
    summary: dict[str, Any] = Field(default_factory=dict)
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    next_offset: int | None = None
    truncated: bool = False
    source: str = ""
    coverage_range: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class Hypothesis(ContractModel):
    cause: str
    hypothesis_type: HypothesisType
    observability: Observability
    confidence: Confidence
    supporting_evidence: list[str] = Field(default_factory=list)
    contradicting_evidence: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    affected_flows: list[str] = Field(default_factory=list)
    explanation: str = ""
    suggestion: str = ""


class HypothesisBatch(ContractModel):
    hypotheses: list[Hypothesis] = Field(default_factory=list)
    requested_evidence: list[EvidenceRequest] = Field(default_factory=list)


class VerificationResult(ContractModel):
    accepted_hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected_causes: list[str] = Field(default_factory=list)
    requested_evidence: list[EvidenceRequest] = Field(default_factory=list)
    ready_for_report: bool = False
    confidence: Confidence | None = None
    limitations: list[str] = Field(default_factory=list)


class DiagnosticReport(ContractModel):
    standard_bandwidth_mbps: float = Field(gt=0)
    actual_bandwidth_mbps: float = Field(gt=0)
    achievement_ratio_pct: float = Field(ge=0)
    target: Target = Target.DOWNLOAD
    primary_cause: str = "unresolved"
    candidate_causes: list[Hypothesis] = Field(default_factory=list)
    key_evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: Confidence
    coverage_summary: CoverageSummary
    evidence_quality: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    troubleshooting_steps: list[str] = Field(default_factory=list)
    optimization_suggestions: list[str] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)
