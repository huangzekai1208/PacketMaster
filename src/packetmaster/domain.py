"""CLI、MCP Server 和诊断图共享的 Pydantic 领域契约。"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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


class EvidenceType(StrEnum):
    EVENTS = "events"
    RETRANSMISSION = "retransmission"
    RETRANSMISSIONS = "retransmissions"
    FAST_RETRANSMISSION = "fast_retransmission"
    DUPLICATE_ACK = "duplicate_ack"
    DUPLICATE_ACKS = "duplicate_acks"
    OUT_OF_ORDER = "out_of_order"
    WINDOW_CHANGES = "window_changes"
    ZERO_WINDOW = "zero_window"
    WINDOW_FULL = "window_full"
    SUMMARY = "summary"
    FLOW_SUMMARY = "flow_summary"
    IO_TIMELINE = "io_timeline"
    RTT_DISTRIBUTION = "rtt_distribution"
    THROUGHPUT_DISTRIBUTION = "throughput_distribution"
    SYN_OPTIONS = "syn_options"
    PACKET_FIELDS = "packet_fields"
    CUSTOM_PACKET_QUERY = "custom_packet_query"


class EvidenceField(StrEnum):
    EVIDENCE_ID = "evidence_id"
    EVENT_TYPE = "event_type"
    FRAME_NUMBER = "frame.number"
    FRAME_TIME_RELATIVE = "frame.time_relative"
    FLOW_ID = "flow_id"
    DIRECTION = "direction"
    TCP_SEQ = "tcp.seq"
    TCP_ACK = "tcp.ack"
    TCP_WINDOW_SIZE = "tcp.window_size"
    TCP_LENGTH = "tcp.len"
    TCP_ACK_RTT = "tcp.analysis.ack_rtt"


class HypothesisType(StrEnum):
    KNOWN_PATTERN = "known_pattern"
    DATA_DISCOVERED = "data_discovered"
    EXTERNAL_FACTOR = "external_factor"


class Observability(StrEnum):
    DIRECT = "direct"
    INDIRECT = "indirect"
    OUTSIDE_CAPTURE = "outside_capture"


class ContractModel(BaseModel):
    """Strict base class for all stable inter-component contracts."""

    model_config = ConfigDict(extra="forbid")


BoundedQueryString = Annotated[str, Field(min_length=1, max_length=256)]
ConfidencePercentage = Annotated[float, Field(ge=0, le=100)]


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
    complete: bool = False
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
    transport_summary: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    artifact_paths: dict[str, Any] = Field(default_factory=dict)


class EvidencePredicate(ContractModel):
    field: EvidenceField
    operator: EvidenceOperator
    value: Any = None

    @model_validator(mode="after")
    def validate_value_complexity(self) -> EvidencePredicate:
        if self.operator is EvidenceOperator.IN:
            if not isinstance(self.value, list) or not 1 <= len(self.value) <= 32:
                raise ValueError("in predicate requires between 1 and 32 values")
            values = self.value
        else:
            values = [self.value]
        if any(isinstance(value, str) and len(value) > 256 for value in values):
            raise ValueError("predicate string values must not exceed 256 characters")
        return self


class CustomEvidenceQuery(ContractModel):
    flow_ids: list[BoundedQueryString] = Field(default_factory=list, max_length=32)
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    predicates: list[EvidencePredicate] = Field(default_factory=list, max_length=16)
    fields: list[EvidenceField] = Field(default_factory=list, max_length=16)


class EvidenceRequest(ContractModel):
    analysis_id: str
    evidence_type: EvidenceType
    flow_id: BoundedQueryString | None = None
    time_start: float | None = Field(default=None, ge=0)
    time_end: float | None = Field(default=None, ge=0)
    fields: list[EvidenceField] = Field(default_factory=list, max_length=16)
    query: CustomEvidenceQuery | None = None
    offset: int = Field(default=0, ge=0)
    limit: int = Field(default=100, ge=1, le=500)


class EvidenceResponse(ContractModel):
    analysis_id: str
    evidence_type: str
    summary: dict[str, Any] = Field(default_factory=dict)
    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = Field(default=0, ge=0)
    total_exact: bool = True
    next_offset: int | None = None
    truncated: bool = False
    source: str = ""
    coverage_range: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)


class Hypothesis(ContractModel):
    cause: str
    hypothesis_type: HypothesisType
    observability: Observability
    confidence: ConfidencePercentage
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
    candidate_hypotheses: list[Hypothesis] = Field(default_factory=list)
    rejected_causes: list[str] = Field(default_factory=list)
    requested_evidence: list[EvidenceRequest] = Field(default_factory=list)
    ready_for_report: bool = False
    limitations: list[str] = Field(default_factory=list)


class DiagnosticReport(ContractModel):
    standard_bandwidth_mbps: float = Field(gt=0)
    actual_bandwidth_mbps: float = Field(gt=0)
    achievement_ratio_pct: float = Field(ge=0)
    target: Target = Target.DOWNLOAD
    primary_cause: str = "unresolved"
    candidate_causes: list[Hypothesis] = Field(default_factory=list)
    key_evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: ConfidencePercentage
    coverage_summary: CoverageSummary
    evidence_quality: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    troubleshooting_steps: list[str] = Field(default_factory=list)
    optimization_suggestions: list[str] = Field(default_factory=list)
    knowledge_citations: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    knowledge_conflicts: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)


class StallDiagnosticReport(ContractModel):
    mode: Literal["stall"] = "stall"
    analysis_id: str
    primary_cause: str = "unresolved"
    candidate_causes: list[Hypothesis] = Field(default_factory=list)
    key_evidence: list[dict[str, Any]] = Field(default_factory=list)
    confidence: ConfidencePercentage
    coverage_summary: CoverageSummary
    stall_events: list[dict[str, Any]] = Field(default_factory=list, max_length=512)
    protocol_summary: dict[str, Any] = Field(default_factory=dict)
    endpoint_summary: list[dict[str, Any]] = Field(default_factory=list, max_length=128)
    dns_summary: dict[str, Any] = Field(default_factory=dict)
    tls_summary: dict[str, Any] = Field(default_factory=dict)
    http_summary: dict[str, Any] = Field(default_factory=dict)
    udp_summary: dict[str, Any] = Field(default_factory=dict)
    keyword_summary: dict[str, int] = Field(default_factory=dict)
    user_context: dict[str, Any] = Field(default_factory=dict)
    business_analysis: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    troubleshooting_steps: list[str] = Field(default_factory=list)
    optimization_suggestions: list[str] = Field(default_factory=list)
    analysis_metadata: dict[str, Any] = Field(default_factory=dict)


class IntentFieldStatus(StrEnum):
    """Deterministic status for one natural-language intent field."""

    MISSING = "missing"
    PARSED = "parsed"
    AMBIGUOUS = "ambiguous"


class PathReference(ContractModel):
    """Opaque path token safe to include in model messages."""

    placeholder: str = Field(pattern=r"^capture_[0-9a-f]{8}$")


class IntentField(ContractModel):
    status: IntentFieldStatus = IntentFieldStatus.MISSING
    value: str | float | Target | None = None
    detail: str = Field(default="", max_length=512)


class DiagnosisIntent(ContractModel):
    """Structured diagnosis parameters extracted before analysis starts."""

    capture: PathReference | None = None
    standard_bandwidth_value: float | None = Field(default=None, gt=0)
    standard_bandwidth_unit: str | None = Field(default=None, max_length=16)
    actual_bandwidth_value: float | None = Field(default=None, gt=0)
    actual_bandwidth_unit: str | None = Field(default=None, max_length=16)
    standard_bandwidth_mbps: float | None = Field(default=None, gt=0)
    actual_bandwidth_mbps: float | None = Field(default=None, gt=0)
    target: Target | None = None
    fields: dict[str, IntentField] = Field(default_factory=dict, max_length=8)
    missing_fields: list[str] = Field(default_factory=list, max_length=8)
    ambiguities: list[str] = Field(default_factory=list, max_length=8)
    confirmed: bool = False


class ChatEvidenceCitation(ContractModel):
    """A bounded, local evidence reference shown in a chat answer."""

    analysis_id: str = Field(min_length=1, max_length=128)
    evidence_type: str = Field(min_length=1, max_length=64)
    evidence_id: str | None = Field(default=None, max_length=128)
    frame_number: int | None = Field(default=None, ge=0)
    relative_time_seconds: float | None = Field(default=None, ge=0)
    flow_id: str | None = Field(default=None, max_length=128)
    detail: str = Field(default="", max_length=512)


class ChatQuestion(ContractModel):
    question: str = Field(min_length=1, max_length=2_000)
    analysis_id: str | None = Field(default=None, min_length=1, max_length=128)


class ChatAnswer(ContractModel):
    """Structured answer contract for the bounded evidence chat graph."""

    answer: str = Field(min_length=1, max_length=8_000)
    evidence_basis: list[ChatEvidenceCitation] = Field(
        default_factory=list, max_length=32
    )
    knowledge_citations: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    limitations: list[str] = Field(default_factory=list, max_length=32)
    follow_up_suggestions: list[str] = Field(default_factory=list, max_length=32)
    requested_evidence: list[EvidenceRequest] = Field(
        default_factory=list, max_length=5
    )
    ready: bool = False


class GeneralChatAnswer(ContractModel):
    """Response contract for conversation before an analysis is active."""

    answer: str = Field(min_length=1, max_length=8_000)
    knowledge_citations: list[str] = Field(default_factory=list, max_length=32)
    limitations: list[str] = Field(default_factory=list, max_length=32)
    follow_up_suggestions: list[str] = Field(default_factory=list, max_length=8)

    @field_validator("knowledge_citations")
    @classmethod
    def validate_knowledge_citations(cls, values: list[str]) -> list[str]:
        pattern = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
        if any(pattern.fullmatch(value) is None for value in values):
            raise ValueError("knowledge citations must contain valid chunk IDs")
        if len(set(values)) != len(values):
            raise ValueError("knowledge citations must be unique")
        return values


class ConversationTurn(ContractModel):
    question: str = Field(min_length=1, max_length=2_000)
    answer: str = Field(min_length=1, max_length=8_000)


class ChatModelContext(ContractModel):
    """The only session projection allowed to cross into a model call."""

    analysis_id: str = Field(min_length=1, max_length=128)
    target: Target
    report: dict[str, Any] = Field(default_factory=dict)
    diagnosis_context: dict[str, Any] = Field(default_factory=dict)
    conversation_summary: str = Field(default="", max_length=8_000)
    conversation_turns: list[ConversationTurn] = Field(
        default_factory=list, max_length=8
    )
    question: str = Field(min_length=1, max_length=2_000)
    collected_evidence: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    knowledge_context: dict[str, Any] = Field(default_factory=dict)

    @field_validator("knowledge_context")
    @classmethod
    def bound_knowledge_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(value, ensure_ascii=False).encode("utf-8")) > 24_576:
            raise ValueError("knowledge_context must not exceed 24576 bytes")
        return value


class ChatSessionState(ContractModel):
    """CLI-owned state; use ``model_context`` for model serialization."""

    session_id: str = Field(min_length=1, max_length=128)
    pending_intent: DiagnosisIntent | None = None
    analysis_id: str | None = Field(default=None, min_length=1, max_length=128)
    target: Target = Target.DOWNLOAD
    standard_bandwidth_mbps: float | None = Field(default=None, gt=0)
    actual_bandwidth_mbps: float | None = Field(default=None, gt=0)
    report: DiagnosticReport | dict[str, Any] | None = None
    report_path: str | None = None
    local_capture_paths: dict[str, str] = Field(default_factory=dict, max_length=8)
    diagnosis_context: dict[str, Any] = Field(default_factory=dict)
    conversation_turns: list[ConversationTurn] = Field(
        default_factory=list, max_length=8
    )
    conversation_summary: str = Field(default="", max_length=8_000)
    question: str | None = Field(default=None, max_length=2_000)
    requested_evidence: list[EvidenceRequest] = Field(
        default_factory=list, max_length=5
    )
    collected_evidence: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    answer: ChatAnswer | None = None
    inspection_count: int = Field(default=0, ge=0, le=2)
    error: dict[str, Any] | None = None

    def model_context(self) -> ChatModelContext:
        if not self.analysis_id or not self.question:
            raise ValueError("analysis_id and question are required for model context")
        if isinstance(self.report, DiagnosticReport):
            report = self.report.model_dump(mode="json")
        else:
            report = self.report or {}
        return ChatModelContext(
            analysis_id=self.analysis_id,
            target=self.target,
            report=_strip_sensitive(report),
            diagnosis_context=_strip_sensitive(self.diagnosis_context),
            conversation_summary=self.conversation_summary,
            conversation_turns=self.conversation_turns,
            question=self.question,
            collected_evidence=_strip_sensitive(self.collected_evidence),
        )


def _strip_sensitive(value: Any) -> Any:
    """Remove sensitive model fields from a session projection."""

    import re

    sensitive = re.compile(
        r"(?:api[_-]?key|authorization|token|password|payload|raw[_-]?packet|"
        r"per[_-]?packet|full[_-]?log|absolute[_-]?path|pcap[_-]?path)",
        re.IGNORECASE,
    )
    path_value = re.compile(r"^(?:[A-Za-z]:[\\/]|/|\\\\|~[/\\])")

    if isinstance(value, dict):
        return {
            str(key): _strip_sensitive(item)
            for key, item in value.items()
            if not sensitive.search(str(key))
        }
    if isinstance(value, list):
        return [_strip_sensitive(item) for item in value[:32]]
    if isinstance(value, str) and path_value.match(value):
        return "<本地路径已隐藏>"
    return value
