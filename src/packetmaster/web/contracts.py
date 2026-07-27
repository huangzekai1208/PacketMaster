"""Stable public contracts for the PacketMaster Web interface."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Generic, Literal, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

from packetmaster.domain import ChatEvidenceCitation, DiagnosticReport, Target

PublicId = Annotated[str, Field(min_length=1, max_length=128, pattern=r"^[\w.-]+$")]


class WebContract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TaskStatus(StrEnum):
    DRAFT = "draft"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    QUEUED = "queued"
    VALIDATING = "validating"
    ANALYZING = "analyzing"
    REASONING = "reasoning"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


class MessageType(StrEnum):
    USER = "user"
    ASSISTANT = "assistant"
    CLARIFICATION = "clarification"
    CONFIRMATION = "confirmation"
    SYSTEM = "system"
    PROGRESS = "progress"
    REPORT = "report"
    ERROR = "error"


class EventType(StrEnum):
    ANALYSIS_STATUS = "analysis_status"
    ANALYSIS_PROGRESS = "analysis_progress"
    ANALYSIS_COMPLETED = "analysis_completed"
    ANALYSIS_PARTIAL = "analysis_partial"
    ANALYSIS_FAILED = "analysis_failed"
    ANALYSIS_CANCELLED = "analysis_cancelled"
    CHAT_STATUS = "chat_status"
    CHAT_ANSWER_READY = "chat_answer_ready"


class MissingParameter(StrEnum):
    CAPTURE = "capture"
    STANDARD_BANDWIDTH = "standard_bandwidth"
    ACTUAL_BANDWIDTH = "actual_bandwidth"


class CaptureSummary(WebContract):
    capture_id: PublicId
    file_name: str = Field(min_length=1, max_length=255)
    size_bytes: int = Field(ge=0)

    @field_validator("file_name")
    @classmethod
    def file_name_only(cls, value: str) -> str:
        if "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("file_name must not contain a path")
        return value


class DiagnosisParameters(WebContract):
    capture: CaptureSummary | None = None
    standard_bandwidth_mbps: float | None = Field(default=None, gt=0)
    actual_bandwidth_mbps: float | None = Field(default=None, gt=0)
    target: Target = Target.DOWNLOAD
    missing: list[MissingParameter] = Field(default_factory=list, max_length=3)
    assumptions: list[str] = Field(default_factory=list, max_length=8)
    ambiguities: list[str] = Field(default_factory=list, max_length=8)
    ready_for_confirmation: bool = False


class SessionSummary(WebContract):
    session_id: PublicId
    title: str = Field(default="新诊断", min_length=1, max_length=120)
    status: TaskStatus = TaskStatus.DRAFT
    current_analysis_id: PublicId | None = None
    created_at: datetime
    updated_at: datetime


class WebMessage(WebContract):
    message_id: PublicId
    session_id: PublicId
    message_type: MessageType
    content: str = Field(min_length=1, max_length=8_000)
    created_at: datetime
    analysis_id: PublicId | None = None
    evidence_count: int = Field(default=0, ge=0)


class AnalysisSummary(WebContract):
    analysis_id: PublicId
    session_id: PublicId
    status: TaskStatus
    stage_message: str = Field(default="", max_length=512)
    progress_fraction: float | None = Field(default=None, ge=0, le=1)
    capture: CaptureSummary
    standard_bandwidth_mbps: float = Field(gt=0)
    actual_bandwidth_mbps: float = Field(gt=0)
    target: Target = Target.DOWNLOAD
    created_at: datetime
    updated_at: datetime
    elapsed_seconds: float = Field(default=0, ge=0)
    processed_packets: int | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=128)


class AnalysisEvent(WebContract):
    event_id: int = Field(ge=1)
    analysis_id: PublicId
    event_type: EventType
    status: TaskStatus
    created_at: datetime
    progress_fraction: float | None = Field(default=None, ge=0, le=1)
    stage_message: str = Field(default="", max_length=512)
    processed_packets: int | None = Field(default=None, ge=0)
    elapsed_seconds: float | None = Field(default=None, ge=0)
    error_code: str | None = Field(default=None, max_length=128)


class ApiError(WebContract):
    code: str = Field(min_length=1, max_length=128, pattern=r"^[A-Z0-9_]+$")
    message: str = Field(min_length=1, max_length=1_000)
    recoverable: bool = False
    suggested_action: str = Field(default="", max_length=1_000)
    details: dict[str, str | int | float | bool | None] = Field(
        default_factory=dict, max_length=16
    )


class ErrorEnvelope(WebContract):
    ok: Literal[False] = False
    error: ApiError
    request_id: PublicId | None = None


DataT = TypeVar("DataT")


class SuccessEnvelope(WebContract, Generic[DataT]):
    ok: Literal[True] = True
    data: DataT
    request_id: PublicId | None = None


class Page(WebContract, Generic[DataT]):
    items: list[DataT]
    total: int = Field(ge=0)
    offset: int = Field(ge=0)
    limit: int = Field(ge=1, le=500)


class HealthStatus(WebContract):
    status: Literal["ok"] = "ok"
    version: str = Field(min_length=1, max_length=64)
    model_configured: bool
    tshark_configured: bool


class CreateSessionRequest(WebContract):
    title: str = Field(default="新诊断", min_length=1, max_length=120)


class RegisterCaptureRequest(WebContract):
    path: str = Field(min_length=1, max_length=4_096)


class SubmitMessageRequest(WebContract):
    content: str = Field(min_length=1, max_length=2_000)
    capture_id: PublicId | None = None


class ConfirmAnalysisRequest(WebContract):
    pass


class DeleteResult(WebContract):
    deleted: bool


class ConversationResult(WebContract):
    route: Literal["general", "diagnosis", "analysis_question"]
    assistant_message: WebMessage
    parameters: DiagnosisParameters | None = None
    analysis: AnalysisSummary | None = None


class SessionDetail(WebContract):
    session: SessionSummary
    messages: Page[WebMessage]
    parameters: DiagnosisParameters | None = None


class CreateAnalysisRequest(WebContract):
    session_id: PublicId


class AnalysisDetail(WebContract):
    analysis: AnalysisSummary
    report_available: bool = False
    recoverable: bool = False
    suggested_action: str = Field(default="", max_length=1_000)


class ReportResult(WebContract):
    analysis_id: PublicId
    report: DiagnosticReport


class MetricSeries(WebContract):
    tcp_summary: dict[str, Any] = Field(default_factory=dict)
    coverage_summary: dict[str, Any] = Field(default_factory=dict)
    intervals: list[dict[str, Any]] = Field(default_factory=list, max_length=5_000)
    rtt_histogram: list[dict[str, Any]] = Field(default_factory=list, max_length=64)
    top_flows: list[dict[str, Any]] = Field(default_factory=list, max_length=256)
    point_limit: int = Field(default=5_000, ge=1, le=5_000)
    downsampled: bool = False


class FlowSummary(WebContract):
    flow_id: str = Field(min_length=1, max_length=512)
    direction: Target
    packet_count: int = Field(default=0, ge=0)
    payload_bytes: int = Field(default=0, ge=0)
    throughput_mbps: float = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0, ge=0)
    retransmission_count: int = Field(default=0, ge=0)
    duplicate_ack_count: int = Field(default=0, ge=0)
    out_of_order_count: int = Field(default=0, ge=0)
    zero_window_count: int = Field(default=0, ge=0)
    window_full_count: int = Field(default=0, ge=0)
    window_min: int | None = Field(default=None, ge=0)
    window_max: int | None = Field(default=None, ge=0)


class ChatRequest(WebContract):
    question: str = Field(min_length=1, max_length=2_000)


class ChatTurnResult(WebContract):
    turn_id: PublicId
    analysis_id: PublicId
    question: str = Field(min_length=1, max_length=2_000)
    answer: str = Field(min_length=1, max_length=8_000)
    citations: list[ChatEvidenceCitation] = Field(default_factory=list, max_length=32)
    knowledge_citations: list[dict[str, Any]] = Field(
        default_factory=list, max_length=32
    )
    limitations: list[str] = Field(default_factory=list, max_length=32)
    suggestions: list[str] = Field(default_factory=list, max_length=32)
    created_at: datetime


def public_json(value: WebContract) -> dict[str, Any]:
    """Return the JSON-mode projection used by API adapters."""

    return value.model_dump(mode="json")
