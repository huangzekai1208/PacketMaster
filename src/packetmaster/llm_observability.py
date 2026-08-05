"""Bounded LLM call telemetry without prompts, answers, or secrets."""

from __future__ import annotations

import contextvars
import re
import threading
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field, model_validator

_SENSITIVE_IDENTITY = re.compile(
    r"(?i)(?:sk-[a-z0-9._-]{12,}|Bearer\s+\S+|[a-z]:[\\/]|"
    r"/(?:users|home|private|tmp|var)/)"
)


class LLMCallStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class LLMTokenUsage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def fill_total(self) -> LLMTokenUsage:
        if (
            self.total_tokens is None
            and self.input_tokens is not None
            and self.output_tokens is not None
        ):
            self.total_tokens = self.input_tokens + self.output_tokens
        return self


class LLMCallRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    trace_id: str | None = Field(default=None, pattern=r"^[A-Za-z0-9._-]{1,128}$")
    operation: str = Field(pattern=r"^[a-z0-9._-]{1,128}$")
    model_name: str = Field(min_length=1, max_length=256)
    prompt_name: str = Field(pattern=r"^[A-Za-z0-9._-]{1,128}$")
    prompt_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    output_schema: str = Field(min_length=1, max_length=256)
    structured_output_method: str = Field(min_length=1, max_length=64)
    started_at: datetime
    latency_seconds: float = Field(ge=0)
    attempt_count: int = Field(ge=1, le=10)
    retry_count: int = Field(ge=0, le=9)
    input_bytes: int = Field(ge=0)
    message_count: int = Field(ge=1, le=32)
    status: LLMCallStatus
    usage: LLMTokenUsage = Field(default_factory=LLMTokenUsage)
    estimated_cost_usd: float | None = Field(default=None, ge=0)
    error_code: str | None = Field(
        default=None, pattern=r"^[A-Z0-9_]{1,128}$"
    )

    @model_validator(mode="after")
    def validate_status(self) -> LLMCallRecord:
        if _SENSITIVE_IDENTITY.search(self.model_name):
            raise ValueError("LLM model identity contains a secret or local path")
        if self.retry_count != self.attempt_count - 1:
            raise ValueError("retry count must match attempt count")
        if self.status is LLMCallStatus.SUCCEEDED and self.error_code is not None:
            raise ValueError("successful calls cannot have an error code")
        if self.status is LLMCallStatus.FAILED and self.error_code is None:
            raise ValueError("failed calls require an error code")
        return self


class LLMObservationSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    call_count: int = Field(ge=0)
    succeeded_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    calls_with_token_usage: int = Field(ge=0)
    input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)
    estimated_cost_usd: float = Field(ge=0)
    operation_counts: dict[str, int] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_counts(self) -> LLMObservationSummary:
        if self.succeeded_count + self.failed_count != self.call_count:
            raise ValueError("LLM summary status counts must match total calls")
        if self.calls_with_token_usage > self.call_count:
            raise ValueError("LLM usage count cannot exceed total calls")
        if sum(self.operation_counts.values()) != self.call_count:
            raise ValueError("LLM operation counts must match total calls")
        return self


class LLMCallObserver(Protocol):
    def record(self, value: LLMCallRecord) -> None: ...


class NullLLMCallObserver:
    def record(self, value: LLMCallRecord) -> None:
        return None


class LLMObservationCollector:
    """Collect calls inside an async-safe request scope."""

    def __init__(self, downstream: LLMCallObserver | None = None) -> None:
        self.downstream = downstream
        self._scope: contextvars.ContextVar[
            tuple[str, list[LLMCallRecord]] | None
        ] = contextvars.ContextVar("packetmaster_llm_observation_scope", default=None)

    @contextmanager
    def scope(self, trace_id: str) -> Iterator[list[LLMCallRecord]]:
        values: list[LLMCallRecord] = []
        token = self._scope.set((trace_id, values))
        try:
            yield values
        finally:
            self._scope.reset(token)

    def trace_id(self) -> str | None:
        current = self._scope.get()
        return current[0] if current is not None else None

    def record(self, value: LLMCallRecord) -> None:
        current = self._scope.get()
        if current is not None:
            if value.trace_id is None:
                value = value.model_copy(update={"trace_id": current[0]})
            current[1].append(value)
        if self.downstream is not None:
            self.downstream.record(value)


class JsonlLLMCallObserver:
    """Append validated metadata records to a thread-safe local artifact."""

    def __init__(self, path: Path) -> None:
        self.path = path.expanduser().resolve()
        self._lock = threading.Lock()

    def record(self, value: LLMCallRecord) -> None:
        encoded = value.model_dump_json() + "\n"
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as stream:
                stream.write(encoded)


def utc_now() -> datetime:
    return datetime.now(UTC)


def token_usage_from_mapping(values: object) -> LLMTokenUsage:
    if not isinstance(values, Mapping):
        return LLMTokenUsage()
    try:
        return LLMTokenUsage(
            input_tokens=values.get("input_tokens", values.get("prompt_tokens")),
            output_tokens=values.get(
                "output_tokens", values.get("completion_tokens")
            ),
            total_tokens=values.get("total_tokens"),
        )
    except (TypeError, ValueError):
        return LLMTokenUsage()


def summarize_llm_calls(values: list[LLMCallRecord]) -> LLMObservationSummary:
    operations: dict[str, int] = {}
    for value in values:
        operations[value.operation] = operations.get(value.operation, 0) + 1
    return LLMObservationSummary(
        call_count=len(values),
        succeeded_count=sum(
            value.status is LLMCallStatus.SUCCEEDED for value in values
        ),
        failed_count=sum(value.status is LLMCallStatus.FAILED for value in values),
        retry_count=sum(value.retry_count for value in values),
        calls_with_token_usage=sum(
            value.usage.total_tokens is not None for value in values
        ),
        input_tokens=sum(value.usage.input_tokens or 0 for value in values),
        output_tokens=sum(value.usage.output_tokens or 0 for value in values),
        total_tokens=sum(value.usage.total_tokens or 0 for value in values),
        estimated_cost_usd=sum(value.estimated_cost_usd or 0 for value in values),
        operation_counts=operations,
    )


def load_llm_calls(path: Path, *, limit: int = 10_000) -> list[LLMCallRecord]:
    if not 1 <= limit <= 100_000:
        raise ValueError("LLM call load limit must be between 1 and 100000")
    resolved = path.expanduser().resolve()
    if not resolved.exists():
        return []
    with resolved.open("r", encoding="utf-8") as stream:
        lines = deque((line.rstrip("\n") for line in stream), maxlen=limit)
    return [LLMCallRecord.model_validate_json(line) for line in lines if line]
