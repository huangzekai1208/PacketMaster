from __future__ import annotations

import asyncio
from datetime import UTC, datetime

import pytest
from langchain_core.exceptions import OutputParserException

from packetmaster.config import Settings
from packetmaster.domain import GeneralChatAnswer
from packetmaster.errors import AppError
from packetmaster.llm_observability import (
    JsonlLLMCallObserver,
    LLMCallRecord,
    LLMCallStatus,
    LLMObservationCollector,
    LLMTokenUsage,
    load_llm_calls,
    summarize_llm_calls,
)
from packetmaster.model import DiagnosisModel


class _Raw:
    usage_metadata = {
        "input_tokens": 100,
        "output_tokens": 20,
        "total_tokens": 120,
    }


class _MalformedUsageRaw:
    usage_metadata = {
        "input_tokens": "not-a-number",
        "output_tokens": -1,
    }


class _FencedRaw:
    usage_metadata = {"input_tokens": 10, "output_tokens": 5}
    content = '```json\n{"answer":"恢复成功"}\n```'


class _Structured:
    def __init__(self, values: list[object]) -> None:
        self.values = iter(values)

    async def ainvoke(self, messages):
        return next(self.values)


class _Client:
    def __init__(self, values: list[object]) -> None:
        self.values = values
        self.include_raw = None

    def with_structured_output(self, schema, *, method, include_raw=False):
        self.include_raw = include_raw
        return _Structured(self.values)


def _settings() -> Settings:
    return Settings(
        model_name="test-model-v1",
        model_base_url="https://example.invalid/v1",
        model_input_cost_per_million_usd=1.0,
        model_output_cost_per_million_usd=2.0,
    )


def test_model_records_usage_cost_and_only_hashed_prompt_metadata() -> None:
    client = _Client(
        [
            {
                "parsed": GeneralChatAnswer(answer="安全回答"),
                "raw": _Raw(),
                "parsing_error": None,
            }
        ]
    )
    collector = LLMObservationCollector()
    model = DiagnosisModel(client=client, settings=_settings(), observer=collector)

    with collector.scope("request-1") as calls:
        answer = asyncio.run(model.general_chat("不能进入观测记录的用户问题"))

    assert answer.answer == "安全回答"
    assert client.include_raw is True
    assert len(calls) == 1
    call = calls[0]
    assert call.trace_id == "request-1"
    assert call.operation == "general_chat"
    assert call.model_name == "test-model-v1"
    assert call.status is LLMCallStatus.SUCCEEDED
    assert call.usage == LLMTokenUsage(
        input_tokens=100, output_tokens=20, total_tokens=120
    )
    assert call.estimated_cost_usd == pytest.approx(0.00014)
    serialized = call.model_dump_json()
    assert "用户问题" not in serialized
    assert "安全回答" not in serialized
    assert "https://" not in serialized


def test_model_records_schema_repair_attempts_and_accumulates_usage() -> None:
    client = _Client(
        [
            {
                "parsed": None,
                "raw": _Raw(),
                "parsing_error": OutputParserException("invalid"),
            },
            {
                "parsed": GeneralChatAnswer(answer="修复成功"),
                "raw": _Raw(),
                "parsing_error": None,
            },
        ]
    )
    collector = LLMObservationCollector()
    model = DiagnosisModel(client=client, settings=_settings(), observer=collector)

    with collector.scope("request-2") as calls:
        asyncio.run(model.general_chat("问题"))

    assert calls[0].attempt_count == 2
    assert calls[0].retry_count == 1
    assert calls[0].message_count == 3
    assert calls[0].usage.total_tokens == 240


def test_malformed_provider_usage_does_not_break_a_valid_answer() -> None:
    client = _Client(
        [
            {
                "parsed": GeneralChatAnswer(answer="有效回答"),
                "raw": _MalformedUsageRaw(),
                "parsing_error": None,
            }
        ]
    )
    collector = LLMObservationCollector()
    model = DiagnosisModel(client=client, settings=_settings(), observer=collector)

    with collector.scope("request-malformed-usage") as calls:
        answer = asyncio.run(model.general_chat("问题"))

    assert answer.answer == "有效回答"
    assert calls[0].status is LLMCallStatus.SUCCEEDED
    assert calls[0].usage.total_tokens is None


def test_model_recovers_schema_valid_json_from_fenced_provider_output() -> None:
    client = _Client(
        [
            {
                "parsed": None,
                "raw": _FencedRaw(),
                "parsing_error": OutputParserException("wrapped JSON"),
            }
        ]
    )
    collector = LLMObservationCollector()
    model = DiagnosisModel(client=client, settings=_settings(), observer=collector)

    with collector.scope("request-fenced-json") as calls:
        answer = asyncio.run(model.general_chat("问题"))

    assert answer.answer == "恢复成功"
    assert calls[0].status is LLMCallStatus.SUCCEEDED
    assert calls[0].attempt_count == 1


def test_invalid_telemetry_identity_never_breaks_a_valid_answer() -> None:
    client = _Client(
        [
            {
                "parsed": GeneralChatAnswer(answer="有效回答"),
                "raw": _Raw(),
                "parsing_error": None,
            }
        ]
    )
    collector = LLMObservationCollector()
    settings = _settings().model_copy(update={"model_name": "sk-secret-model-name"})
    model = DiagnosisModel(client=client, settings=settings, observer=collector)

    with collector.scope("request-invalid-identity") as calls:
        answer = asyncio.run(model.general_chat("问题"))

    assert answer.answer == "有效回答"
    assert calls == []


def test_model_failure_is_observed_without_exception_text() -> None:
    client = _Client(
        [
            {
                "parsed": None,
                "raw": _Raw(),
                "parsing_error": OutputParserException("secret parser detail"),
            },
            {
                "parsed": None,
                "raw": _Raw(),
                "parsing_error": OutputParserException("secret parser detail"),
            },
        ]
    )
    collector = LLMObservationCollector()
    model = DiagnosisModel(client=client, settings=_settings(), observer=collector)

    with collector.scope("request-3") as calls:
        with pytest.raises(AppError) as raised:
            asyncio.run(model.general_chat("问题"))

    assert raised.value.code == "INVALID_MODEL_OUTPUT"
    assert calls[0].status is LLMCallStatus.FAILED
    assert calls[0].error_code == "INVALID_MODEL_OUTPUT"
    assert "secret parser detail" not in calls[0].model_dump_json()


def _record(call_id: str, operation: str) -> LLMCallRecord:
    return LLMCallRecord(
        call_id=call_id,
        operation=operation,
        model_name="model",
        prompt_name=f"{operation}.md",
        prompt_sha256="a" * 64,
        output_schema="Answer",
        structured_output_method="json_schema",
        started_at=datetime.now(UTC),
        latency_seconds=0.1,
        attempt_count=1,
        retry_count=0,
        input_bytes=10,
        message_count=2,
        status="succeeded",
        usage={"input_tokens": 10, "output_tokens": 5},
        estimated_cost_usd=0.001,
    )


def test_collector_isolates_concurrent_request_scopes() -> None:
    collector = LLMObservationCollector()

    async def collect(trace_id: str, call_id: str):
        with collector.scope(trace_id) as calls:
            await asyncio.sleep(0)
            collector.record(_record(call_id, "answer"))
            await asyncio.sleep(0)
            return calls

    async def run_concurrently():
        return await asyncio.gather(
            collect("trace-a", "a" * 32),
            collect("trace-b", "b" * 32),
        )

    first, second = asyncio.run(run_concurrently())

    assert [item.trace_id for item in first] == ["trace-a"]
    assert [item.trace_id for item in second] == ["trace-b"]


def test_summary_reports_usage_coverage_and_operation_counts() -> None:
    first = _record("a" * 32, "hypothesis")
    second = _record("b" * 32, "verification").model_copy(
        update={
            "status": LLMCallStatus.FAILED,
            "error_code": "MODEL_TIMEOUT",
            "attempt_count": 2,
            "retry_count": 1,
            "usage": LLMTokenUsage(),
            "estimated_cost_usd": None,
        }
    )

    summary = summarize_llm_calls([first, second])

    assert summary.call_count == 2
    assert summary.succeeded_count == 1
    assert summary.failed_count == 1
    assert summary.retry_count == 1
    assert summary.calls_with_token_usage == 1
    assert summary.total_tokens == 15
    assert summary.operation_counts == {"hypothesis": 1, "verification": 1}


def test_jsonl_observer_round_trips_validated_metadata(tmp_path) -> None:
    path = tmp_path / "observability" / "llm_calls.jsonl"
    observer = JsonlLLMCallObserver(path)
    observer.record(_record("a" * 32, "hypothesis"))
    observer.record(_record("b" * 32, "verification"))

    values = load_llm_calls(path, limit=1)

    assert [value.operation for value in values] == ["verification"]
    assert "prompt content" not in path.read_text(encoding="utf-8")
