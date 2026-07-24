import asyncio

from packetmaster.domain import (
    ChatAnswer,
    ChatModelContext,
    DiagnosisIntent,
    PathReference,
    Target,
)
from packetmaster.model import DiagnosisModel


class _Structured:
    def __init__(self, schema):
        self.schema = schema

    async def ainvoke(self, messages):
        assert "/Users" not in str(messages)
        assert "API_KEY" not in str(messages)
        if self.schema is ChatAnswer:
            return ChatAnswer(answer="当前证据显示存在重传。", ready=True)
        raise AssertionError(self.schema)


class _FakeClient:
    def with_structured_output(self, schema, method):
        assert method in {"json_mode", "json_schema"}
        return _Structured(schema)


class _IntentStructured:
    async def ainvoke(self, messages):
        return DiagnosisIntent(capture=PathReference(placeholder="capture_deadbeef"))


class _IntentClient:
    def with_structured_output(self, schema, method):
        assert schema is DiagnosisIntent
        return _IntentStructured()


def _context() -> ChatModelContext:
    return ChatModelContext(
        analysis_id="analysis-1",
        target=Target.DOWNLOAD,
        question="主因是什么？",
        report={"coverage_summary": {"complete": True}},
    )


def test_answer_question_uses_chat_schema_without_sensitive_data() -> None:
    answer = asyncio.run(
        DiagnosisModel(client=_FakeClient()).answer_question(_context())
    )

    assert answer.ready is True
    assert answer.answer.startswith("当前证据")


def test_verify_chat_answer_returns_structured_answer() -> None:
    model = DiagnosisModel(client=_FakeClient())
    answer = asyncio.run(
        model.verify_chat_answer(_context(), ChatAnswer(answer="草稿"), [])
    )

    assert answer.ready is True


def test_parse_intent_rejects_model_invented_capture_reference() -> None:
    intent, extraction = asyncio.run(
        DiagnosisModel(client=_IntentClient()).parse_intent("标准 1G，实际 600M")
    )

    assert extraction.references == ()
    assert intent.capture is None
    assert "报文路径引用无效" in intent.ambiguities
