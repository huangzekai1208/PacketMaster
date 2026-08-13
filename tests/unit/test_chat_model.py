import asyncio

from packetmaster.domain import (
    BusinessTargetSelection,
    ChatAnswer,
    ChatModelContext,
    DiagnosisIntent,
    GeneralChatAnswer,
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
        if self.schema is GeneralChatAnswer:
            return GeneralChatAnswer(answer="你好，我可以帮助你分析 TCP 测速问题。")
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


class _BusinessStructured:
    def __init__(self, family: str):
        self.family = family

    async def ainvoke(self, messages):
        serialized = str(messages)
        assert "/private/login" not in serialized
        assert "secret-token-value" not in serialized
        return BusinessTargetSelection(
            selected_family=self.family,
            confidence=91,
            ambiguous=False,
            matched_subject="游戏客户端",
        )


class _BusinessClient:
    def __init__(self, family: str):
        self.family = family

    def with_structured_output(self, schema, method, include_raw=True):
        assert schema is BusinessTargetSelection
        return _BusinessStructured(self.family)


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


def test_general_chat_does_not_require_analysis_context() -> None:
    answer = asyncio.run(DiagnosisModel(client=_FakeClient()).general_chat("你好"))

    assert answer.answer.startswith("你好")


def test_parse_intent_rejects_model_invented_capture_reference() -> None:
    intent, extraction = asyncio.run(
        DiagnosisModel(client=_IntentClient()).parse_intent("请帮我提取诊断参数")
    )

    assert extraction.references == ()
    assert intent.capture is None
    assert "报文路径引用无效" in intent.ambiguities


def test_parse_intent_uses_local_complete_parameters_without_model() -> None:
    text = "报文路径:/tmp/sample.pcapng，标准带宽1G，实际带宽20M，分析速度不达标原因"
    intent, _ = asyncio.run(DiagnosisModel(client=object()).parse_intent(text))

    assert intent.standard_bandwidth_mbps == 1000
    assert intent.actual_bandwidth_mbps == 20
    assert intent.missing_fields == []


def test_parse_intent_defaults_unitless_bandwidth_to_mbps() -> None:
    text = "报文 test.pcapng，标准带宽 1000，实际带宽 20"
    intent, _ = asyncio.run(DiagnosisModel(client=object()).parse_intent(text))

    assert intent.standard_bandwidth_unit == "Mbps"
    assert intent.actual_bandwidth_unit == "Mbps"
    assert intent.standard_bandwidth_mbps == 1000


def test_select_business_target_accepts_only_observed_family() -> None:
    candidates = [
        {"family": "game.example", "hosts": ["auth.game.example"]},
        {"family": "cdn.test", "hosts": ["asset.cdn.test"]},
    ]
    selection = asyncio.run(
        DiagnosisModel(client=_BusinessClient("game.example")).select_business_target(
            "游戏客户端访问 "
            "https://game.example/private/login?token=secret-token-value 失败",
            candidates,
        )
    )

    assert selection.selected_family == "game.example"
    assert selection.ambiguous is False


def test_select_business_target_rejects_invented_family() -> None:
    selection = asyncio.run(
        DiagnosisModel(
            client=_BusinessClient("invented.example")
        ).select_business_target(
            "游戏客户端无法登录",
            [{"family": "observed.example", "hosts": ["auth.observed.example"]}],
        )
    )

    assert selection.selected_family is None
    assert selection.confidence == 0
    assert selection.ambiguous is True
