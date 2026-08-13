"""使用 OpenAI 兼容接口生成结构化诊断结论，不暴露隐藏推理。"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Mapping
from datetime import datetime
from importlib.resources import files
from typing import Any
from uuid import uuid4

from langchain_core.exceptions import OutputParserException
from pydantic import BaseModel, ValidationError

from packetmaster.config import Settings
from packetmaster.context import DiagnosisContext, bounded_evidence
from packetmaster.domain import (
    BusinessTargetSelection,
    ChatAnswer,
    ChatModelContext,
    DiagnosisIntent,
    EvidenceResponse,
    GeneralChatAnswer,
    HypothesisBatch,
    VerificationResult,
)
from packetmaster.errors import AppError
from packetmaster.intent import (
    PathExtraction,
    extract_capture_paths,
    extract_contextual_values,
    extract_explicit_bandwidth,
    merge_intent,
)
from packetmaster.llm_observability import (
    LLMCallObserver,
    LLMCallRecord,
    LLMCallStatus,
    LLMTokenUsage,
    NullLLMCallObserver,
    token_usage_from_mapping,
    utc_now,
)
from packetmaster.rag.contracts import KnowledgeAugmentation, KnowledgeBundle

_CJK_PATTERN = re.compile(r"[\u3400-\u4dbf\u4e00-\u9fff]")
_LATIN_WORD_PATTERN = re.compile(r"[A-Za-z]{2,}")
_BUSINESS_URL_PATTERN = re.compile(
    r"https?://(?P<host>[a-z0-9.-]+)(?::\d+)?(?:/[^\s]*)?", re.IGNORECASE
)
_BUSINESS_SECRET_PATTERN = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{12,}|"
    r"(?:api[_-]?key|authorization|token|password|passwd|密码)\s*[:=：]\s*\S+)"
)


class _ChineseOutputError(ValueError):
    def __init__(self, count: int) -> None:
        super().__init__("model user-facing output is not simplified Chinese")
        self.count = count


def _hypothesis_texts(batch: HypothesisBatch) -> list[str]:
    values: list[str] = []
    for hypothesis in batch.hypotheses:
        values.extend(
            [
                hypothesis.cause,
                *hypothesis.supporting_evidence,
                *hypothesis.contradicting_evidence,
                *hypothesis.missing_evidence,
                hypothesis.explanation,
                hypothesis.suggestion,
            ]
        )
    return values


def _english_narrative(value: str) -> bool:
    if not value.strip() or _CJK_PATTERN.search(value):
        return False
    words = _LATIN_WORD_PATTERN.findall(value)
    if not words:
        return False
    if all(word.isupper() and len(word) <= 8 for word in words):
        return False
    return len(words) >= 2 or sum(len(word) for word in words) >= 10


def _bounded_business_symptom(value: str) -> str:
    """Retain the business subject and action without URL paths or credentials."""
    without_paths = _BUSINESS_URL_PATTERN.sub(lambda match: match.group("host"), value)
    without_secrets = _BUSINESS_SECRET_PATTERN.sub("<敏感信息已隐藏>", without_paths)
    return " ".join(without_secrets.split()).strip()[:500]


def _ensure_chinese_user_text(value: BaseModel) -> None:
    texts: list[str] = []
    if isinstance(value, HypothesisBatch):
        texts = _hypothesis_texts(value)
    elif isinstance(value, VerificationResult):
        texts = [
            *_hypothesis_texts(HypothesisBatch(hypotheses=value.candidate_hypotheses)),
            *value.rejected_causes,
            *value.limitations,
        ]
    elif isinstance(value, KnowledgeAugmentation):
        texts = [
            *_hypothesis_texts(value.hypotheses),
            *value.limitations,
            *(citation.supported_statement for citation in value.citations),
        ]
    invalid_count = sum(_english_narrative(text) for text in texts)
    if invalid_count:
        raise _ChineseOutputError(invalid_count)


class DiagnosisModel:
    def __init__(
        self,
        client: Any | None = None,
        settings: Settings | None = None,
        observer: LLMCallObserver | None = None,
    ) -> None:
        self.settings = settings
        self._client = client
        self.observer = observer or NullLLMCallObserver()

    def _structured_output_method(self) -> str:
        settings = self.settings or Settings.load()
        configured = settings.model_structured_output_method
        if configured != "auto":
            return configured
        provider_identity = " ".join(
            value for value in (settings.model_name, settings.model_base_url) if value
        ).lower()
        return "json_mode" if "deepseek" in provider_identity else "json_schema"

    def _client_or_error(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from langchain_openai import ChatOpenAI
        except ImportError as exc:
            raise AppError(
                code="MODEL_DEPENDENCY_UNAVAILABLE",
                message="langchain-openai is not installed",
                recoverable=False,
                suggested_action="Install PacketMaster model dependencies.",
            ) from exc
        settings = self.settings or Settings.load()
        api_key = (
            settings.model_api_key.get_secret_value()
            if settings.model_api_key is not None
            else None
        )
        self._client = ChatOpenAI(
            model=settings.model_name,
            base_url=settings.model_base_url,
            api_key=api_key,
            timeout=settings.model_timeout_seconds,
        )
        return self._client

    @staticmethod
    def _prompt(name: str) -> str:
        try:
            return (
                files("packetmaster")
                .joinpath("prompts", name)
                .read_text(encoding="utf-8")
            )
        except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
            raise AppError(
                code="MODEL_PROMPT_UNAVAILABLE",
                message="PacketMaster diagnosis prompt is unavailable",
                recoverable=False,
                suggested_action="Reinstall PacketMaster prompt resources.",
                details={"prompt": name},
            ) from exc

    async def _invoke(
        self, schema: type[BaseModel], prompt_name: str, payload: dict[str, Any]
    ) -> BaseModel:
        started_at = utc_now()
        started = time.perf_counter()
        attempts = 0
        usage = LLMTokenUsage()
        client = self._client_or_error()
        serialized_payload = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        )
        if len(serialized_payload) > 132_000:
            raise AppError(
                code="MODEL_CONTEXT_TOO_LARGE",
                message="Bounded diagnosis context exceeds the model input limit",
                recoverable=True,
                suggested_action="Reduce evidence pages or hypothesis count.",
            )
        method = self._structured_output_method()
        system_prompt = self._prompt(prompt_name)
        if method == "json_mode":
            serialized_schema = json.dumps(
                schema.model_json_schema(),
                ensure_ascii=False,
                separators=(",", ":"),
            )
            system_prompt += (
                "\n\n只返回一个符合以下 JSON Schema 的 JSON 对象，不要使用 Markdown "
                f"代码块或输出额外文本。JSON Schema：{serialized_schema}"
            )
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": serialized_payload,
            },
        ]
        include_raw = True
        try:
            structured = client.with_structured_output(
                schema, method=method, include_raw=True
            )
        except TypeError as exc:
            if "include_raw" not in str(exc):
                raise
            include_raw = False
            structured = client.with_structured_output(schema, method=method)
        try:
            for attempt in range(2):
                attempts = attempt + 1
                try:
                    result = await structured.ainvoke(messages)
                    parsed, raw, parsing_error = self._structured_result(
                        result, include_raw=include_raw
                    )
                    usage = self._merge_usage(usage, self._extract_usage(raw))
                    if parsing_error is not None:
                        recovered = self._recover_structured_result(raw, schema)
                        if recovered is None:
                            raise parsing_error
                        parsed = recovered
                    validated = (
                        parsed
                        if isinstance(parsed, schema)
                        else schema.model_validate(parsed)
                    )
                    _ensure_chinese_user_text(validated)
                    self._record_call(
                        prompt_name=prompt_name,
                        system_prompt=system_prompt,
                        schema=schema,
                        method=method,
                        started_at=started_at,
                        started=started,
                        attempts=attempts,
                        input_bytes=len(serialized_payload.encode("utf-8")),
                        message_count=len(messages),
                        status=LLMCallStatus.SUCCEEDED,
                        usage=usage,
                    )
                    return validated
                except (
                    OutputParserException,
                    ValidationError,
                    _ChineseOutputError,
                ) as exc:
                    if attempt == 1:
                        language_error = isinstance(exc, _ChineseOutputError)
                        raise AppError(
                            code=(
                                "INVALID_MODEL_LANGUAGE"
                                if language_error
                                else "INVALID_MODEL_OUTPUT"
                            ),
                            message=(
                                "诊断模型未按要求使用简体中文"
                                if language_error
                                else (
                                    "Diagnosis model returned invalid structured output"
                                )
                            ),
                            recoverable=True,
                            suggested_action=(
                                "请从最近的诊断断点重试。"
                                if language_error
                                else "Retry with the PacketMaster structured schema."
                            ),
                            details={
                                "attempts": 2,
                                "exception_type": exc.__class__.__name__,
                                **(
                                    {"invalid_text_fields": exc.count}
                                    if language_error
                                    else {}
                                ),
                            },
                        ) from exc
                    if isinstance(exc, _ChineseOutputError):
                        repair_instruction = (
                            "上一次响应的结构正确，但面向用户的报告文字包含英文。"
                            "请保持分析结论、数值、证据引用和 JSON 结构不变，仅将 "
                            "cause、支持/反向/缺失证据、explanation、suggestion、"
                            "rejected_causes、limitations 等叙述字段改写为简体中文。"
                            "TCP、RTT、ACK、Mbps、IP、流 ID、协议字段、JSON 属性名和"
                            "枚举值保持原样。只返回 JSON 对象。"
                        )
                    else:
                        repair_instruction = (
                            "上一次响应未通过结构化校验。请保持原分析结论，"
                            "仅修复输出结构，使其严格符合系统消息中的 JSON "
                            "Schema；只返回 JSON 对象，不要输出解释、Markdown "
                            "或代码块。"
                        )
                    messages = [
                        *messages,
                        {
                            "role": "user",
                            "content": repair_instruction,
                        },
                    ]
        except TimeoutError as exc:
            error = AppError(
                code="MODEL_TIMEOUT",
                message="Diagnosis model timed out",
                recoverable=True,
                suggested_action="Retry or increase the model timeout.",
            )
            self._record_failed_call(
                error,
                prompt_name,
                system_prompt,
                schema,
                method,
                started_at,
                started,
                attempts,
                serialized_payload,
                messages,
                usage,
            )
            raise error from exc
        except AppError as error:
            self._record_failed_call(
                error,
                prompt_name,
                system_prompt,
                schema,
                method,
                started_at,
                started,
                max(1, attempts),
                serialized_payload,
                messages,
                usage,
            )
            raise
        except Exception as exc:
            error = AppError(
                code="MODEL_CALL_FAILED",
                message="Diagnosis model call failed",
                recoverable=True,
                suggested_action="Check model configuration and retry.",
                details={
                    "exception_type": exc.__class__.__name__,
                    "structured_output_method": method,
                },
            )
            self._record_failed_call(
                error,
                prompt_name,
                system_prompt,
                schema,
                method,
                started_at,
                started,
                max(1, attempts),
                serialized_payload,
                messages,
                usage,
            )
            raise error from exc

    @staticmethod
    def _structured_result(
        result: object, *, include_raw: bool
    ) -> tuple[object, object | None, Exception | None]:
        if include_raw and isinstance(result, Mapping) and "parsed" in result:
            parsing_error = result.get("parsing_error")
            return (
                result.get("parsed"),
                result.get("raw"),
                parsing_error if isinstance(parsing_error, Exception) else None,
            )
        return result, None, None

    @staticmethod
    def _recover_structured_result(
        raw: object | None, schema: type[BaseModel]
    ) -> BaseModel | None:
        """Recover valid JSON wrapped in fences or surrounding prose.

        Some OpenAI-compatible gateways report a parser error even when the
        response contains a valid JSON object. Recovery remains strict: the
        extracted object must pass the requested Pydantic schema unchanged.
        """
        content = getattr(raw, "content", None)
        if isinstance(content, list):
            content = "".join(
                item.get("text", "")
                for item in content
                if isinstance(item, Mapping) and isinstance(item.get("text"), str)
            )
        if not isinstance(content, str) or not content.strip():
            return None
        candidate = content.strip()
        if candidate.startswith("```"):
            lines = candidate.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            candidate = "\n".join(lines).strip()
        start, end = candidate.find("{"), candidate.rfind("}")
        if start < 0 or end <= start:
            return None
        try:
            value = json.loads(candidate[start : end + 1])
            return schema.model_validate(value)
        except (json.JSONDecodeError, TypeError, ValidationError):
            return None

    @staticmethod
    def _extract_usage(raw: object | None) -> LLMTokenUsage:
        if raw is None:
            return LLMTokenUsage()
        direct = getattr(raw, "usage_metadata", None)
        metadata = getattr(raw, "response_metadata", None)
        token_usage = (
            metadata.get("token_usage") if isinstance(metadata, Mapping) else None
        )
        values = direct if isinstance(direct, Mapping) else token_usage
        return token_usage_from_mapping(values)

    @staticmethod
    def _merge_usage(left: LLMTokenUsage, right: LLMTokenUsage) -> LLMTokenUsage:
        def add(first: int | None, second: int | None) -> int | None:
            if first is None:
                return second
            if second is None:
                return first
            return first + second

        return LLMTokenUsage(
            input_tokens=add(left.input_tokens, right.input_tokens),
            output_tokens=add(left.output_tokens, right.output_tokens),
            total_tokens=add(left.total_tokens, right.total_tokens),
        )

    def _estimated_cost(self, usage: LLMTokenUsage) -> float | None:
        settings = self.settings or Settings.load()
        if (
            usage.input_tokens is None
            or usage.output_tokens is None
            or settings.model_input_cost_per_million_usd is None
            or settings.model_output_cost_per_million_usd is None
        ):
            return None
        return (
            usage.input_tokens * settings.model_input_cost_per_million_usd
            + usage.output_tokens * settings.model_output_cost_per_million_usd
        ) / 1_000_000

    def _record_call(
        self,
        *,
        prompt_name: str,
        system_prompt: str,
        schema: type[BaseModel],
        method: str,
        started_at: datetime,
        started: float,
        attempts: int,
        input_bytes: int,
        message_count: int,
        status: LLMCallStatus,
        usage: LLMTokenUsage,
        error_code: str | None = None,
    ) -> None:
        try:
            settings = self.settings or Settings.load()
            value = LLMCallRecord(
                call_id=uuid4().hex,
                operation=prompt_name.removesuffix(".md"),
                model_name=settings.model_name,
                prompt_name=prompt_name,
                prompt_sha256=hashlib.sha256(system_prompt.encode("utf-8")).hexdigest(),
                output_schema=schema.__name__,
                structured_output_method=method,
                started_at=started_at,
                latency_seconds=time.perf_counter() - started,
                attempt_count=attempts,
                retry_count=attempts - 1,
                input_bytes=input_bytes,
                message_count=message_count,
                status=status,
                usage=usage,
                estimated_cost_usd=self._estimated_cost(usage),
                error_code=error_code,
            )
            self.observer.record(value)
        except Exception:
            # Telemetry must never break diagnosis or expose user data in errors.
            return

    def _record_failed_call(
        self,
        error: AppError,
        prompt_name: str,
        system_prompt: str,
        schema: type[BaseModel],
        method: str,
        started_at: datetime,
        started: float,
        attempts: int,
        serialized_payload: str,
        messages: list[dict[str, str]],
        usage: LLMTokenUsage,
    ) -> None:
        self._record_call(
            prompt_name=prompt_name,
            system_prompt=system_prompt,
            schema=schema,
            method=method,
            started_at=started_at,
            started=started,
            attempts=attempts,
            input_bytes=len(serialized_payload.encode("utf-8")),
            message_count=len(messages),
            status=LLMCallStatus.FAILED,
            usage=usage,
            error_code=error.code,
        )

    async def generate_hypotheses(self, context: DiagnosisContext) -> HypothesisBatch:
        result = await self._invoke(
            HypothesisBatch,
            "hypothesis.md",
            {"diagnosis_context": context.model_dump(mode="json")},
        )
        return HypothesisBatch.model_validate(result)

    async def parse_intent(
        self,
        user_text: str,
        previous: DiagnosisIntent | None = None,
    ) -> tuple[DiagnosisIntent, PathExtraction]:
        """Extract intent from sanitized text while keeping paths local."""

        extraction = extract_capture_paths(user_text)
        explicit = extract_explicit_bandwidth(user_text)
        contextual = extract_contextual_values(user_text, previous)
        local_values: dict[str, Any] = {}
        if extraction.references:
            local_values["capture"] = extraction.references[0]
        local_values.update(explicit)
        for key, value in contextual.items():
            local_values.setdefault(key, value)
        # Explicit values and short contextual replies do not need a fragile
        # model round trip, even when another field still needs clarification.
        if extraction.references or explicit or contextual:
            intent = DiagnosisIntent(**local_values)
        else:
            try:
                result = await self._invoke(
                    DiagnosisIntent,
                    "diagnosis_intent.md",
                    {
                        "user_message": extraction.sanitized_text,
                        "previous_intent": previous.model_dump(mode="json")
                        if previous is not None
                        else None,
                    },
                )
                intent = DiagnosisIntent.model_validate(result)
            except AppError:
                if not local_values:
                    raise
                intent = DiagnosisIntent(**local_values)
        for key, value in local_values.items():
            setattr(intent, key, value)
        allowed_references = {
            reference.placeholder for reference in extraction.references
        }
        if previous is not None and previous.capture is not None:
            allowed_references.add(previous.capture.placeholder)
        if (
            intent.capture is not None
            and intent.capture.placeholder not in allowed_references
        ):
            intent.capture = None
            intent.ambiguities.append("报文路径引用无效")
        if len(extraction.references) == 1:
            intent.capture = extraction.references[0]
        elif len(extraction.references) > 1:
            intent.capture = None
            intent.ambiguities.append("检测到多个报文路径")
        return merge_intent(previous, intent), extraction

    async def select_business_target(
        self,
        symptom: str,
        candidates: list[dict[str, Any]],
    ) -> BusinessTargetSelection:
        bounded = [
            {
                "family": str(item.get("family", ""))[:253],
                "hosts": [str(host)[:253] for host in item.get("hosts", [])[:16]],
                "reasons": [
                    str(reason)[:128] for reason in item.get("reasons", [])[:8]
                ],
            }
            for item in candidates[:16]
        ]
        result = await self._invoke(
            BusinessTargetSelection,
            "business_target.md",
            {
                "symptom": _bounded_business_symptom(symptom),
                "candidate_businesses": bounded,
            },
        )
        selection = BusinessTargetSelection.model_validate(result)
        allowed = {item["family"] for item in bounded}
        if selection.selected_family not in allowed:
            return BusinessTargetSelection(
                confidence=0,
                ambiguous=True,
                matched_subject=selection.matched_subject,
            )
        return selection

    async def verify(
        self,
        context: DiagnosisContext,
        hypotheses: HypothesisBatch,
        evidence: list[EvidenceResponse],
    ) -> VerificationResult:
        result = await self._invoke(
            VerificationResult,
            "verification.md",
            {
                "diagnosis_context": context.model_dump(mode="json"),
                "hypotheses": hypotheses.model_dump(mode="json"),
                "additional_evidence": bounded_evidence(evidence),
            },
        )
        return VerificationResult.model_validate(result)

    async def augment_hypotheses(
        self,
        context: DiagnosisContext,
        hypotheses: HypothesisBatch,
        knowledge: KnowledgeBundle,
    ) -> KnowledgeAugmentation:
        result = await self._invoke(
            KnowledgeAugmentation,
            "knowledge_augmentation.md",
            {
                "diagnosis_context": context.model_dump(mode="json"),
                "base_hypotheses": hypotheses.model_dump(mode="json"),
                "retrieved_knowledge": knowledge.model_dump(mode="json"),
            },
        )
        return KnowledgeAugmentation.model_validate(result)

    async def answer_question(self, context: ChatModelContext) -> ChatAnswer:
        result = await self._invoke(
            ChatAnswer,
            "chat_answer.md",
            {"chat_context": context.model_dump(mode="json")},
        )
        return ChatAnswer.model_validate(result)

    async def general_chat(
        self,
        user_text: str,
        conversation_summary: str = "",
        turns: list[Any] | None = None,
        knowledge: KnowledgeBundle | None = None,
    ) -> GeneralChatAnswer:
        """Answer ordinary conversation without requiring an active analysis."""
        payload = {
            "user_message": user_text,
            "conversation_summary": conversation_summary,
            "conversation_turns": [
                turn.model_dump(mode="json") if hasattr(turn, "model_dump") else turn
                for turn in (turns or [])[-8:]
            ],
            "retrieved_knowledge": (
                knowledge.model_dump(mode="json") if knowledge else None
            ),
        }
        result = await self._invoke(GeneralChatAnswer, "general_chat.md", payload)
        return GeneralChatAnswer.model_validate(result)

    async def verify_chat_answer(
        self,
        context: ChatModelContext,
        answer: ChatAnswer,
        evidence: list[EvidenceResponse],
    ) -> ChatAnswer:
        result = await self._invoke(
            ChatAnswer,
            "chat_verify.md",
            {
                "chat_context": context.model_dump(mode="json"),
                "draft_answer": answer.model_dump(mode="json"),
                "additional_evidence": bounded_evidence(evidence),
            },
        )
        return ChatAnswer.model_validate(result)
