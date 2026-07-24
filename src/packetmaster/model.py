"""OpenAI-compatible structured diagnosis without exposing hidden reasoning."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any

from langchain_core.exceptions import OutputParserException
from pydantic import BaseModel, ValidationError

from packetmaster.config import Settings
from packetmaster.context import DiagnosisContext, bounded_evidence
from packetmaster.domain import (
    ChatAnswer,
    ChatModelContext,
    DiagnosisIntent,
    EvidenceResponse,
    HypothesisBatch,
    VerificationResult,
)
from packetmaster.errors import AppError
from packetmaster.intent import PathExtraction, extract_capture_paths, merge_intent


class DiagnosisModel:
    def __init__(
        self, client: Any | None = None, settings: Settings | None = None
    ) -> None:
        self.settings = settings
        self._client = client

    def _structured_output_method(self) -> str:
        settings = self.settings or Settings.load()
        configured = settings.model_structured_output_method
        if configured != "auto":
            return configured
        provider_identity = " ".join(
            value
            for value in (settings.model_name, settings.model_base_url)
            if value
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
            return files("packetmaster").joinpath("prompts", name).read_text(
                encoding="utf-8"
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
        client = self._client_or_error()
        serialized_payload = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        )
        if len(serialized_payload) > 100_000:
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
        structured = client.with_structured_output(schema, method=method)
        try:
            for attempt in range(2):
                try:
                    result = await structured.ainvoke(messages)
                    return (
                        result
                        if isinstance(result, schema)
                        else schema.model_validate(result)
                    )
                except (OutputParserException, ValidationError) as exc:
                    if attempt == 1:
                        raise AppError(
                            code="INVALID_MODEL_OUTPUT",
                            message=(
                                "Diagnosis model returned invalid structured output"
                            ),
                            recoverable=True,
                            suggested_action=(
                                "Retry with the PacketMaster structured schema."
                            ),
                            details={
                                "attempts": 2,
                                "exception_type": exc.__class__.__name__,
                            },
                        ) from exc
                    messages = [
                        *messages,
                        {
                            "role": "user",
                            "content": (
                                "上一次响应未通过结构化校验。请保持原分析结论，"
                                "仅修复输出结构，使其严格符合系统消息中的 JSON "
                                "Schema；只返回 JSON 对象，不要输出解释、Markdown "
                                "或代码块。"
                            ),
                        },
                    ]
        except TimeoutError as exc:
            raise AppError(
                code="MODEL_TIMEOUT",
                message="Diagnosis model timed out",
                recoverable=True,
                suggested_action="Retry or increase the model timeout.",
            ) from exc
        except AppError:
            raise
        except Exception as exc:
            raise AppError(
                code="MODEL_CALL_FAILED",
                message="Diagnosis model call failed",
                recoverable=True,
                suggested_action="Check model configuration and retry.",
                details={
                    "exception_type": exc.__class__.__name__,
                    "structured_output_method": method,
                },
            ) from exc

    async def generate_hypotheses(
        self, context: DiagnosisContext
    ) -> HypothesisBatch:
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

    async def answer_question(self, context: ChatModelContext) -> ChatAnswer:
        result = await self._invoke(
            ChatAnswer,
            "chat_answer.md",
            {"chat_context": context.model_dump(mode="json")},
        )
        return ChatAnswer.model_validate(result)

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
