"""OpenAI-compatible structured diagnosis without exposing hidden reasoning."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ValidationError

from packetmaster.config import Settings
from packetmaster.context import DiagnosisContext, sanitize_for_model
from packetmaster.domain import HypothesisBatch, VerificationResult
from packetmaster.errors import AppError

_PROMPT_ROOT = Path(__file__).resolve().parent / "prompts"


class DiagnosisModel:
    def __init__(
        self, client: Any | None = None, settings: Settings | None = None
    ) -> None:
        self.settings = settings or Settings.load()
        self._client = client

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
        api_key = (
            self.settings.model_api_key.get_secret_value()
            if self.settings.model_api_key is not None
            else None
        )
        self._client = ChatOpenAI(
            model=self.settings.model_name,
            base_url=self.settings.model_base_url,
            api_key=api_key,
            timeout=self.settings.model_timeout_seconds,
        )
        return self._client

    @staticmethod
    def _prompt(name: str) -> str:
        try:
            return (_PROMPT_ROOT / name).read_text(encoding="utf-8")
        except OSError as exc:
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
        messages: list[dict[str, str]] = [
            {"role": "system", "content": self._prompt(prompt_name)},
            {
                "role": "user",
                "content": json.dumps(
                    sanitize_for_model(payload),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            },
        ]
        try:
            structured = client.with_structured_output(schema)
            result = await structured.ainvoke(messages)
            return (
                result
                if isinstance(result, schema)
                else schema.model_validate(result)
            )
        except TimeoutError as exc:
            raise AppError(
                code="MODEL_TIMEOUT",
                message="Diagnosis model timed out",
                recoverable=True,
                suggested_action="Retry or increase the model timeout.",
            ) from exc
        except ValidationError as exc:
            raise AppError(
                code="INVALID_MODEL_OUTPUT",
                message="Diagnosis model returned invalid structured output",
                recoverable=True,
                suggested_action="Retry with the PacketMaster structured schema.",
                details={"validation_count": len(exc.errors(include_input=False))},
            ) from exc
        except AppError:
            raise
        except Exception as exc:
            raise AppError(
                code="MODEL_CALL_FAILED",
                message="Diagnosis model call failed",
                recoverable=True,
                suggested_action="Check model configuration and retry.",
                details={"exception_type": exc.__class__.__name__},
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

    async def verify(
        self,
        context: DiagnosisContext,
        hypotheses: HypothesisBatch,
        evidence: list[Any],
    ) -> VerificationResult:
        result = await self._invoke(
            VerificationResult,
            "verification.md",
            {
                "diagnosis_context": context.model_dump(mode="json"),
                "hypotheses": hypotheses.model_dump(mode="json"),
                "additional_evidence": sanitize_for_model(evidence),
            },
        )
        return VerificationResult.model_validate(result)
