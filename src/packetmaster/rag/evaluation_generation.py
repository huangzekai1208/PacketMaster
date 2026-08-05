"""Real answer generation and deterministic checks for RAG evaluation."""

from __future__ import annotations

import hashlib
import re
import time
from contextlib import nullcontext
from dataclasses import dataclass
from typing import Protocol

from packetmaster.domain import GeneralChatAnswer
from packetmaster.errors import AppError
from packetmaster.llm_observability import (
    LLMCallRecord,
    LLMObservationCollector,
)
from packetmaster.rag.contracts import KnowledgeBundle
from packetmaster.rag.evaluation_contracts import (
    EvaluationCaseV2,
    EvaluationGenerationResult,
)
from packetmaster.rag.evaluation_store import EvaluationArtifactStore

_SECRET = re.compile(
    r"(?i)(?:sk-[a-z0-9._-]{12,}|(?:api[_-]?key|authorization|token|password)"
    r"\s*[:=]\s*\S+)"
)
_ABSOLUTE_PATH = re.compile(
    r"(?i)(?<!\w)(?:[a-z]:[\\/]|/users/|/home/|/private/|/tmp/|/var/|~[/\\])"
    r"[^\n，。；,;!?]*"
)
_RAG_CLAIM = re.compile(
    r"(?:RAG\s*已使用|已(?:查阅|检索)(?:了)?知识库|根据(?:检索到的)?知识库)",
    re.IGNORECASE,
)
_NORMALIZE = re.compile(r"[\W_]+", re.UNICODE)


class GeneralChatGenerator(Protocol):
    """The production and evaluation shared answer-generation boundary."""

    async def general_chat(
        self,
        user_text: str,
        conversation_summary: str = "",
        turns: list[object] | None = None,
        knowledge: KnowledgeBundle | None = None,
    ) -> GeneralChatAnswer: ...


class GenerationResultStore(Protocol):
    def save_generation_result(self, result: EvaluationGenerationResult) -> None: ...


@dataclass(frozen=True)
class GenerationUsage:
    input_tokens: int | None = None
    output_tokens: int | None = None
    retry_count: int = 0


class EvaluationGenerationIncomplete(AppError):
    def __init__(self, *, case_id: str, cause: Exception) -> None:
        code = cause.code if isinstance(cause, AppError) else cause.__class__.__name__
        super().__init__(
            code="EVALUATION_GENERATION_INCOMPLETE",
            message="RAG answer generation did not complete",
            recoverable=True,
            suggested_action="Restore the answer model and resume this evaluation run.",
            details={"case_id": case_id, "cause_code": code},
        )


def _redact(value: str) -> str:
    return _ABSOLUTE_PATH.sub(
        "<本地路径已隐藏>", _SECRET.sub("<敏感信息已隐藏>", value)
    )


def _normalized(value: str) -> str:
    return _NORMALIZE.sub("", value).casefold()


def _covered(answer: str, expected: str) -> bool:
    normalized_expected = _normalized(expected)
    return bool(normalized_expected) and normalized_expected in _normalized(answer)


class EvaluationGenerationRunner:
    def __init__(
        self,
        model: GeneralChatGenerator,
        *,
        generation_fingerprint: str,
        artifact_store: EvaluationArtifactStore | None = None,
        result_store: GenerationResultStore | None = None,
        observer: LLMObservationCollector | None = None,
    ) -> None:
        if re.fullmatch(r"[a-f0-9]{64}", generation_fingerprint) is None:
            raise ValueError("generation fingerprint must be a SHA-256 value")
        self.model = model
        self.generation_fingerprint = generation_fingerprint
        self.artifact_store = artifact_store
        self.result_store = result_store
        model_observer = getattr(model, "observer", None)
        self.observer = observer or (
            model_observer
            if isinstance(model_observer, LLMObservationCollector)
            else None
        )

    async def evaluate_case(
        self,
        run_id: str,
        case: EvaluationCaseV2,
        bundle: KnowledgeBundle,
        *,
        usage: GenerationUsage | None = None,
    ) -> EvaluationGenerationResult:
        started = time.perf_counter()
        observed_calls: list[LLMCallRecord] = []
        trace_hash = hashlib.sha256(f"{run_id}:{case.case_id}".encode()).hexdigest()
        scope = (
            self.observer.scope(f"eval-{trace_hash[:32]}")
            if self.observer is not None
            else nullcontext(observed_calls)
        )
        try:
            with scope as observed_calls:
                structured = await self.model.general_chat(
                    case.query.query_text,
                    "",
                    [],
                    knowledge=bundle if bundle.results else None,
                )
                answer = GeneralChatAnswer.model_validate(structured)
        except Exception as exc:
            raise EvaluationGenerationIncomplete(
                case_id=case.case_id, cause=exc
            ) from exc
        latency = time.perf_counter() - started

        safe_answer = _redact(answer.answer)
        safe_limitations = [_redact(item) for item in answer.limitations]
        safe_suggestions = [_redact(item) for item in answer.follow_up_suggestions]
        citations = list(answer.knowledge_citations)
        context_ids = [item.chunk_id for item in bundle.results]
        context = set(context_ids)
        approved = set(case.approved_citation_chunk_ids)
        facts = [item for item in case.expected_facts if _covered(safe_answer, item)]
        causes = [item for item in case.expected_causes if _covered(safe_answer, item)]
        forbidden_hits = [
            item for item in case.forbidden_conclusions if _covered(safe_answer, item)
        ]
        has_context = bool(context_ids)
        claims_rag = bool(_RAG_CLAIM.search(safe_answer))
        checks = {
            "citations_exist": bool(citations) if has_context else not citations,
            "citations_in_context": set(citations) <= context,
            "citations_human_approved": set(citations) <= approved,
            "expected_facts_covered": len(facts) == len(case.expected_facts),
            "expected_causes_covered": len(causes) == len(case.expected_causes),
            "forbidden_conclusions_absent": not forbidden_hits,
            "required_structure_complete": (
                isinstance(answer.knowledge_citations, list)
                and isinstance(answer.limitations, list)
                and isinstance(answer.follow_up_suggestions, list)
            ),
            "rag_status_consistent": has_context or not claims_rag,
        }
        degraded = bool(bundle.warnings) or bundle.truncated
        warnings = [_redact(item) for item in bundle.warnings]
        if bundle.truncated:
            warnings.append("RAG_CONTEXT_TRUNCATED")
        observed_call = observed_calls[-1] if observed_calls else None
        if usage is None and observed_call is not None:
            usage = GenerationUsage(
                input_tokens=observed_call.usage.input_tokens,
                output_tokens=observed_call.usage.output_tokens,
                retry_count=observed_call.retry_count,
            )
        if usage is None:
            usage = GenerationUsage()
        if usage.input_tokens is None or usage.output_tokens is None:
            warnings.append("MODEL_USAGE_UNAVAILABLE")

        artifact = None
        artifact_payload = {
            "schema_version": 1,
            "case_id": case.case_id,
            "context": [
                {
                    "chunk_id": item.chunk_id,
                    "knowledge_id": item.knowledge_id,
                    "version_id": item.version_id,
                    "title": _redact(item.title),
                    "content_sha256": hashlib.sha256(
                        item.content.encode("utf-8")
                    ).hexdigest(),
                }
                for item in bundle.results
            ],
            "structured_answer": {
                "answer": safe_answer,
                "knowledge_citations": citations,
                "limitations": safe_limitations,
                "follow_up_suggestions": safe_suggestions,
            },
            "deterministic_checks": checks,
            "generation_fingerprint": self.generation_fingerprint,
            "llm_call": (
                observed_call.model_dump(mode="json")
                if observed_call is not None
                else None
            ),
        }
        if self.artifact_store is not None:
            artifact = self.artifact_store.save_json(
                run_id=run_id,
                case_id=case.case_id,
                kind="generation",
                value=artifact_payload,
            )

        result = EvaluationGenerationResult(
            run_id=run_id,
            case_id=case.case_id,
            answer=safe_answer,
            citation_chunk_ids=citations,
            context_chunk_ids=context_ids,
            deterministic_checks=checks,
            extracted_facts=facts,
            extracted_causes=causes,
            latency_seconds=latency,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            retry_count=usage.retry_count,
            generation_fingerprint=self.generation_fingerprint,
            degraded=degraded,
            warnings=warnings,
            artifact=artifact,
        )
        if self.result_store is not None:
            self.result_store.save_generation_result(result)
        return result
