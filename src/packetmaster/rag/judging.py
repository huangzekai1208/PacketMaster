"""Restricted, versioned LLM Judge provider for RAG answer evaluation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from datetime import datetime
from importlib.resources import files
from pathlib import Path
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from uuid import uuid4

from pydantic import Field, model_validator

from packetmaster.errors import AppError
from packetmaster.llm_observability import (
    LLMCallObserver,
    LLMCallRecord,
    LLMCallStatus,
    LLMObservationCollector,
    LLMTokenUsage,
    NullLLMCallObserver,
    token_usage_from_mapping,
    utc_now,
)
from packetmaster.rag.base import JudgeProvider
from packetmaster.rag.contracts import Identifier, RagContract
from packetmaster.rag.evaluation_contracts import JudgeResult, JudgeScores

JudgeViolation = Literal[
    "UNSUPPORTED_CLAIM",
    "INVENTED_CITATION",
    "CONTRADICTION",
    "MISAPPLIED_KNOWLEDGE",
    "FORBIDDEN_CONCLUSION",
    "MISSING_CRITICAL_FACT",
]
_SEVERE = {
    "UNSUPPORTED_CLAIM",
    "INVENTED_CITATION",
    "CONTRADICTION",
    "FORBIDDEN_CONCLUSION",
}
_SENSITIVE = re.compile(
    r"(?i)(?:sk-[a-z0-9._-]{12,}|(?:api[_-]?key|authorization|token|password)"
    r"\s*[:=]\s*\S+|[a-z]:[\\/]|/(?:users|home|private|tmp|var)/)"
)


class JudgeContext(RagContract):
    chunk_id: Identifier
    content: str = Field(min_length=1, max_length=8_000)


class JudgeRequest(RagContract):
    case_id: Identifier
    question: str = Field(min_length=1, max_length=4_000)
    answer: str = Field(min_length=1, max_length=32_000)
    citation_chunk_ids: list[Identifier] = Field(default_factory=list, max_length=32)
    expected_facts: list[str] = Field(default_factory=list, max_length=32)
    expected_causes: list[str] = Field(default_factory=list, max_length=32)
    forbidden_conclusions: list[str] = Field(default_factory=list, max_length=32)
    context: list[JudgeContext] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def reject_sensitive_external_data(self) -> JudgeRequest:
        if _SENSITIVE.search(self.model_dump_json()):
            raise ValueError("judge request contains a secret or local path")
        return self


class JudgeAssessment(RagContract):
    scores: JudgeScores
    passed: bool
    uncertain: bool = False
    violations: list[JudgeViolation] = Field(default_factory=list, max_length=32)
    reason: str = Field(min_length=1, max_length=2_000)
    evidence_chunk_ids: list[Identifier] = Field(default_factory=list, max_length=32)

    @model_validator(mode="after")
    def enforce_severe_violations(self) -> JudgeAssessment:
        if self.passed and _SEVERE.intersection(self.violations):
            raise ValueError("severe violations cannot pass")
        return self


class JudgeCalibrationLabel(RagContract):
    case_id: Identifier
    reviewer_ids: list[str] = Field(min_length=2, max_length=2)
    expected_passed: bool
    severe_violations: list[JudgeViolation] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def require_independent_reviewers(self) -> JudgeCalibrationLabel:
        if len(set(self.reviewer_ids)) != 2:
            raise ValueError("calibration labels require two distinct reviewers")
        return self


class JudgeCalibrationReport(RagContract):
    case_count: int = Field(ge=1)
    pass_agreement: float = Field(ge=0, le=1)
    severe_violation_agreement: float = Field(ge=0, le=1)
    calibrated: bool


class _RetryableJudgeError(Exception):
    pass


def judge_fingerprint(
    *,
    model_name: str,
    model_revision: str,
    rubric: str,
    prompt: str,
    temperature: float,
    max_tokens: int,
) -> str:
    payload = json.dumps(
        {
            "model": model_name,
            "revision": model_revision,
            "rubric_sha256": hashlib.sha256(rubric.encode()).hexdigest(),
            "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest(),
            "schema": JudgeAssessment.model_json_schema(),
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


class OpenAICompatibleJudge:
    def __init__(
        self,
        *,
        model_name: str,
        model_revision: str,
        api_key: str | None,
        base_url: str,
        timeout_seconds: float,
        max_retries: int,
        temperature: float,
        max_tokens: int,
        rubric: str,
        prompt: str,
        observer: LLMCallObserver | None = None,
    ) -> None:
        if not api_key:
            raise AppError(
                code="JUDGE_AUTH_MISSING",
                message="Judge API Key 未配置",
                recoverable=True,
                suggested_action="请单独配置 JUDGE_API_KEY 后重试。",
            )
        if not model_revision:
            raise AppError(
                code="JUDGE_REVISION_REQUIRED",
                message="正式 Judge 必须锁定模型 revision",
                recoverable=True,
                suggested_action="请配置 JUDGE_MODEL_REVISION 后重试。",
            )
        self._model_name = model_name
        self._model_revision = model_revision
        self._api_key = api_key
        self._endpoint = f"{base_url.rstrip('/')}/chat/completions"
        self._timeout_seconds = timeout_seconds
        self._max_retries = max_retries
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._rubric = rubric
        self._prompt = prompt
        self.observer = observer or NullLLMCallObserver()

    @property
    def model_name(self) -> str:
        return self._model_name

    @property
    def model_revision(self) -> str:
        return self._model_revision

    @property
    def fingerprint(self) -> str:
        return judge_fingerprint(
            model_name=self.model_name,
            model_revision=self.model_revision,
            rubric=self._rubric,
            prompt=self._prompt,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )

    def _request(
        self, request_value: JudgeRequest
    ) -> tuple[JudgeAssessment, LLMTokenUsage]:
        untrusted = request_value.model_dump_json()
        messages = [
            {
                "role": "system",
                "content": f"{self._prompt}\n\nFIXED RUBRIC:\n{self._rubric}",
            },
            {
                "role": "user",
                "content": f"<UNTRUSTED_EVALUATION_DATA>{untrusted}"
                "</UNTRUSTED_EVALUATION_DATA>",
            },
        ]
        body = json.dumps(
            {
                "model": self.model_revision,
                "messages": messages,
                "temperature": self._temperature,
                "max_tokens": self._max_tokens,
                "response_format": {"type": "json_object"},
            },
            ensure_ascii=False,
        ).encode()
        http_request = Request(
            self._endpoint,
            data=body,
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urlopen(http_request, timeout=self._timeout_seconds) as response:
                response_body = json.loads(response.read().decode())
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise AppError(
                    code="JUDGE_AUTH_FAILED",
                    message="Judge Provider 鉴权失败",
                    recoverable=True,
                    suggested_action="请检查独立 Judge 凭据与模型权限。",
                ) from exc
            if exc.code == 429 or exc.code >= 500:
                raise _RetryableJudgeError() from exc
            raise AppError(
                code="JUDGE_SERVICE_UNAVAILABLE",
                message="Judge Provider 请求失败",
                recoverable=True,
                suggested_action="请检查 Judge 端点和模型配置。",
            ) from exc
        except (URLError, TimeoutError, OSError) as exc:
            raise _RetryableJudgeError() from exc
        try:
            content = response_body["choices"][0]["message"]["content"]
            return (
                JudgeAssessment.model_validate_json(content),
                token_usage_from_mapping(response_body.get("usage")),
            )
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AppError(
                code="INVALID_JUDGE_OUTPUT",
                message="Judge 返回了无效结构",
                recoverable=True,
                suggested_action="请检查固定 Judge 模型与输出 Schema。",
            ) from exc

    async def judge(self, request: JudgeRequest) -> JudgeAssessment:
        started_at = utc_now()
        started = time.perf_counter()
        for attempt in range(self._max_retries + 1):
            try:
                response = await asyncio.to_thread(self._request, request)
                if isinstance(response, tuple):
                    assessment, usage = response
                else:
                    # Compatibility for test doubles and custom providers.
                    assessment, usage = response, LLMTokenUsage()
                self._record_call(
                    request,
                    started_at=started_at,
                    started=started,
                    attempts=attempt + 1,
                    status=LLMCallStatus.SUCCEEDED,
                    usage=usage,
                )
                return assessment
            except _RetryableJudgeError as exc:
                if attempt == self._max_retries:
                    error = AppError(
                        code="JUDGE_SERVICE_UNAVAILABLE",
                        message="Judge Provider 暂时不可用",
                        recoverable=True,
                        suggested_action="恢复服务后继续本次评测 Run。",
                    )
                    self._record_call(
                        request,
                        started_at=started_at,
                        started=started,
                        attempts=attempt + 1,
                        status=LLMCallStatus.FAILED,
                        usage=LLMTokenUsage(),
                        error_code=error.code,
                    )
                    raise error from exc
                await asyncio.sleep(0.25 * (2**attempt))
            except AppError as error:
                self._record_call(
                    request,
                    started_at=started_at,
                    started=started,
                    attempts=attempt + 1,
                    status=LLMCallStatus.FAILED,
                    usage=LLMTokenUsage(),
                    error_code=error.code,
                )
                raise
        raise AssertionError("unreachable")

    def _record_call(
        self,
        request: JudgeRequest,
        *,
        started_at: datetime,
        started: float,
        attempts: int,
        status: LLMCallStatus,
        usage: LLMTokenUsage,
        error_code: str | None = None,
    ) -> None:
        try:
            system_prompt = f"{self._prompt}\n\nFIXED RUBRIC:\n{self._rubric}"
            value = LLMCallRecord(
                call_id=uuid4().hex,
                operation="rag_judge",
                model_name=self.model_revision,
                prompt_name="rag-answer-v1-prompt.md",
                prompt_sha256=hashlib.sha256(system_prompt.encode()).hexdigest(),
                output_schema=JudgeAssessment.__name__,
                structured_output_method="json_object",
                started_at=started_at,
                latency_seconds=time.perf_counter() - started,
                attempt_count=attempts,
                retry_count=attempts - 1,
                input_bytes=len(request.model_dump_json().encode()),
                message_count=2,
                status=status,
                usage=usage,
                error_code=error_code,
            )
            self.observer.record(value)
        except Exception:
            return


class JudgeEvaluator:
    def __init__(
        self, provider: JudgeProvider, *, fingerprint: str, calibrated: bool
    ) -> None:
        self.provider = provider
        self.fingerprint = fingerprint
        self.calibrated = calibrated

    async def evaluate(
        self, request: JudgeRequest, *, external_judge_allowed: bool
    ) -> JudgeResult:
        if not external_judge_allowed:
            raise AppError(
                code="JUDGE_EXTERNAL_DATA_NOT_ALLOWED",
                message="数据集 manifest 不允许外部 Judge",
                recoverable=False,
                suggested_action="使用本地 Judge 或由审核人更新外发授权。",
            )
        observer = getattr(self.provider, "observer", None)
        observed_calls: list[LLMCallRecord] = []
        if isinstance(observer, LLMObservationCollector):
            trace_hash = hashlib.sha256(request.case_id.encode()).hexdigest()
            with observer.scope(f"judge-{trace_hash[:32]}") as observed_calls:
                assessment = await self.provider.judge(request)
        else:
            assessment = await self.provider.judge(request)
        observed_call = observed_calls[-1] if observed_calls else None
        context_ids = {item.chunk_id for item in request.context}
        if not set(assessment.evidence_chunk_ids) <= context_ids:
            raise AppError(
                code="INVALID_JUDGE_EVIDENCE",
                message="Judge 引用了本次上下文之外的证据",
                recoverable=True,
                suggested_action="本次 Judge 阶段应标记 incomplete 并重试。",
            )
        if context_ids and not assessment.evidence_chunk_ids:
            raise AppError(
                code="INVALID_JUDGE_EVIDENCE",
                message="Judge 理由缺少上下文证据",
                recoverable=True,
                suggested_action="本次 Judge 阶段应标记 incomplete 并重试。",
            )
        return JudgeResult(
            case_id=request.case_id,
            scores=assessment.scores,
            passed=assessment.passed,
            uncertain=assessment.uncertain,
            violations=assessment.violations,
            reason=assessment.reason,
            evidence_chunk_ids=assessment.evidence_chunk_ids,
            judge_fingerprint=self.fingerprint,
            calibrated=self.calibrated,
            latency_seconds=(
                observed_call.latency_seconds if observed_call is not None else None
            ),
            input_tokens=(
                observed_call.usage.input_tokens if observed_call is not None else None
            ),
            output_tokens=(
                observed_call.usage.output_tokens if observed_call is not None else None
            ),
            retry_count=(observed_call.retry_count if observed_call is not None else 0),
        )

    async def evaluate_repeated(
        self,
        request: JudgeRequest,
        *,
        external_judge_allowed: bool,
        repetitions: int,
    ) -> JudgeResult:
        if not 1 <= repetitions <= 5:
            raise ValueError("judge repetitions must be between 1 and 5")
        results = [
            await self.evaluate(
                request, external_judge_allowed=external_judge_allowed
            )
            for _ in range(repetitions)
        ]
        score_fields = tuple(JudgeScores.model_fields)
        scores = {
            field: min(getattr(result.scores, field) for result in results)
            for field in score_fields
        }
        violations = sorted(
            {violation for result in results for violation in result.violations}
        )
        evidence = sorted(
            {
                chunk_id
                for result in results
                for chunk_id in result.evidence_chunk_ids
            }
        )
        pass_values = {result.passed for result in results}
        return JudgeResult(
            case_id=request.case_id,
            scores=scores,
            passed=all(result.passed for result in results),
            uncertain=(
                any(result.uncertain for result in results)
                or len(pass_values) > 1
                or any(result.scores != results[0].scores for result in results[1:])
            ),
            violations=violations,
            reason=" | ".join(result.reason for result in results)[:2_000],
            evidence_chunk_ids=evidence,
            judge_fingerprint=self.fingerprint,
            calibrated=self.calibrated,
            latency_seconds=sum(result.latency_seconds or 0 for result in results),
            input_tokens=sum(result.input_tokens or 0 for result in results),
            output_tokens=sum(result.output_tokens or 0 for result in results),
            retry_count=sum(result.retry_count for result in results),
        )


def calculate_calibration(
    labels: list[JudgeCalibrationLabel], results: list[JudgeResult]
) -> JudgeCalibrationReport:
    if not labels or {item.case_id for item in labels} != {
        item.case_id for item in results
    }:
        raise ValueError("calibration labels and Judge results must match exactly")
    by_case = {item.case_id: item for item in results}
    pass_matches = 0
    severe_matches = 0
    for label in labels:
        result = by_case[label.case_id]
        pass_matches += result.passed == label.expected_passed
        expected_severe = set(label.severe_violations) & _SEVERE
        actual_severe = set(result.violations) & _SEVERE
        severe_matches += expected_severe == actual_severe
    pass_agreement = pass_matches / len(labels)
    severe_agreement = severe_matches / len(labels)
    return JudgeCalibrationReport(
        case_count=len(labels),
        pass_agreement=pass_agreement,
        severe_violation_agreement=severe_agreement,
        calibrated=(
            len(labels) >= 20
            and pass_agreement >= 0.9
            and severe_agreement >= 0.9
        ),
    )


def _judge_resource(name: str) -> str:
    project_path = Path("evaluation/judge") / name
    if project_path.exists():
        return project_path.read_text(encoding="utf-8")
    return files("packetmaster").joinpath("evaluation", "judge", name).read_text(
        encoding="utf-8"
    )


def build_judge(settings: Any) -> OpenAICompatibleJudge | None:
    if not settings.judge_enabled:
        return None
    key = settings.judge_api_key
    return OpenAICompatibleJudge(
        model_name=settings.judge_model,
        model_revision=settings.judge_model_revision or "",
        api_key=key.get_secret_value() if key else None,
        base_url=settings.judge_base_url,
        timeout_seconds=settings.judge_timeout_seconds,
        max_retries=settings.judge_max_retries,
        temperature=settings.judge_temperature,
        max_tokens=settings.judge_max_tokens,
        rubric=_judge_resource("rag-answer-v1-rubric.md"),
        prompt=_judge_resource("rag-answer-v1-prompt.md"),
    )
