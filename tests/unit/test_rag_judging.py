from __future__ import annotations

import asyncio

import pytest
from pydantic import ValidationError

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.judging import (
    JudgeAssessment,
    JudgeCalibrationLabel,
    JudgeEvaluator,
    JudgeRequest,
    OpenAICompatibleJudge,
    build_judge,
    calculate_calibration,
    judge_fingerprint,
)


def _request() -> JudgeRequest:
    return JudgeRequest(
        case_id="case-1",
        question="为什么 seq 是 0？",
        answer="Wireshark 显示相对序列号。",
        citation_chunk_ids=["knowledge:v1:chunk-1"],
        expected_facts=["相对序列号"],
        context=[
            {
                "chunk_id": "knowledge:v1:chunk-1",
                "content": "Wireshark 默认显示相对序列号。",
            }
        ],
    )


def _assessment(**updates) -> JudgeAssessment:
    value = {
        "scores": {
            "faithfulness": 4,
            "answer_relevance": 4,
            "citation_correctness": 4,
            "evidence_consistency": 4,
            "completeness": 3,
        },
        "passed": True,
        "reason": "回答由该切片支持。",
        "evidence_chunk_ids": ["knowledge:v1:chunk-1"],
    }
    value.update(updates)
    return JudgeAssessment.model_validate(value)


class _Provider:
    model_name = "judge-model"
    model_revision = "judge-model-20260731"

    def __init__(self, assessment: JudgeAssessment) -> None:
        self.assessment = assessment

    async def judge(self, request: JudgeRequest) -> JudgeAssessment:
        return self.assessment


def test_judge_evaluator_returns_strict_traceable_result() -> None:
    evaluator = JudgeEvaluator(
        _Provider(_assessment()), fingerprint="a" * 64, calibrated=True
    )

    result = asyncio.run(
        evaluator.evaluate(_request(), external_judge_allowed=True)
    )

    assert result.passed is True
    assert result.calibrated is True
    assert result.judge_fingerprint == "a" * 64
    assert result.evidence_chunk_ids == ["knowledge:v1:chunk-1"]


def test_external_judge_requires_manifest_permission() -> None:
    evaluator = JudgeEvaluator(
        _Provider(_assessment()), fingerprint="a" * 64, calibrated=False
    )

    with pytest.raises(AppError) as raised:
        asyncio.run(
            evaluator.evaluate(_request(), external_judge_allowed=False)
        )

    assert raised.value.code == "JUDGE_EXTERNAL_DATA_NOT_ALLOWED"


def test_judge_rejects_evidence_outside_context() -> None:
    assessment = _assessment(evidence_chunk_ids=["invented:v1:chunk-1"])
    evaluator = JudgeEvaluator(
        _Provider(assessment), fingerprint="a" * 64, calibrated=False
    )

    with pytest.raises(AppError) as raised:
        asyncio.run(evaluator.evaluate(_request(), external_judge_allowed=True))

    assert raised.value.code == "INVALID_JUDGE_EVIDENCE"


def test_judge_schema_rejects_unknown_violation_and_out_of_range_score() -> None:
    raw = _assessment().model_dump(mode="json")
    raw["violations"] = ["MADE_UP"]
    with pytest.raises(ValidationError):
        JudgeAssessment.model_validate(raw)

    raw = _assessment().model_dump(mode="json")
    raw["scores"]["faithfulness"] = 5
    with pytest.raises(ValidationError):
        JudgeAssessment.model_validate(raw)


def test_severe_violation_cannot_pass() -> None:
    with pytest.raises(ValidationError, match="severe violations cannot pass"):
        _assessment(violations=["INVENTED_CITATION"])


def test_judge_request_rejects_secrets_and_absolute_paths() -> None:
    raw = _request().model_dump(mode="json")
    raw["answer"] = "key=sk-abcdefghijklmnop"
    with pytest.raises(ValidationError, match="secret or local path"):
        JudgeRequest.model_validate(raw)

    raw = _request().model_dump(mode="json")
    raw["context"][0]["content"] = "/Users/demo/capture.pcap"
    with pytest.raises(ValidationError, match="secret or local path"):
        JudgeRequest.model_validate(raw)


def test_judge_fingerprint_changes_with_revision_rubric_and_prompt() -> None:
    base = {
        "model_name": "judge",
        "model_revision": "judge-v1",
        "rubric": "rubric-v1",
        "prompt": "prompt-v1",
        "temperature": 0.0,
        "max_tokens": 1000,
    }
    fingerprint = judge_fingerprint(**base)

    for field in ("model_revision", "rubric", "prompt", "max_tokens"):
        changed = dict(base)
        changed[field] = (
            1001 if field == "max_tokens" else f"{changed[field]}-changed"
        )
        assert judge_fingerprint(**changed) != fingerprint


def test_build_judge_uses_only_independent_key_and_requires_revision() -> None:
    disabled = Settings(
        judge_enabled=False,
        model_api_key="sk-model-abcdefghijkl",
        embedding_api_key="sk-embedding-abcdefghijkl",
    )
    assert build_judge(disabled) is None

    missing_key = disabled.model_copy(
        update={"judge_enabled": True, "judge_model_revision": "judge-v1"}
    )
    with pytest.raises(AppError) as raised:
        build_judge(missing_key)
    assert raised.value.code == "JUDGE_AUTH_MISSING"

    missing_revision = Settings(
        judge_enabled=True,
        judge_api_key="sk-judge-abcdefghijkl",
        model_api_key="sk-model-abcdefghijkl",
        embedding_api_key="sk-embedding-abcdefghijkl",
    )
    with pytest.raises(AppError) as raised:
        build_judge(missing_revision)
    assert raised.value.code == "JUDGE_REVISION_REQUIRED"


class _MalformedJudge(OpenAICompatibleJudge):
    def _request(self, request_value: JudgeRequest) -> JudgeAssessment:
        raise AppError(
            code="INVALID_JUDGE_OUTPUT",
            message="invalid",
            recoverable=True,
            suggested_action="retry",
        )


def test_invalid_judge_output_is_not_converted_to_a_score() -> None:
    provider = _MalformedJudge(
        model_name="judge",
        model_revision="judge-v1",
        api_key="secret",
        base_url="https://example.invalid/v1",
        timeout_seconds=1,
        max_retries=0,
        temperature=0,
        max_tokens=1000,
        rubric="rubric",
        prompt="prompt",
    )

    with pytest.raises(AppError) as raised:
        asyncio.run(provider.judge(_request()))

    assert raised.value.code == "INVALID_JUDGE_OUTPUT"


class _SequenceProvider(_Provider):
    def __init__(self, assessments: list[JudgeAssessment]) -> None:
        self.assessments = iter(assessments)

    async def judge(self, request: JudgeRequest) -> JudgeAssessment:
        return next(self.assessments)


def test_repeated_judge_uses_conservative_deterministic_aggregation() -> None:
    failed = _assessment(
        passed=False,
        uncertain=True,
        violations=["UNSUPPORTED_CLAIM"],
        scores={
            "faithfulness": 1,
            "answer_relevance": 4,
            "citation_correctness": 2,
            "evidence_consistency": 3,
            "completeness": 3,
        },
    )
    evaluator = JudgeEvaluator(
        _SequenceProvider([_assessment(), failed]),
        fingerprint="a" * 64,
        calibrated=False,
    )

    result = asyncio.run(
        evaluator.evaluate_repeated(
            _request(), external_judge_allowed=True, repetitions=2
        )
    )

    assert result.passed is False
    assert result.uncertain is True
    assert result.scores.faithfulness == 1
    assert result.violations == ["UNSUPPORTED_CLAIM"]


def test_calibration_requires_exact_cases_and_two_reviewers() -> None:
    label = JudgeCalibrationLabel(
        case_id="case-1",
        reviewer_ids=["reviewer-a", "reviewer-b"],
        expected_passed=True,
    )
    result = JudgeEvaluator(
        _Provider(_assessment()), fingerprint="a" * 64, calibrated=False
    )
    judged = asyncio.run(result.evaluate(_request(), external_judge_allowed=True))

    report = calculate_calibration([label], [judged])

    assert report.pass_agreement == 1
    assert report.severe_violation_agreement == 1
    assert report.calibrated is False
    with pytest.raises(ValidationError, match="distinct reviewers"):
        JudgeCalibrationLabel(
            case_id="case-1",
            reviewer_ids=["reviewer-a", "reviewer-a"],
            expected_passed=True,
        )
