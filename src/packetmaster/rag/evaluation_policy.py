"""Versioned, fingerprinted release policy for RAG evaluation."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field, model_validator

from packetmaster.rag.contracts import Identifier, RagContract
from packetmaster.rag.evaluation_contracts import canonical_fingerprint


class MetricThreshold(RagContract):
    minimum: float | None = None
    exclusive_minimum: float | None = None
    maximum: float | None = None
    maximum_regression: float | None = Field(default=None, ge=0)
    blocking: bool = True

    @model_validator(mode="after")
    def validate_bounds(self) -> MetricThreshold:
        if all(
            value is None
            for value in (
                self.minimum,
                self.exclusive_minimum,
                self.maximum,
                self.maximum_regression,
            )
        ):
            raise ValueError("metric threshold requires at least one bound")
        lower = self.minimum
        if lower is None:
            lower = self.exclusive_minimum
        if lower is not None and self.maximum is not None and lower > self.maximum:
            raise ValueError("metric minimum cannot exceed maximum")
        return self


class JudgePolicy(RagContract):
    enabled: bool = False
    calibrated: bool = False
    blocking: bool = False
    minimum_scores: dict[Identifier, int] = Field(
        default_factory=dict, max_length=16
    )
    fail_on_severe_violation: bool = True

    @model_validator(mode="after")
    def validate_judge_policy(self) -> JudgePolicy:
        if any(not 0 <= score <= 4 for score in self.minimum_scores.values()):
            raise ValueError("judge score thresholds must be between 0 and 4")
        if self.blocking and (not self.enabled or not self.calibrated):
            raise ValueError("blocking judge policy must be enabled and calibrated")
        return self


class EvaluationPolicy(RagContract):
    schema_version: int = Field(default=1, ge=1)
    policy_id: Identifier
    version: int = Field(ge=1)
    description: str = Field(min_length=1, max_length=1_000)
    minimum_formal_cases: int = Field(ge=1, le=10_000)
    metrics: dict[Identifier, MetricThreshold] = Field(min_length=1, max_length=64)
    critical_metrics: dict[Identifier, MetricThreshold] = Field(
        default_factory=dict, max_length=32
    )
    judge: JudgePolicy = Field(default_factory=JudgePolicy)
    require_clean_revision: bool = True
    require_human_approval: bool = True


def load_evaluation_policy(path: Path) -> EvaluationPolicy:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("evaluation policy must be a JSON object")
    return EvaluationPolicy.model_validate(value)


def policy_fingerprint(policy: EvaluationPolicy) -> str:
    return canonical_fingerprint(policy)
