from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from packetmaster.rag.evaluation_policy import (
    EvaluationPolicy,
    JudgePolicy,
    MetricThreshold,
    load_evaluation_policy,
    policy_fingerprint,
)


def test_production_policy_loads_and_has_stable_fingerprint() -> None:
    path = Path("evaluation/policies/rag-production-v1.json")

    first = load_evaluation_policy(path)
    second = load_evaluation_policy(path)

    assert first.minimum_formal_cases == 50
    assert first.metrics["recall_at_5"].minimum == 0.85
    assert first.metrics["recall_at_20"].blocking is False
    assert first.judge.blocking is False
    assert policy_fingerprint(first) == policy_fingerprint(second)


def test_policy_fingerprint_changes_with_threshold() -> None:
    policy = load_evaluation_policy(
        Path("evaluation/policies/rag-production-v1.json")
    )
    metrics = {
        **policy.metrics,
        "recall_at_5": MetricThreshold(minimum=0.9),
    }
    changed = policy.model_copy(update={"metrics": metrics})

    assert policy_fingerprint(policy) != policy_fingerprint(changed)


def test_blocking_judge_requires_calibration() -> None:
    with pytest.raises(ValidationError, match="enabled and calibrated"):
        JudgePolicy(enabled=True, calibrated=False, blocking=True)


def test_metric_threshold_requires_a_bound() -> None:
    with pytest.raises(ValidationError, match="at least one bound"):
        MetricThreshold()

    with pytest.raises(ValidationError, match="cannot exceed"):
        MetricThreshold(minimum=1, maximum=0)


def test_policy_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        EvaluationPolicy.model_validate(
            {
                "policy_id": "p",
                "version": 1,
                "description": "test",
                "minimum_formal_cases": 1,
                "metrics": {"recall": {"minimum": 0.5}},
                "unknown": True,
            }
        )
