from __future__ import annotations

import json
from pathlib import Path

from packetmaster.rag.contracts import CaseProfile
from packetmaster.rag.evaluation import load_evaluation_cases
from packetmaster.rag.evaluation_contracts import load_evaluation_dataset_v2
from packetmaster.rag.evaluation_policy import load_evaluation_policy


def _root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_documented_case_and_evaluation_templates_match_runtime_contracts() -> None:
    root = _root()
    case = json.loads(
        root.joinpath("docs/templates/knowledge-case.example.json").read_text(
            encoding="utf-8"
        )
    )
    evaluations = load_evaluation_cases(
        root / "docs/templates/rag-evaluation.example.json"
    )
    evaluations_v2 = load_evaluation_dataset_v2(
        root / "docs/templates/rag-evaluation-v2.example.json"
    )
    policy = load_evaluation_policy(
        root / "evaluation/policies/rag-production-v1.json"
    )

    assert CaseProfile.model_validate(case).direction.value == "download"
    assert len(evaluations) == 1
    assert evaluations[0].case_id == "eval.zero-window.001"
    assert len(evaluations_v2.cases) == 1
    assert evaluations_v2.manifest.policy_id == policy.policy_id


def test_rag_operations_document_keeps_active_gate_and_command_compatibility() -> None:
    document = _root().joinpath("docs/rag-operations.md").read_text(
        encoding="utf-8"
    )

    assert "50 条" in document
    assert "pkm knowledge evaluate" in document
    assert "packetmaster" in document
    assert "Qdrant Server" in document
