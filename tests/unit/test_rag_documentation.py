from __future__ import annotations

import json
from pathlib import Path

from packetmaster.rag.contracts import CaseProfile
from packetmaster.rag.evaluation import load_evaluation_cases


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

    assert CaseProfile.model_validate(case).direction.value == "download"
    assert len(evaluations) == 1
    assert evaluations[0].case_id == "eval.zero-window.001"


def test_rag_operations_document_keeps_active_gate_and_command_compatibility() -> None:
    document = _root().joinpath("docs/rag-operations.md").read_text(
        encoding="utf-8"
    )

    assert "50 条" in document
    assert "pkm knowledge evaluate" in document
    assert "packetmaster" in document
    assert "Qdrant Server" in document
