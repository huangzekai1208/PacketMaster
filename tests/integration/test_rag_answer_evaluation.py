from __future__ import annotations

import asyncio

import pytest

from packetmaster.domain import GeneralChatAnswer
from packetmaster.model import DiagnosisModel
from packetmaster.rag.contracts import KnowledgeBundle, RetrievalCandidate
from packetmaster.rag.evaluation_contracts import EvaluationCaseV2
from packetmaster.rag.evaluation_generation import (
    EvaluationGenerationIncomplete,
    EvaluationGenerationRunner,
)


class _Structured:
    async def ainvoke(self, messages):
        payload = messages[-1]["content"]
        assert "knowledge:v1:chunk-1" in payload
        assert "retrieved_knowledge" in payload
        return GeneralChatAnswer(
            answer="Wireshark 默认显示相对序列号。",
            knowledge_citations=["knowledge:v1:chunk-1"],
        )


class _Client:
    def with_structured_output(self, schema, method):
        assert schema is GeneralChatAnswer
        return _Structured()


class _InvalidStructured:
    async def ainvoke(self, messages):
        return {"answer": ""}


class _InvalidClient:
    def with_structured_output(self, schema, method):
        return _InvalidStructured()


def test_evaluation_reuses_diagnosis_model_general_chat_prompt_path() -> None:
    case = EvaluationCaseV2(
        case_id="case-1",
        query={"query_id": "case-1", "query_text": "为什么 seq 是 0？"},
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        relevance_grades={"knowledge:v1:chunk-1": 3},
        critical=True,
        question_type="tcp",
        expected_facts=["Wireshark 默认显示相对序列号"],
        applicable_chunk_ids=["knowledge:v1:chunk-1"],
        approved_citation_chunk_ids=["knowledge:v1:chunk-1"],
        annotated_by="annotator",
        reviewed_by="reviewer",
        label_change_reason="initial",
    )
    candidate = RetrievalCandidate(
        knowledge_id="knowledge",
        version_id="knowledge:v1",
        chunk_id="knowledge:v1:chunk-1",
        title="TCP 序列号",
        knowledge_type="runbook",
        authority="high",
        source_name="test",
        content="Wireshark 默认显示相对序列号。",
    )
    bundle = KnowledgeBundle(
        query_id="case-1",
        results=[candidate],
        total_content_bytes=len(candidate.content.encode("utf-8")),
    )
    model = DiagnosisModel(client=_Client())

    result = asyncio.run(
        EvaluationGenerationRunner(
            model, generation_fingerprint="a" * 64
        ).evaluate_case("run-1", case, bundle)
    )

    assert result.answer == "Wireshark 默认显示相对序列号。"
    assert result.deterministic_checks["citations_in_context"] is True


def test_invalid_model_schema_makes_generation_incomplete() -> None:
    case = EvaluationCaseV2(
        case_id="case-1",
        query={"query_id": "case-1", "query_text": "为什么 seq 是 0？"},
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        relevance_grades={"knowledge:v1:chunk-1": 3},
        critical=True,
        question_type="tcp",
        expected_facts=["相对序列号"],
        annotated_by="annotator",
        reviewed_by="reviewer",
        label_change_reason="initial",
    )
    model = DiagnosisModel(client=_InvalidClient())

    with pytest.raises(EvaluationGenerationIncomplete) as raised:
        asyncio.run(
            EvaluationGenerationRunner(
                model, generation_fingerprint="a" * 64
            ).evaluate_case("run-1", case, KnowledgeBundle(query_id="case-1"))
        )

    assert raised.value.details["cause_code"] == "INVALID_MODEL_OUTPUT"
