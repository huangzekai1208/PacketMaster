from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from packetmaster.domain import GeneralChatAnswer
from packetmaster.errors import AppError
from packetmaster.rag.contracts import KnowledgeBundle, RetrievalCandidate
from packetmaster.rag.evaluation_contracts import EvaluationCaseV2
from packetmaster.rag.evaluation_generation import (
    EvaluationGenerationIncomplete,
    EvaluationGenerationRunner,
    GenerationUsage,
)
from packetmaster.rag.evaluation_store import EvaluationArtifactStore


def _case() -> EvaluationCaseV2:
    return EvaluationCaseV2(
        case_id="case-1",
        query={"query_id": "case-1", "query_text": "为什么 TCP seq 是 0？"},
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        relevance_grades={"knowledge:v1:chunk-1": 3},
        critical=True,
        question_type="tcp",
        expected_facts=["Wireshark 默认显示相对序列号"],
        expected_causes=["真实初始序列号不是固定为 0"],
        forbidden_conclusions=["TCP 初始序列号固定为 0"],
        applicable_chunk_ids=["knowledge:v1:chunk-1"],
        approved_citation_chunk_ids=["knowledge:v1:chunk-1"],
        annotated_by="annotator",
        reviewed_by="reviewer",
        label_change_reason="initial",
    )


def _bundle(*, truncated: bool = False) -> KnowledgeBundle:
    candidate = RetrievalCandidate(
        knowledge_id="knowledge",
        version_id="knowledge:v1",
        chunk_id="knowledge:v1:chunk-1",
        title="TCP 序列号",
        knowledge_type="runbook",
        authority="high",
        source_name="test",
        content="Wireshark 默认显示相对序列号，真实初始序列号不是固定为 0。",
        rerank_score=0.9,
    )
    return KnowledgeBundle(
        query_id="case-1",
        results=[candidate],
        total_content_bytes=len(candidate.content.encode("utf-8")),
        truncated=truncated,
        warnings=["重排序降级"] if truncated else [],
    )


class _Model:
    def __init__(self, answer: GeneralChatAnswer | Exception) -> None:
        self.answer = answer
        self.calls: list[tuple[str, KnowledgeBundle | None]] = []

    async def general_chat(
        self,
        user_text: str,
        conversation_summary: str = "",
        turns: list[object] | None = None,
        knowledge: KnowledgeBundle | None = None,
    ) -> GeneralChatAnswer:
        self.calls.append((user_text, knowledge))
        if isinstance(self.answer, Exception):
            raise self.answer
        return self.answer


def _runner(model: _Model, artifact_root: Path | None = None):
    return EvaluationGenerationRunner(
        model,
        generation_fingerprint="a" * 64,
        artifact_store=(
            EvaluationArtifactStore(artifact_root) if artifact_root else None
        ),
    )


class _ResultStore:
    def __init__(self) -> None:
        self.saved = []

    def save_generation_result(self, result) -> None:
        self.saved.append(result)


def test_generation_uses_real_context_and_persists_snapshot(tmp_path: Path) -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="Wireshark 默认显示相对序列号；真实初始序列号不是固定为 0。",
            knowledge_citations=["knowledge:v1:chunk-1"],
        )
    )

    result = asyncio.run(
        _runner(model, tmp_path).evaluate_case(
            "run-1",
            _case(),
            _bundle(),
            usage=GenerationUsage(input_tokens=120, output_tokens=30, retry_count=1),
        )
    )

    assert model.calls[0][1] is not None
    assert result.context_chunk_ids == ["knowledge:v1:chunk-1"]
    assert result.citation_chunk_ids == ["knowledge:v1:chunk-1"]
    assert all(result.deterministic_checks.values())
    assert result.extracted_facts == ["Wireshark 默认显示相对序列号"]
    assert result.extracted_causes == ["真实初始序列号不是固定为 0"]
    assert result.input_tokens == 120
    assert result.retry_count == 1
    assert result.artifact is not None
    artifact = EvaluationArtifactStore(tmp_path).load_json(result.artifact)
    assert artifact["context"][0]["chunk_id"] == "knowledge:v1:chunk-1"
    assert "content_sha256" in artifact["context"][0]


def test_generation_persists_successful_result() -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="Wireshark 默认显示相对序列号；真实初始序列号不是固定为 0。",
            knowledge_citations=["knowledge:v1:chunk-1"],
        )
    )
    store = _ResultStore()
    runner = EvaluationGenerationRunner(
        model,
        generation_fingerprint="a" * 64,
        result_store=store,
    )

    result = asyncio.run(runner.evaluate_case("run-1", _case(), _bundle()))

    assert store.saved == [result]


def test_generation_detects_missing_fact_forbidden_and_bad_citation() -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="TCP 初始序列号固定为 0。",
            knowledge_citations=["other:v1:chunk-1"],
        )
    )

    result = asyncio.run(_runner(model).evaluate_case("run-1", _case(), _bundle()))

    assert result.deterministic_checks["expected_facts_covered"] is False
    assert result.deterministic_checks["expected_causes_covered"] is False
    assert result.deterministic_checks["forbidden_conclusions_absent"] is False
    assert result.deterministic_checks["citations_in_context"] is False
    assert result.deterministic_checks["citations_human_approved"] is False
    assert "MODEL_USAGE_UNAVAILABLE" in result.warnings


def test_generation_marks_context_truncation_and_degradation() -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="Wireshark 默认显示相对序列号，真实初始序列号不是固定为 0。",
            knowledge_citations=["knowledge:v1:chunk-1"],
        )
    )

    result = asyncio.run(
        _runner(model).evaluate_case("run-1", _case(), _bundle(truncated=True))
    )

    assert result.degraded is True
    assert "RAG_CONTEXT_TRUNCATED" in result.warnings
    assert "重排序降级" in result.warnings


def test_generation_rejects_false_rag_claim_without_context() -> None:
    model = _Model(GeneralChatAnswer(answer="RAG 已使用，答案如下。"))
    empty = KnowledgeBundle(query_id="case-1")

    result = asyncio.run(_runner(model).evaluate_case("run-1", _case(), empty))

    assert model.calls[0][1] is None
    assert result.deterministic_checks["rag_status_consistent"] is False
    assert result.deterministic_checks["citations_exist"] is True


def test_generation_records_model_refusal_as_quality_failure() -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="抱歉，我无法回答这个问题。",
            limitations=["当前上下文不足"],
        )
    )

    result = asyncio.run(_runner(model).evaluate_case("run-1", _case(), _bundle()))

    assert result.deterministic_checks["citations_exist"] is False
    assert result.deterministic_checks["expected_facts_covered"] is False


def test_generation_failure_is_incomplete_instead_of_quality_zero() -> None:
    model = _Model(
        AppError(
            code="MODEL_TIMEOUT",
            message="timeout",
            recoverable=True,
            suggested_action="retry",
        )
    )

    with pytest.raises(EvaluationGenerationIncomplete) as raised:
        asyncio.run(_runner(model).evaluate_case("run-1", _case(), _bundle()))

    assert raised.value.code == "EVALUATION_GENERATION_INCOMPLETE"
    assert raised.value.details["cause_code"] == "MODEL_TIMEOUT"


def test_generation_redacts_secrets_and_paths(tmp_path: Path) -> None:
    model = _Model(
        GeneralChatAnswer(
            answer="API_KEY=sk-abcdefghijklmnop 文件 /Users/demo/capture.pcap。",
            knowledge_citations=["knowledge:v1:chunk-1"],
            limitations=["查看 /tmp/private.txt"],
        )
    )

    result = asyncio.run(
        _runner(model, tmp_path).evaluate_case("run-1", _case(), _bundle())
    )

    assert "sk-" not in result.answer
    assert "/Users" not in result.answer
    assert result.artifact is not None
    artifact = EvaluationArtifactStore(tmp_path).load_json(result.artifact)
    assert "sk-" not in str(artifact)
    assert "/tmp" not in str(artifact)
