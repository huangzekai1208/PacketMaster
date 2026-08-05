from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import SecretStr

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.database import KnowledgeDatabase
from packetmaster.rag.evaluation_contracts import EvaluationDatasetV2
from packetmaster.rag.evaluation_identity import build_evaluation_snapshot
from packetmaster.rag.evaluation_policy import EvaluationPolicy

_PROMPTS = (
    "chat_answer.md",
    "chat_verify.md",
    "general_chat.md",
    "knowledge_augmentation.md",
)


def _database(tmp_path: Path) -> KnowledgeDatabase:
    database = KnowledgeDatabase(tmp_path / "knowledge.sqlite")
    database.initialize()
    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO knowledge_documents (
                knowledge_id, title, knowledge_type, language, authority,
                status, summary, applicability_json, current_version_id,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "knowledge.tcp",
                "TCP",
                "runbook",
                "zh-CN",
                "high",
                "approved",
                "TCP knowledge",
                "{}",
                "knowledge.tcp:v1",
                "2026-07-31T00:00:00+00:00",
                "2026-07-31T00:00:00+00:00",
            ),
        )
        connection.execute(
            """
            INSERT INTO knowledge_versions (
                version_id, knowledge_id, version_number, source_name,
                source_location, content_hash, status, created_at,
                approved_at, approved_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "knowledge.tcp:v1",
                "knowledge.tcp",
                1,
                "test",
                "section",
                "a" * 64,
                "approved",
                "2026-07-31T00:00:00+00:00",
                "2026-07-31T00:00:00+00:00",
                "reviewer",
            ),
        )
        connection.execute(
            """
            INSERT INTO knowledge_chunks (
                chunk_id, knowledge_id, version_id, chunk_index,
                heading_path_json, source_location, content, content_hash,
                status, media_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "knowledge.tcp:v1:chunk-0",
                "knowledge.tcp",
                "knowledge.tcp:v1",
                0,
                '["TCP"]',
                "section / TCP",
                "Wireshark 显示相对序列号。",
                "b" * 64,
                "approved",
                "[]",
            ),
        )
        connection.execute(
            """
            INSERT INTO knowledge_embeddings (
                chunk_id, model_name, dimension, vector, content_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "knowledge.tcp:v1:chunk-0",
                "fake-embedding",
                2,
                b"12345678",
                "b" * 64,
                "2026-07-31T00:00:00+00:00",
            ),
        )
        connection.execute(
            "INSERT INTO knowledge_chunks_fts VALUES (?, ?, ?, ?)",
            (
                "knowledge.tcp:v1:chunk-0",
                "TCP",
                "TCP",
                "Wireshark 显示相对序列号。",
            ),
        )
    return database


def _dataset(*, chunk_id: str = "knowledge.tcp:v1:chunk-0") -> EvaluationDatasetV2:
    return EvaluationDatasetV2.model_validate(
        {
            "schema_version": 2,
            "manifest": {
                "dataset_id": "rag.tcp.v2",
                "version": 1,
                "language": "zh-CN",
                "domain": "TCP",
                "created_at": "2026-07-31T00:00:00Z",
                "created_by": "annotator",
                "reviewed_by": ["reviewer"],
                "change_summary": "initial",
                "annotation_guideline_version": "guideline-v2",
                "policy_id": "rag-production",
                "allowed_knowledge_ids": ["knowledge.tcp"],
            },
            "cases": [
                {
                    "case_id": "case-1",
                    "query": {"query_id": "case-1", "query_text": "seq=0"},
                    "relevant_chunk_ids": [chunk_id],
                    "relevance_grades": {chunk_id: 3},
                    "critical": True,
                    "question_type": "protocol",
                    "expected_facts": ["相对序列号"],
                    "applicable_chunk_ids": [chunk_id],
                    "annotated_by": "annotator",
                    "reviewed_by": "reviewer",
                    "label_change_reason": "initial",
                }
            ],
        }
    )


def _policy() -> EvaluationPolicy:
    return EvaluationPolicy(
        policy_id="rag-production",
        version=1,
        description="test policy",
        minimum_formal_cases=1,
        metrics={"recall-at-5": {"minimum": 0.85}},
    )


def _settings(**changes: object) -> Settings:
    values: dict[str, object] = {
        "embedding_model": "fake-embedding",
        "embedding_dimension": 2,
        "embedding_api_key": SecretStr("sk-test-not-serialized"),
        "embedding_base_url": "https://embedding.example/v1",
        "reranker_enabled": False,
        "model_base_url": "https://model.example/v1",
        "model_name": "answer-model-v1",
    }
    values.update(changes)
    return Settings(**values)


def _prompt_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "prompts"
    directory.mkdir()
    for name in _PROMPTS:
        directory.joinpath(name).write_text(f"prompt {name}\n", encoding="utf-8")
    return directory


def test_snapshot_is_complete_stable_and_excludes_secret(tmp_path: Path) -> None:
    database = _database(tmp_path)
    prompts = _prompt_dir(tmp_path)
    snapshot = build_evaluation_snapshot(
        database=database,
        settings=_settings(),
        dataset=_dataset(),
        policy=_policy(),
        prompt_dir=prompts,
        code_revision="6a2287e",
        dirty=False,
    )
    repeated = build_evaluation_snapshot(
        database=database,
        settings=_settings(),
        dataset=_dataset(),
        policy=_policy(),
        prompt_dir=prompts,
        code_revision="6a2287e",
        dirty=False,
    )

    assert snapshot == repeated
    assert snapshot.approved_chunk_count == 1
    assert snapshot.indexed_chunk_count == 1
    assert snapshot.fts_chunk_count == 1
    assert "sk-test" not in snapshot.model_dump_json()


def test_semantic_configuration_and_prompt_changes_alter_identity(
    tmp_path: Path,
) -> None:
    database = _database(tmp_path)
    prompts = _prompt_dir(tmp_path)

    baseline = build_evaluation_snapshot(
        database=database,
        settings=_settings(),
        dataset=_dataset(),
        policy=_policy(),
        prompt_dir=prompts,
        code_revision="6a2287e",
        dirty=False,
    )
    retrieval_change = build_evaluation_snapshot(
        database=database,
        settings=_settings(rag_final_top_k=5),
        dataset=_dataset(),
        policy=_policy(),
        prompt_dir=prompts,
        code_revision="6a2287e",
        dirty=False,
    )
    prompts.joinpath("chat_answer.md").write_text("changed\n", encoding="utf-8")
    prompt_change = build_evaluation_snapshot(
        database=database,
        settings=_settings(),
        dataset=_dataset(),
        policy=_policy(),
        prompt_dir=prompts,
        code_revision="6a2287e",
        dirty=False,
    )

    assert (
        baseline.identity.retrieval_fingerprint
        != retrieval_change.identity.retrieval_fingerprint
    )
    assert (
        baseline.identity.generation_fingerprint
        != prompt_change.identity.generation_fingerprint
    )
    assert (
        baseline.identity.corpus_fingerprint
        == prompt_change.identity.corpus_fingerprint
    )


def test_snapshot_rejects_missing_label_embedding_and_fts(tmp_path: Path) -> None:
    database = _database(tmp_path)
    prompts = _prompt_dir(tmp_path)
    arguments = {
        "database": database,
        "settings": _settings(),
        "policy": _policy(),
        "prompt_dir": prompts,
        "code_revision": "6a2287e",
        "dirty": False,
    }

    with pytest.raises(AppError) as missing_label:
        build_evaluation_snapshot(
            **arguments,
            dataset=_dataset(chunk_id="knowledge.tcp:v1:chunk-99"),
        )
    assert missing_label.value.code == "EVALUATION_CORPUS_MISMATCH"

    with database.transaction(immediate=True) as connection:
        connection.execute("DELETE FROM knowledge_embeddings")
    with pytest.raises(AppError) as missing_embedding:
        build_evaluation_snapshot(**arguments, dataset=_dataset())
    assert missing_embedding.value.code == "EVALUATION_INDEX_INCOMPLETE"

    with database.transaction(immediate=True) as connection:
        connection.execute(
            """
            INSERT INTO knowledge_embeddings (
                chunk_id, model_name, dimension, vector, content_hash, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                "knowledge.tcp:v1:chunk-0",
                "fake-embedding",
                2,
                b"12345678",
                "b" * 64,
                "2026-07-31T00:00:00+00:00",
            ),
        )
        connection.execute("DELETE FROM knowledge_chunks_fts")
    with pytest.raises(AppError) as missing_fts:
        build_evaluation_snapshot(**arguments, dataset=_dataset())
    assert missing_fts.value.code == "EVALUATION_INDEX_INCOMPLETE"
