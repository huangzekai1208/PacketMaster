from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pytest

import packetmaster.rag.database as database_module
from packetmaster.rag.database import KnowledgeDatabase
from packetmaster.rag.evaluation_contracts import (
    EvaluationArtifactRef,
    EvaluationCaseResult,
    EvaluationGenerationResult,
    EvaluationIdentity,
    EvaluationOutcome,
    EvaluationRun,
    GateDecision,
    JudgeResult,
    production_system_fingerprint,
)
from packetmaster.rag.evaluation_store import (
    EvaluationArtifactStore,
    SQLiteEvaluationStore,
)


def _identity(*, dataset: str = "a") -> EvaluationIdentity:
    return EvaluationIdentity(
        dataset_fingerprint=dataset * 64,
        corpus_fingerprint="b" * 64,
        chunking_fingerprint="c" * 64,
        embedding_fingerprint="d" * 64,
        retrieval_fingerprint="e" * 64,
        reranker_fingerprint="f" * 64,
        generation_fingerprint="1" * 64,
        judge_fingerprint="2" * 64,
        policy_fingerprint="3" * 64,
        code_revision="6a2287e",
    )


def _run(*, identity: EvaluationIdentity | None = None) -> EvaluationRun:
    return EvaluationRun(
        run_id="evaluation-run-1",
        run_class="formal",
        state="pending",
        stage="validation",
        identity=identity or _identity(),
        created_at=datetime(2026, 7, 31, tzinfo=UTC),
        total_cases=50,
    )


def _database(tmp_path: Path) -> KnowledgeDatabase:
    database = KnowledgeDatabase(tmp_path / "knowledge.sqlite")
    database.initialize()
    return database


def _create_v2_database(path: Path) -> None:
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.executescript(database_module._MIGRATION_1)
        connection.executescript(database_module._MIGRATION_2)
        connection.execute("PRAGMA user_version = 2")
    finally:
        connection.close()


def test_schema_v2_upgrade_preserves_legacy_gate_as_audit(tmp_path: Path) -> None:
    path = tmp_path / "knowledge-v2.sqlite"
    _create_v2_database(path)
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute(
            "INSERT INTO knowledge_metadata(key, value) VALUES (?, ?)",
            ("last_evaluation", '{"production_ready":true}'),
        )
        connection.execute(
            "INSERT INTO knowledge_metadata(key, value) VALUES (?, ?)",
            ("active_gate_passed", "1"),
        )
    finally:
        connection.close()

    database = KnowledgeDatabase(path)
    database.initialize()

    with database.connect() as upgraded:
        version = upgraded.execute("PRAGMA user_version").fetchone()[0]
        legacy = dict(
            upgraded.execute(
                "SELECT key, value_json FROM evaluation_legacy_records"
            ).fetchall()
        )
        active = upgraded.execute(
            "SELECT value FROM knowledge_metadata WHERE key = 'active_gate_passed'"
        ).fetchone()[0]

    assert version == 3
    assert legacy["active_gate_passed"] == "1"
    assert "production_ready" in legacy["last_evaluation"]
    assert active == "1"


def test_schema_v3_migration_rolls_back_all_new_tables_on_failure(
    tmp_path: Path,
) -> None:
    path = tmp_path / "conflicting-v2.sqlite"
    _create_v2_database(path)
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        connection.execute("CREATE TABLE evaluation_case_results(marker TEXT)")
    finally:
        connection.close()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        KnowledgeDatabase(path).initialize()

    connection = sqlite3.connect(path)
    try:
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        run_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'evaluation_runs'"
        ).fetchone()
        conflict = connection.execute(
            "SELECT sql FROM sqlite_master WHERE name = 'evaluation_case_results'"
        ).fetchone()[0]
    finally:
        connection.close()

    assert version == 2
    assert run_table is None
    assert "marker TEXT" in conflict


def test_run_round_trip_allows_progress_but_not_identity_changes(
    tmp_path: Path,
) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    pending = _run()
    store.save_run(pending)
    completed = EvaluationRun.model_validate(
        {
            **pending.model_dump(mode="json"),
            "state": "completed",
            "stage": "gate",
            "outcome": "passed",
            "completed_cases": 50,
            "completed_at": "2026-07-31T01:00:00Z",
        }
    )

    store.save_run(completed)

    assert store.get_run(pending.run_id) == completed
    changed = EvaluationRun.model_validate(
        {
            **pending.model_dump(mode="json"),
            "identity": _identity(dataset="9").model_dump(mode="json"),
        }
    )
    with pytest.raises(ValueError, match="identity is immutable"):
        store.save_run(changed)
    assert store.get_run(pending.run_id) == completed


def test_case_generation_and_judge_results_round_trip(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    run = _run()
    store.save_run(run)
    case_result = EvaluationCaseResult(
        run_id=run.run_id,
        case_id="case-1",
        variant="reranked",
        retrieved_chunk_ids=["knowledge:v1:chunk-1"],
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        relevant_ranks={"knowledge:v1:chunk-1": 1},
        metrics={"recall-at-5": 1.0},
        latency_seconds=0.2,
    )
    generation = EvaluationGenerationResult(
        run_id=run.run_id,
        case_id="case-1",
        answer="Wireshark 显示的是相对序列号。",
        citation_chunk_ids=["knowledge:v1:chunk-1"],
        deterministic_checks={"citation-exists": True},
        latency_seconds=0.5,
        generation_fingerprint="4" * 64,
    )
    judge = JudgeResult(
        case_id="case-1",
        scores={
            "faithfulness": 4,
            "answer_relevance": 4,
            "citation_correctness": 4,
            "evidence_consistency": 4,
            "completeness": 3,
        },
        passed=True,
        reason="回答与引用一致。",
        evidence_chunk_ids=["knowledge:v1:chunk-1"],
        judge_fingerprint="2" * 64,
        calibrated=True,
    )

    store.save_case_result(case_result)
    store.save_generation_result(generation)
    store.save_judge_result(run.run_id, judge)

    updated_case = case_result.model_copy(update={"latency_seconds": 0.3})
    store.save_case_result(updated_case)

    assert store.list_case_results(run.run_id) == [updated_case]
    assert store.get_generation_result(run.run_id, "case-1") == generation
    assert store.list_judge_results(run.run_id) == [judge]


def test_baseline_requires_an_approved_passing_decision(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    run = _run()
    store.save_run(run)
    gate_run = EvaluationRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "state": "running",
            "stage": "gate",
        }
    )
    store.save_run(gate_run)
    failed = GateDecision(
        run_id=run.run_id,
        outcome=EvaluationOutcome.FAILED,
        policy_fingerprint="3" * 64,
        checks=[
            {
                "check_id": "recall-at-5",
                "passed": False,
                "blocking": True,
                "actual": "0.8",
                "expected": ">=0.85",
            }
        ],
        decided_at=datetime(2026, 7, 31, tzinfo=UTC),
    )
    failed_id = store.record_gate_decision(failed)
    with pytest.raises(ValueError, match="approved passing"):
        store.set_baseline(
            target="production",
            run_id=run.run_id,
            decision_id=failed_id,
            set_by="reviewer",
        )

    passed = GateDecision(
        run_id=run.run_id,
        outcome=EvaluationOutcome.PASSED,
        policy_fingerprint="3" * 64,
        checks=[
            {
                "check_id": "recall-at-5",
                "passed": True,
                "blocking": True,
                "actual": "0.98",
                "expected": ">=0.85",
            }
        ],
        decided_at=datetime(2026, 7, 31, 1, tzinfo=UTC),
        approved_by="reviewer",
        approval_note="允许作为生产基线。",
    )
    passed_id = store.record_gate_decision(passed)
    completed = EvaluationRun.model_validate(
        {
            **gate_run.model_dump(mode="json"),
            "state": "completed",
            "outcome": "passed",
            "completed_cases": 50,
            "completed_at": "2026-07-31T02:00:00Z",
        }
    )
    store.save_run(completed)

    store.set_baseline(
        target="production",
        run_id=run.run_id,
        decision_id=passed_id,
        set_by="reviewer",
    )

    assert store.get_baseline_run_id("production") == run.run_id
    assert store.list_gate_decisions(run.run_id) == [failed, passed]
    system_fingerprint = production_system_fingerprint(completed.identity)
    assert store.approved_gate_passed(system_fingerprint) is True
    assert store.approved_gate_passed("9" * 64) is False
    with store.database.connect() as connection:
        events = connection.execute(
            "SELECT COUNT(*) FROM evaluation_baseline_events"
        ).fetchone()[0]
    assert events == 1
    with pytest.raises(sqlite3.IntegrityError):
        with store.database.transaction(immediate=True) as connection:
            connection.execute(
                "DELETE FROM evaluation_runs WHERE run_id = ?", (run.run_id,)
            )
    assert store.get_baseline_run_id("production") == run.run_id


def test_gate_decision_policy_must_match_run_identity(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    run = _run()
    gate_run = EvaluationRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "state": "running",
            "stage": "gate",
        }
    )
    store.save_run(gate_run)
    decision = GateDecision(
        run_id=run.run_id,
        outcome="passed",
        policy_fingerprint="9" * 64,
        checks=[
            {
                "check_id": "recall-at-5",
                "passed": True,
                "blocking": True,
                "actual": "1.0",
                "expected": ">=0.85",
            }
        ],
        decided_at="2026-07-31T00:00:00Z",
    )

    with pytest.raises(ValueError, match="policy does not match"):
        store.record_gate_decision(decision)
    assert store.list_gate_decisions(run.run_id) == []


def test_result_payload_rejects_secrets_and_local_paths(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    run = _run()
    store.save_run(run)
    secret = EvaluationGenerationResult(
        run_id=run.run_id,
        case_id="case-1",
        answer="credential sk-1234567890abcdefghijkl",
        latency_seconds=0.1,
        generation_fingerprint="4" * 64,
    )

    with pytest.raises(ValueError, match="secret or local path"):
        store.save_generation_result(secret)
    assert store.get_generation_result(run.run_id, "case-1") is None


def test_terminal_run_and_results_are_immutable(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    run = _run()
    completed = EvaluationRun.model_validate(
        {
            **run.model_dump(mode="json"),
            "state": "completed",
            "stage": "gate",
            "outcome": "passed",
            "completed_cases": 50,
            "completed_at": "2026-07-31T01:00:00Z",
        }
    )
    store.save_run(completed)

    with pytest.raises(ValueError, match="terminal evaluation run is immutable"):
        store.save_run(run)
    result = EvaluationCaseResult(
        run_id=run.run_id,
        case_id="case-1",
        variant="bm25",
        retrieved_chunk_ids=[],
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        latency_seconds=0.1,
    )
    with pytest.raises(ValueError, match="cannot modify a terminal run"):
        store.save_case_result(result)


def test_result_for_unknown_run_fails_without_partial_write(tmp_path: Path) -> None:
    store = SQLiteEvaluationStore(_database(tmp_path))
    result = EvaluationCaseResult(
        run_id="missing-run",
        case_id="case-1",
        variant="vector",
        retrieved_chunk_ids=[],
        relevant_chunk_ids=["knowledge:v1:chunk-1"],
        latency_seconds=0.1,
    )

    with pytest.raises(ValueError, match="does not exist"):
        store.save_case_result(result)
    with store.database.connect() as connection:
        count = connection.execute(
            "SELECT COUNT(*) FROM evaluation_case_results"
        ).fetchone()[0]
    assert count == 0


def test_artifact_store_round_trips_relative_hashed_json(tmp_path: Path) -> None:
    artifacts = EvaluationArtifactStore(tmp_path / "evaluation-artifacts")

    reference = artifacts.save_json(
        run_id="run-1",
        case_id="case-1",
        kind="trace",
        value={"chunk_ids": ["knowledge:v1:chunk-1"]},
    )

    assert not Path(reference.relative_path).is_absolute()
    assert artifacts.load_json(reference) == {
        "chunk_ids": ["knowledge:v1:chunk-1"]
    }


def test_artifact_store_rejects_escape_secret_and_tampering(
    tmp_path: Path,
) -> None:
    artifacts = EvaluationArtifactStore(tmp_path / "evaluation-artifacts")
    with pytest.raises(ValueError, match="invalid evaluation run ID"):
        artifacts.save_json(
            run_id="../escape",
            case_id="case-1",
            kind="trace",
            value={"ok": True},
        )
    with pytest.raises(ValueError, match="secret or local path"):
        artifacts.save_json(
            run_id="run-1",
            case_id="case-1",
            kind="generation",
            value={"answer": "Bearer private-credential"},
        )

    reference = artifacts.save_json(
        run_id="run-1",
        case_id="case-1",
        kind="trace",
        value={"ok": True},
    )
    path = artifacts.root / reference.relative_path
    path.write_text('{"ok":false}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        artifacts.load_json(reference)

    with pytest.raises(ValueError, match="safe and relative"):
        EvaluationArtifactRef(
            relative_path="../outside.json",
            sha256="a" * 64,
            size_bytes=1,
        )
