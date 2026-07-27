from __future__ import annotations

from pathlib import Path

from packetmaster.config import Settings
from packetmaster.rag.contracts import RagMode
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.runtime import build_rag_runtime


def test_runtime_is_absent_when_rag_is_disabled(tmp_path: Path) -> None:
    settings = Settings(
        rag_enabled=False,
        knowledge_database_path=tmp_path / "knowledge.sqlite",
    )

    assert build_rag_runtime(settings) is None
    assert not settings.knowledge_database_path.exists()


def test_active_mode_without_evaluation_gate_downgrades_to_shadow(
    tmp_path: Path,
) -> None:
    settings = Settings(
        rag_enabled=True,
        rag_mode="active",
        knowledge_database_path=tmp_path / "knowledge.sqlite",
    )

    runtime = build_rag_runtime(settings)

    assert runtime is not None
    assert runtime.mode is RagMode.SHADOW
    assert runtime.degradation_reason == "RAG_ACTIVE_GATE_NOT_PASSED"


def test_active_mode_is_allowed_after_recorded_gate(tmp_path: Path) -> None:
    path = tmp_path / "knowledge.sqlite"
    database = KnowledgeDatabase(path)
    database.initialize()

    class PassedReport:
        production_ready = True
        case_count = 50

        @staticmethod
        def model_dump(mode="json"):
            return {"production_ready": True}

    SQLiteKnowledgeStore(database).record_evaluation(PassedReport())
    settings = Settings(
        rag_enabled=True,
        rag_mode="active",
        knowledge_database_path=path,
    )

    runtime = build_rag_runtime(settings)

    assert runtime is not None
    assert runtime.mode is RagMode.ACTIVE
    assert runtime.degradation_reason is None


def test_corrupt_database_degrades_runtime_without_blocking_startup(
    tmp_path: Path,
) -> None:
    path = tmp_path / "knowledge.sqlite"
    path.write_bytes(b"not-a-sqlite-database")
    runtime = build_rag_runtime(
        Settings(
            rag_enabled=True,
            rag_mode="active",
            knowledge_database_path=path,
        )
    )

    assert runtime is not None
    assert runtime.mode is RagMode.SHADOW
    assert runtime.degradation_reason == "RAG_DATABASE_UNAVAILABLE"
