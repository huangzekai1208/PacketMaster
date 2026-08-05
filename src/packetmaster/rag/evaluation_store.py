"""SQLite persistence for versioned RAG evaluation runs and results."""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from pathlib import Path
from uuid import uuid4

from packetmaster.rag.database import KnowledgeDatabase, _json, _now, _timestamp
from packetmaster.rag.evaluation_contracts import (
    EvaluationArtifactRef,
    EvaluationCaseResult,
    EvaluationGenerationResult,
    EvaluationRun,
    GateDecision,
    JudgeResult,
    production_system_fingerprint,
)

_SENSITIVE_VALUE = re.compile(
    r"sk-[A-Za-z0-9._-]{12,}|Bearer\s+\S+|[A-Za-z]:[\\/]|"
    r"/(?:Users|home|private|tmp|var)/",
    re.IGNORECASE,
)


def _safe_payload(value: object) -> str:
    payload = _json(value)
    if _SENSITIVE_VALUE.search(payload):
        raise ValueError("evaluation payload contains a secret or local path")
    return payload


class EvaluationArtifactStore:
    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()

    def save_json(
        self, *, run_id: str, case_id: str, kind: str, value: object
    ) -> EvaluationArtifactRef:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", run_id):
            raise ValueError("invalid evaluation run ID")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", case_id):
            raise ValueError("invalid evaluation case ID")
        if kind not in {"trace", "generation", "judge"}:
            raise ValueError("unsupported evaluation artifact kind")
        content = _safe_payload(value) + "\n"
        encoded = content.encode("utf-8")
        if len(encoded) > 10 * 1024 * 1024:
            raise ValueError("evaluation artifact exceeds the size limit")
        relative = Path(run_id) / f"{case_id}-{kind}.json"
        destination = (self.root / relative).resolve()
        if not destination.is_relative_to(self.root):
            raise ValueError("evaluation artifact escaped its root")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(
            f".{destination.name}.{uuid4().hex}.tmp"
        )
        try:
            temporary.write_bytes(encoded)
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        return EvaluationArtifactRef(
            relative_path=relative.as_posix(),
            sha256=hashlib.sha256(encoded).hexdigest(),
            size_bytes=len(encoded),
        )

    def load_json(self, reference: EvaluationArtifactRef) -> object:
        destination = (self.root / reference.relative_path).resolve()
        if not destination.is_relative_to(self.root):
            raise ValueError("evaluation artifact escaped its root")
        encoded = destination.read_bytes()
        if len(encoded) != reference.size_bytes:
            raise ValueError("evaluation artifact size does not match")
        if hashlib.sha256(encoded).hexdigest() != reference.sha256:
            raise ValueError("evaluation artifact hash does not match")
        return json.loads(encoded)


class SQLiteEvaluationStore:
    def __init__(self, database: KnowledgeDatabase) -> None:
        self.database = database

    def save_run(self, run: EvaluationRun) -> None:
        identity_json = _safe_payload(run.identity)
        run_json = _safe_payload(run)
        system_fingerprint = production_system_fingerprint(run.identity)
        updated_at = _timestamp(_now())
        with self.database.transaction(immediate=True) as connection:
            existing = connection.execute(
                """
                SELECT run_class, state, identity_json, run_json,
                       total_cases, completed_cases, created_at
                FROM evaluation_runs WHERE run_id = ?
                """,
                (run.run_id,),
            ).fetchone()
            if existing is not None and (
                str(existing["run_class"]) != run.run_class.value
                or str(existing["identity_json"]) != identity_json
                or int(existing["total_cases"]) != run.total_cases
                or str(existing["created_at"]) != _timestamp(run.created_at)
            ):
                raise ValueError("evaluation run identity is immutable")
            if existing is not None:
                terminal = {"completed", "failed", "cancelled"}
                if (
                    str(existing["state"]) in terminal
                    and str(existing["run_json"]) != run_json
                ):
                    raise ValueError("terminal evaluation run is immutable")
                if run.completed_cases < int(existing["completed_cases"]):
                    raise ValueError("evaluation progress cannot move backwards")
            connection.execute(
                """
                INSERT INTO evaluation_runs (
                    run_id, run_class, state, stage, outcome,
                    dataset_fingerprint, system_fingerprint, identity_json,
                    run_json, total_cases, completed_cases, created_at,
                    completed_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    state = excluded.state,
                    stage = excluded.stage,
                    outcome = excluded.outcome,
                    run_json = excluded.run_json,
                    completed_cases = excluded.completed_cases,
                    completed_at = excluded.completed_at,
                    updated_at = excluded.updated_at
                """,
                (
                    run.run_id,
                    run.run_class.value,
                    run.state.value,
                    run.stage.value,
                    run.outcome.value if run.outcome else None,
                    run.identity.dataset_fingerprint,
                    system_fingerprint,
                    identity_json,
                    run_json,
                    run.total_cases,
                    run.completed_cases,
                    _timestamp(run.created_at),
                    _timestamp(run.completed_at) if run.completed_at else None,
                    updated_at,
                ),
            )

    def get_run(self, run_id: str) -> EvaluationRun | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT run_json FROM evaluation_runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
        return (
            EvaluationRun.model_validate_json(str(row["run_json"]))
            if row is not None
            else None
        )

    def save_case_result(self, result: EvaluationCaseResult) -> None:
        self._upsert_case_payload(
            table="evaluation_case_results",
            run_id=result.run_id,
            case_id=result.case_id,
            payload=result,
            variant=result.variant.value,
        )

    def list_case_results(self, run_id: str) -> list[EvaluationCaseResult]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT result_json FROM evaluation_case_results
                WHERE run_id = ? ORDER BY case_id, variant
                """,
                (run_id,),
            ).fetchall()
        return [
            EvaluationCaseResult.model_validate_json(str(row["result_json"]))
            for row in rows
        ]

    def save_generation_result(self, result: EvaluationGenerationResult) -> None:
        self._upsert_case_payload(
            table="evaluation_generation_results",
            run_id=result.run_id,
            case_id=result.case_id,
            payload=result,
        )

    def get_generation_result(
        self, run_id: str, case_id: str
    ) -> EvaluationGenerationResult | None:
        payload = self._get_case_payload(
            "evaluation_generation_results", run_id, case_id
        )
        return (
            EvaluationGenerationResult.model_validate_json(payload)
            if payload is not None
            else None
        )

    def save_judge_result(self, run_id: str, result: JudgeResult) -> None:
        self._upsert_case_payload(
            table="evaluation_judge_results",
            run_id=run_id,
            case_id=result.case_id,
            payload=result,
            judge_fingerprint=result.judge_fingerprint,
        )

    def list_judge_results(self, run_id: str) -> list[JudgeResult]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT result_json FROM evaluation_judge_results
                WHERE run_id = ? ORDER BY case_id, judge_fingerprint
                """,
                (run_id,),
            ).fetchall()
        return [
            JudgeResult.model_validate_json(str(row["result_json"])) for row in rows
        ]

    def record_gate_decision(self, decision: GateDecision) -> int:
        payload = _safe_payload(decision)
        with self.database.transaction(immediate=True) as connection:
            run = connection.execute(
                """
                SELECT state, stage, identity_json
                FROM evaluation_runs WHERE run_id = ?
                """,
                (decision.run_id,),
            ).fetchone()
            if run is None or (
                str(run["stage"]) != "gate"
                or str(run["state"]) not in {"running", "completed"}
            ):
                raise ValueError("gate decision requires a run in the gate stage")
            identity = json.loads(str(run["identity_json"]))
            if identity.get("policy_fingerprint") != decision.policy_fingerprint:
                raise ValueError("gate decision policy does not match run identity")
            cursor = connection.execute(
                """
                INSERT INTO evaluation_gate_decisions (
                    run_id, outcome, policy_fingerprint, approved_by,
                    decision_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    decision.run_id,
                    decision.outcome.value,
                    decision.policy_fingerprint,
                    decision.approved_by,
                    payload,
                    _timestamp(decision.decided_at),
                ),
            )
        return int(cursor.lastrowid)

    def list_gate_decisions(self, run_id: str) -> list[GateDecision]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT decision_json FROM evaluation_gate_decisions
                WHERE run_id = ? ORDER BY decision_id
                """,
                (run_id,),
            ).fetchall()
        return [
            GateDecision.model_validate_json(str(row["decision_json"]))
            for row in rows
        ]

    def set_baseline(
        self, *, target: str, run_id: str, decision_id: int, set_by: str
    ) -> None:
        if not target or len(target) > 128 or not set_by or len(set_by) > 128:
            raise ValueError("baseline target and reviewer must be bounded")
        with self.database.transaction(immediate=True) as connection:
            decision = connection.execute(
                """
                SELECT d.outcome, d.approved_by, d.policy_fingerprint,
                       r.run_class, r.state, r.outcome AS run_outcome,
                       r.identity_json
                FROM evaluation_gate_decisions d
                JOIN evaluation_runs r ON r.run_id = d.run_id
                WHERE d.decision_id = ? AND d.run_id = ?
                """,
                (decision_id, run_id),
            ).fetchone()
            identity = (
                json.loads(str(decision["identity_json"]))
                if decision is not None
                else {}
            )
            if (
                decision is None
                or str(decision["outcome"]) != "passed"
                or not decision["approved_by"]
                or str(decision["run_class"]) != "formal"
                or str(decision["state"]) != "completed"
                or str(decision["run_outcome"]) != "passed"
                or identity.get("policy_fingerprint")
                != str(decision["policy_fingerprint"])
            ):
                raise ValueError("baseline requires an approved passing decision")
            created_at = _timestamp(_now())
            connection.execute(
                """
                INSERT INTO evaluation_baseline_events (
                    target, run_id, decision_id, set_by, created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (target, run_id, decision_id, set_by, created_at),
            )
            connection.execute(
                """
                INSERT INTO evaluation_baselines (
                    target, run_id, decision_id, set_by, created_at
                ) VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(target) DO UPDATE SET
                    run_id = excluded.run_id,
                    decision_id = excluded.decision_id,
                    set_by = excluded.set_by,
                    created_at = excluded.created_at
                """,
                (target, run_id, decision_id, set_by, created_at),
            )

    def get_baseline_run_id(self, target: str) -> str | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT run_id FROM evaluation_baselines WHERE target = ?",
                (target,),
            ).fetchone()
        return str(row["run_id"]) if row is not None else None

    def approved_gate_passed(self, system_fingerprint: str) -> bool:
        if not re.fullmatch(r"[a-f0-9]{64}", system_fingerprint):
            raise ValueError("system fingerprint must be a SHA-256 digest")
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT 1
                FROM evaluation_runs r
                JOIN evaluation_gate_decisions d ON d.run_id = r.run_id
                WHERE r.system_fingerprint = ?
                  AND r.run_class = 'formal'
                  AND r.state = 'completed'
                  AND r.outcome = 'passed'
                  AND d.outcome = 'passed'
                  AND d.approved_by IS NOT NULL
                LIMIT 1
                """,
                (system_fingerprint,),
            ).fetchone()
        return row is not None

    def _upsert_case_payload(
        self,
        *,
        table: str,
        run_id: str,
        case_id: str,
        payload: object,
        variant: str | None = None,
        judge_fingerprint: str | None = None,
    ) -> None:
        allowed = {
            "evaluation_case_results": ("variant", variant),
            "evaluation_generation_results": (None, None),
            "evaluation_judge_results": (
                "judge_fingerprint",
                judge_fingerprint,
            ),
        }
        if table not in allowed:
            raise ValueError("unsupported evaluation result table")
        discriminator, value = allowed[table]
        columns = ["run_id", "case_id"]
        values: list[object] = [run_id, case_id]
        if discriminator is not None:
            if value is None:
                raise ValueError("evaluation result discriminator is required")
            columns.append(discriminator)
            values.append(value)
        columns.extend(["result_json", "updated_at"])
        values.extend([_safe_payload(payload), _timestamp(_now())])
        conflict = ", ".join(columns[:-2])
        placeholders = ", ".join("?" for _ in columns)
        with self.database.transaction(immediate=True) as connection:
            self._require_writable_run(connection, run_id)
            connection.execute(
                f"""
                INSERT INTO {table} ({', '.join(columns)})
                VALUES ({placeholders})
                ON CONFLICT({conflict}) DO UPDATE SET
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                values,
            )

    def _get_case_payload(
        self, table: str, run_id: str, case_id: str
    ) -> str | None:
        if table != "evaluation_generation_results":
            raise ValueError("unsupported evaluation result table")
        with self.database.connect() as connection:
            row = connection.execute(
                f"""
                SELECT result_json FROM {table}
                WHERE run_id = ? AND case_id = ?
                """,
                (run_id, case_id),
            ).fetchone()
        return str(row["result_json"]) if row is not None else None

    @staticmethod
    def _require_writable_run(
        connection: sqlite3.Connection, run_id: str
    ) -> None:
        row = connection.execute(
            "SELECT state FROM evaluation_runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        if row is None:
            raise ValueError("evaluation run does not exist")
        if str(row["state"]) not in {"pending", "running"}:
            raise ValueError("evaluation results cannot modify a terminal run")
