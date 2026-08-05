"""Versioned contracts for reproducible RAG evaluation runs."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import Field, field_validator, model_validator

from packetmaster.rag.contracts import Identifier, KnowledgeQuery, RagContract

_SENSITIVE = re.compile(
    r"(?:api[_-]?key|authorization|token|password|payload|pcap[_-]?path|"
    r"[A-Za-z]:[\\/]|/(?:Users|home|private|tmp|var)/)",
    re.IGNORECASE,
)
Sha256 = str


class EvaluationVariant(StrEnum):
    BM25 = "bm25"
    VECTOR = "vector"
    RRF = "rrf"
    RERANKED = "reranked"


class EvaluationRunState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EvaluationOutcome(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    INCOMPLETE = "incomplete"


class EvaluationRunClass(StrEnum):
    INFORMATIONAL = "informational"
    FORMAL = "formal"
    LEGACY = "legacy"


class EvaluationStage(StrEnum):
    VALIDATION = "validation"
    RETRIEVAL = "retrieval"
    GENERATION = "generation"
    JUDGE = "judge"
    COMPARISON = "comparison"
    GATE = "gate"


class DatasetManifest(RagContract):
    dataset_id: Identifier
    version: int = Field(ge=1)
    language: str = Field(min_length=2, max_length=32)
    domain: str = Field(min_length=1, max_length=128)
    created_at: datetime
    created_by: str = Field(min_length=1, max_length=128)
    reviewed_by: list[str] = Field(min_length=1, max_length=16)
    change_summary: str = Field(min_length=1, max_length=1_000)
    annotation_guideline_version: Identifier
    policy_id: Identifier
    allowed_knowledge_ids: list[Identifier] = Field(
        default_factory=list, max_length=256
    )
    external_judge_allowed: bool = False

    @field_validator("reviewed_by")
    @classmethod
    def validate_reviewers(cls, values: list[str]) -> list[str]:
        if any(not value.strip() or len(value) > 128 for value in values):
            raise ValueError("reviewers must contain 1 to 128 characters")
        if len(set(values)) != len(values):
            raise ValueError("reviewers must be unique")
        return values


class EvaluationCaseV2(RagContract):
    case_id: Identifier
    query: KnowledgeQuery
    relevant_chunk_ids: list[Identifier] = Field(min_length=1, max_length=32)
    relevance_grades: dict[Identifier, int] = Field(min_length=1, max_length=32)
    critical: bool
    question_type: Identifier
    expected_facts: list[str] = Field(min_length=1, max_length=32)
    expected_causes: list[str] = Field(default_factory=list, max_length=32)
    forbidden_conclusions: list[str] = Field(default_factory=list, max_length=32)
    applicable_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    applicability_note: str = Field(default="", max_length=1_000)
    reference_answer: str | None = Field(default=None, max_length=8_000)
    approved_citation_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    annotated_by: str = Field(min_length=1, max_length=128)
    reviewed_by: str = Field(min_length=1, max_length=128)
    label_change_reason: str = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def validate_labels(self) -> EvaluationCaseV2:
        if self.query.query_id != self.case_id:
            raise ValueError("evaluation case_id and query_id must match")
        if set(self.relevance_grades) != set(self.relevant_chunk_ids):
            raise ValueError("relevance grades must cover exactly relevant chunks")
        if any(not 0 <= grade <= 3 for grade in self.relevance_grades.values()):
            raise ValueError("relevance grades must be between 0 and 3")
        relevant = set(self.relevant_chunk_ids)
        if not set(self.applicable_chunk_ids) <= relevant:
            raise ValueError("applicable chunks must be relevant chunks")
        if not set(self.approved_citation_chunk_ids) <= relevant:
            raise ValueError("approved citations must be relevant chunks")
        if self.annotated_by == self.reviewed_by:
            raise ValueError("annotator and reviewer must be different")
        return self


class EvaluationDatasetV2(RagContract):
    schema_version: Literal[2] = 2
    manifest: DatasetManifest
    cases: list[EvaluationCaseV2] = Field(min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_dataset(self) -> EvaluationDatasetV2:
        case_ids = [case.case_id for case in self.cases]
        if len(set(case_ids)) != len(case_ids):
            raise ValueError("evaluation dataset contains duplicate case IDs")
        allowed = set(self.manifest.allowed_knowledge_ids)
        if allowed:
            labeled = {
                chunk_id.split(":v", 1)[0]
                for case in self.cases
                for chunk_id in case.relevant_chunk_ids
            }
            if not labeled <= allowed:
                raise ValueError("labels contain knowledge outside manifest scope")
        return self


class EvaluationIdentity(RagContract):
    dataset_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    corpus_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    chunking_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    embedding_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    retrieval_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    reranker_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    generation_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    judge_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    policy_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    code_revision: str = Field(min_length=7, max_length=64)
    dirty: bool = False


class EvaluationRun(RagContract):
    run_id: Identifier
    run_class: EvaluationRunClass
    state: EvaluationRunState
    stage: EvaluationStage
    identity: EvaluationIdentity
    created_at: datetime
    completed_at: datetime | None = None
    outcome: EvaluationOutcome | None = None
    completed_cases: int = Field(default=0, ge=0)
    total_cases: int = Field(ge=1)
    error_code: Identifier | None = None

    @model_validator(mode="after")
    def validate_completion(self) -> EvaluationRun:
        if self.completed_cases > self.total_cases:
            raise ValueError("completed cases cannot exceed total cases")
        if self.state is EvaluationRunState.COMPLETED:
            if self.completed_at is None or self.outcome is None:
                raise ValueError("completed runs require time and outcome")
        elif self.outcome is not None:
            raise ValueError("unfinished runs cannot have an outcome")
        if self.run_class is EvaluationRunClass.FORMAL and self.identity.dirty:
            raise ValueError("formal runs require a clean code revision")
        return self


class EvaluationArtifactRef(RagContract):
    relative_path: str = Field(min_length=1, max_length=512)
    sha256: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    size_bytes: int = Field(ge=1, le=10 * 1024 * 1024)

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value:
            raise ValueError("evaluation artifact path must be safe and relative")
        return value


class EvaluationCaseResult(RagContract):
    run_id: Identifier
    case_id: Identifier
    variant: EvaluationVariant
    retrieved_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=100
    )
    relevant_chunk_ids: list[Identifier] = Field(min_length=1, max_length=32)
    relevant_ranks: dict[Identifier, int] = Field(
        default_factory=dict, max_length=32
    )
    metrics: dict[Identifier, float] = Field(default_factory=dict, max_length=64)
    latency_seconds: float = Field(ge=0)
    warnings: list[str] = Field(default_factory=list, max_length=32)
    failure_labels: list[Identifier] = Field(default_factory=list, max_length=32)
    artifact: EvaluationArtifactRef | None = None

    @model_validator(mode="after")
    def validate_trace(self) -> EvaluationCaseResult:
        relevant = set(self.relevant_chunk_ids)
        if not set(self.relevant_ranks) <= relevant:
            raise ValueError("relevant ranks must refer to labeled chunks")
        if any(
            rank < 1 or rank > len(self.retrieved_chunk_ids)
            for rank in self.relevant_ranks.values()
        ):
            raise ValueError("relevant rank is outside retrieved results")
        for chunk_id, rank in self.relevant_ranks.items():
            if self.retrieved_chunk_ids[rank - 1] != chunk_id:
                raise ValueError("relevant rank does not match retrieved order")
        return self


class EvaluationGenerationResult(RagContract):
    run_id: Identifier
    case_id: Identifier
    answer: str = Field(min_length=1, max_length=32_000)
    citation_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    context_chunk_ids: list[Identifier] = Field(default_factory=list, max_length=8)
    deterministic_checks: dict[Identifier, bool] = Field(
        default_factory=dict, max_length=64
    )
    extracted_facts: list[str] = Field(default_factory=list, max_length=64)
    extracted_causes: list[str] = Field(default_factory=list, max_length=32)
    latency_seconds: float = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    retry_count: int = Field(default=0, ge=0, le=10)
    generation_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    degraded: bool = False
    warnings: list[str] = Field(default_factory=list, max_length=32)
    artifact: EvaluationArtifactRef | None = None


class JudgeScores(RagContract):
    faithfulness: int = Field(ge=0, le=4)
    answer_relevance: int = Field(ge=0, le=4)
    citation_correctness: int = Field(ge=0, le=4)
    evidence_consistency: int = Field(ge=0, le=4)
    completeness: int = Field(ge=0, le=4)


class JudgeResult(RagContract):
    case_id: Identifier
    scores: JudgeScores
    passed: bool
    uncertain: bool = False
    violations: list[Identifier] = Field(default_factory=list, max_length=32)
    reason: str = Field(min_length=1, max_length=2_000)
    evidence_chunk_ids: list[Identifier] = Field(
        default_factory=list, max_length=32
    )
    judge_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    calibrated: bool = False
    latency_seconds: float | None = Field(default=None, ge=0)
    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    retry_count: int = Field(default=0, ge=0, le=20)


class GateCheck(RagContract):
    check_id: Identifier
    passed: bool
    blocking: bool
    actual: str = Field(min_length=1, max_length=256)
    expected: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="", max_length=1_000)


class GateDecision(RagContract):
    run_id: Identifier
    outcome: EvaluationOutcome
    policy_fingerprint: Sha256 = Field(pattern=r"^[a-f0-9]{64}$")
    checks: list[GateCheck] = Field(min_length=1, max_length=256)
    decided_at: datetime
    approved_by: str | None = Field(default=None, min_length=1, max_length=128)
    approval_note: str = Field(default="", max_length=1_000)

    @model_validator(mode="after")
    def validate_decision(self) -> GateDecision:
        blocking_failures = [
            check for check in self.checks if check.blocking and not check.passed
        ]
        if self.outcome is EvaluationOutcome.PASSED and blocking_failures:
            raise ValueError("passed decision cannot contain blocking failures")
        if (
            self.approved_by is not None
            and self.outcome is not EvaluationOutcome.PASSED
        ):
            raise ValueError("only passed decisions can be approved")
        return self


def canonical_fingerprint(value: RagContract | dict[str, object]) -> str:
    payload = value.model_dump(mode="json") if isinstance(value, RagContract) else value
    encoded = json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def production_system_fingerprint(identity: EvaluationIdentity) -> str:
    return canonical_fingerprint(
        {
            "corpus_fingerprint": identity.corpus_fingerprint,
            "chunking_fingerprint": identity.chunking_fingerprint,
            "embedding_fingerprint": identity.embedding_fingerprint,
            "retrieval_fingerprint": identity.retrieval_fingerprint,
            "reranker_fingerprint": identity.reranker_fingerprint,
            "generation_fingerprint": identity.generation_fingerprint,
            "code_revision": identity.code_revision,
        }
    )


def load_evaluation_dataset_v2(path: Path) -> EvaluationDatasetV2:
    raw = path.read_text(encoding="utf-8")
    if _SENSITIVE.search(raw):
        raise ValueError("evaluation dataset contains sensitive fields or paths")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("V2 evaluation dataset must be a JSON object")
    return EvaluationDatasetV2.model_validate(value)
