"""Versioned SQLite persistence and approved-knowledge retrieval."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from packetmaster.errors import AppError
from packetmaster.rag.contracts import (
    CaseProfile,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeQuery,
    KnowledgeStatus,
    KnowledgeType,
    KnowledgeVersion,
    RetrievalCandidate,
)

_SCHEMA_VERSION = 1
_MIGRATION_1 = """
CREATE TABLE knowledge_documents (
    knowledge_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    knowledge_type TEXT NOT NULL,
    language TEXT NOT NULL,
    authority TEXT NOT NULL,
    status TEXT NOT NULL,
    summary TEXT NOT NULL,
    applicability_json TEXT NOT NULL,
    current_version_id TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX knowledge_documents_status_idx
    ON knowledge_documents(status, knowledge_type, updated_at DESC);

CREATE TABLE knowledge_versions (
    version_id TEXT PRIMARY KEY,
    knowledge_id TEXT NOT NULL REFERENCES knowledge_documents(knowledge_id),
    version_number INTEGER NOT NULL,
    source_name TEXT NOT NULL,
    source_location TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    valid_from TEXT,
    valid_to TEXT,
    approved_at TEXT,
    approved_by TEXT,
    supersedes_version_id TEXT REFERENCES knowledge_versions(version_id),
    UNIQUE(knowledge_id, version_number),
    UNIQUE(knowledge_id, content_hash)
);
CREATE INDEX knowledge_versions_status_idx
    ON knowledge_versions(status, knowledge_id, version_number DESC);

CREATE TABLE knowledge_chunks (
    chunk_id TEXT PRIMARY KEY,
    knowledge_id TEXT NOT NULL REFERENCES knowledge_documents(knowledge_id),
    version_id TEXT NOT NULL REFERENCES knowledge_versions(version_id)
        ON DELETE CASCADE,
    chunk_index INTEGER NOT NULL,
    heading_path_json TEXT NOT NULL,
    source_location TEXT NOT NULL,
    content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    UNIQUE(version_id, chunk_index)
);
CREATE INDEX knowledge_chunks_version_idx
    ON knowledge_chunks(version_id, chunk_index);
CREATE INDEX knowledge_chunks_status_idx
    ON knowledge_chunks(status, knowledge_id);

CREATE TABLE knowledge_case_profiles (
    version_id TEXT PRIMARY KEY REFERENCES knowledge_versions(version_id)
        ON DELETE CASCADE,
    profile_json TEXT NOT NULL
);

CREATE TABLE knowledge_embeddings (
    chunk_id TEXT PRIMARY KEY REFERENCES knowledge_chunks(chunk_id)
        ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    dimension INTEGER NOT NULL,
    vector BLOB NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX knowledge_embeddings_model_idx
    ON knowledge_embeddings(model_name, dimension);

CREATE TABLE knowledge_audit_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    knowledge_id TEXT NOT NULL,
    version_id TEXT,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    reason TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX knowledge_audit_events_knowledge_idx
    ON knowledge_audit_events(knowledge_id, event_id);

CREATE TABLE knowledge_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
INSERT INTO knowledge_metadata(key, value) VALUES ('index_generation', '0');

CREATE VIRTUAL TABLE knowledge_chunks_fts USING fts5(
    chunk_id UNINDEXED,
    title,
    heading,
    content,
    tokenize='trigram'
);
"""


def _now() -> datetime:
    return datetime.now(UTC)


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("timestamps must include a timezone")
    return value.astimezone(UTC).isoformat()


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


def _json(value: object) -> str:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json")
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


@dataclass(frozen=True)
class StoredEmbedding:
    chunk_id: str
    model_name: str
    dimension: int
    vector: bytes
    content_hash: str

    def __post_init__(self) -> None:
        if not self.model_name or self.dimension < 1:
            raise ValueError("embedding model and positive dimension are required")
        if len(self.vector) != self.dimension * 4:
            raise ValueError("embedding vector must contain float32 bytes")
        if len(self.content_hash) != 64:
            raise ValueError("embedding content_hash must be a SHA-256 hex digest")


class KnowledgeDatabase:
    def __init__(self, path: Path, *, timeout_seconds: float = 5.0) -> None:
        self.path = path.expanduser().resolve()
        self.timeout_seconds = timeout_seconds

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with self.connect() as connection:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version > _SCHEMA_VERSION:
                    raise RuntimeError(
                        f"knowledge schema {version} is newer than {_SCHEMA_VERSION}"
                    )
                if version < 1:
                    with connection:
                        connection.executescript(_MIGRATION_1)
                        connection.execute("PRAGMA user_version = 1")
                self._check_fts5(connection)
        except sqlite3.OperationalError as exc:
            if "fts5" in str(exc).lower() or "tokenizer" in str(exc).lower():
                raise AppError(
                    code="RAG_FTS5_UNAVAILABLE",
                    message="当前 Python SQLite 不支持 PacketMaster 所需的 FTS5",
                    recoverable=True,
                    suggested_action="请使用项目支持的 Python/Conda 环境重新安装。",
                ) from exc
            raise

    @staticmethod
    def _check_fts5(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE name = 'knowledge_chunks_fts'"
        ).fetchone()
        if row is None:
            raise sqlite3.OperationalError("FTS5 table is unavailable")

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        try:
            yield connection
        finally:
            connection.close()

    @contextmanager
    def transaction(self, *, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()


class SQLiteKnowledgeStore:
    def __init__(
        self,
        database: KnowledgeDatabase,
        *,
        embedding_model: str | None = None,
        embedding_dimension: int | None = None,
    ) -> None:
        self.database = database
        self.embedding_model = embedding_model
        self.embedding_dimension = embedding_dimension
        self._vector_cache: tuple[
            int, int, list[tuple[dict[str, object], tuple[float, ...]]]
        ] | None = None

    def save_draft(
        self,
        document: KnowledgeDocument,
        version: KnowledgeVersion,
        chunks: Sequence[KnowledgeChunk],
        *,
        case_profile: CaseProfile | None = None,
    ) -> None:
        if document.status is not KnowledgeStatus.DRAFT:
            raise ValueError("new knowledge document must be draft")
        if version.status is not KnowledgeStatus.DRAFT:
            raise ValueError("new knowledge version must be draft")
        if version.knowledge_id != document.knowledge_id:
            raise ValueError("document and version knowledge_id must match")
        if not chunks:
            raise ValueError("at least one knowledge chunk is required")
        if any(
            chunk.knowledge_id != document.knowledge_id
            or chunk.version_id != version.version_id
            or chunk.status is not KnowledgeStatus.DRAFT
            for chunk in chunks
        ):
            raise ValueError("all chunks must belong to the draft document version")
        if sorted(chunk.chunk_index for chunk in chunks) != list(range(len(chunks))):
            raise ValueError("chunk indexes must be contiguous from zero")
        now = _timestamp(_now())
        try:
            with self.database.transaction(immediate=True) as connection:
                connection.execute(
                    """
                    INSERT INTO knowledge_documents (
                        knowledge_id, title, knowledge_type, language, authority,
                        status, summary, applicability_json, current_version_id,
                        created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        document.knowledge_id,
                        document.title,
                        document.knowledge_type.value,
                        document.language,
                        document.authority.value,
                        document.status.value,
                        document.summary,
                        _json(document.applicability),
                        document.current_version_id,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO knowledge_versions (
                        version_id, knowledge_id, version_number, source_name,
                        source_location, content_hash, status, created_at,
                        valid_from, valid_to, approved_at, approved_by,
                        supersedes_version_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        version.version_id,
                        version.knowledge_id,
                        version.version_number,
                        version.source_name,
                        version.source_location,
                        version.content_hash,
                        version.status.value,
                        _timestamp(version.created_at),
                        _timestamp(version.valid_from) if version.valid_from else None,
                        _timestamp(version.valid_to) if version.valid_to else None,
                        None,
                        None,
                        version.supersedes_version_id,
                    ),
                )
                connection.executemany(
                    """
                    INSERT INTO knowledge_chunks (
                        chunk_id, knowledge_id, version_id, chunk_index,
                        heading_path_json, source_location, content, content_hash,
                        status
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            chunk.chunk_id,
                            chunk.knowledge_id,
                            chunk.version_id,
                            chunk.chunk_index,
                            _json(chunk.heading_path),
                            chunk.source_location,
                            chunk.content,
                            chunk.content_hash,
                            chunk.status.value,
                        )
                        for chunk in chunks
                    ],
                )
                if case_profile is not None:
                    connection.execute(
                        "INSERT INTO knowledge_case_profiles VALUES (?, ?)",
                        (version.version_id, _json(case_profile)),
                    )
                self._audit(
                    connection,
                    document.knowledge_id,
                    version.version_id,
                    "import_draft",
                    "system",
                    "",
                )
        except sqlite3.IntegrityError as exc:
            raise AppError(
                code="KNOWLEDGE_CONFLICT",
                message="知识 ID、版本号或内容已经存在",
                recoverable=True,
                suggested_action="请检查现有版本，或使用新的知识 ID 和版本号。",
            ) from exc

    def save_embeddings(
        self, version_id: str, embeddings: Sequence[StoredEmbedding]
    ) -> None:
        models = {(item.model_name, item.dimension) for item in embeddings}
        if len(models) > 1:
            raise ValueError("one embedding batch must use one model and dimension")
        with self.database.transaction(immediate=True) as connection:
            chunks = connection.execute(
                "SELECT chunk_id FROM knowledge_chunks WHERE version_id = ?",
                (version_id,),
            ).fetchall()
            expected = {str(row["chunk_id"]) for row in chunks}
            provided = {embedding.chunk_id for embedding in embeddings}
            if not provided <= expected:
                raise ValueError("embedding chunk does not belong to version")
            connection.executemany(
                """
                INSERT INTO knowledge_embeddings (
                    chunk_id, model_name, dimension, vector, content_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(chunk_id) DO UPDATE SET
                    model_name = excluded.model_name,
                    dimension = excluded.dimension,
                    vector = excluded.vector,
                    content_hash = excluded.content_hash,
                    created_at = excluded.created_at
                """,
                [
                    (
                        item.chunk_id,
                        item.model_name,
                        item.dimension,
                        item.vector,
                        item.content_hash,
                        _timestamp(_now()),
                    )
                    for item in embeddings
                ],
            )
            self._increment_generation(connection)

    def indexed_chunk_ids(
        self, version_id: str, *, model_name: str, dimension: int
    ) -> set[str]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT c.chunk_id
                FROM knowledge_chunks c
                JOIN knowledge_embeddings e ON e.chunk_id = c.chunk_id
                WHERE c.version_id = ? AND e.model_name = ? AND e.dimension = ?
                  AND e.content_hash = c.content_hash
                """,
                (version_id, model_name, dimension),
            ).fetchall()
        return {str(row[0]) for row in rows}

    def publish_version(self, version_id: str, *, approved_by: str) -> None:
        if not approved_by or len(approved_by) > 128:
            raise ValueError("approved_by must contain 1 to 128 characters")
        approved_at = _timestamp(_now())
        with self.database.transaction(immediate=True) as connection:
            version = connection.execute(
                "SELECT * FROM knowledge_versions WHERE version_id = ?",
                (version_id,),
            ).fetchone()
            if version is None:
                raise AppError(
                    code="KNOWLEDGE_NOT_FOUND",
                    message="知识版本不存在",
                    recoverable=True,
                    suggested_action="请检查知识版本 ID。",
                )
            if version["status"] == KnowledgeStatus.APPROVED.value:
                return
            if version["status"] != KnowledgeStatus.DRAFT.value:
                raise AppError(
                    code="INVALID_KNOWLEDGE_STATE",
                    message="只有草稿知识可以发布",
                    recoverable=True,
                    suggested_action="请创建新版本后重新审核。",
                )
            incomplete = connection.execute(
                """
                SELECT c.chunk_id
                FROM knowledge_chunks c
                LEFT JOIN knowledge_embeddings e ON e.chunk_id = c.chunk_id
                WHERE c.version_id = ?
                  AND (e.chunk_id IS NULL OR e.content_hash != c.content_hash)
                LIMIT 1
                """,
                (version_id,),
            ).fetchone()
            if incomplete is not None:
                raise AppError(
                    code="KNOWLEDGE_INDEX_INCOMPLETE",
                    message="知识 embedding 缺失或内容 hash 不匹配",
                    recoverable=True,
                    suggested_action="请重新生成该版本的完整向量索引。",
                )
            knowledge_id = str(version["knowledge_id"])
            current = connection.execute(
                "SELECT current_version_id FROM knowledge_documents "
                "WHERE knowledge_id = ?",
                (knowledge_id,),
            ).fetchone()
            previous = str(current[0]) if current and current[0] else None
            if previous and previous != version_id:
                connection.execute(
                    "UPDATE knowledge_versions SET status = ? WHERE version_id = ?",
                    (KnowledgeStatus.SUPERSEDED.value, previous),
                )
                connection.execute(
                    "UPDATE knowledge_chunks SET status = ? WHERE version_id = ?",
                    (KnowledgeStatus.SUPERSEDED.value, previous),
                )
                self._delete_fts_version(connection, previous)
            connection.execute(
                """
                UPDATE knowledge_versions
                SET status = ?, approved_at = ?, approved_by = ?
                WHERE version_id = ?
                """,
                (
                    KnowledgeStatus.APPROVED.value,
                    approved_at,
                    approved_by,
                    version_id,
                ),
            )
            connection.execute(
                "UPDATE knowledge_chunks SET status = ? WHERE version_id = ?",
                (KnowledgeStatus.APPROVED.value, version_id),
            )
            connection.execute(
                """
                UPDATE knowledge_documents
                SET status = ?, current_version_id = ?, updated_at = ?
                WHERE knowledge_id = ?
                """,
                (
                    KnowledgeStatus.APPROVED.value,
                    version_id,
                    approved_at,
                    knowledge_id,
                ),
            )
            title = connection.execute(
                "SELECT title FROM knowledge_documents WHERE knowledge_id = ?",
                (knowledge_id,),
            ).fetchone()[0]
            chunks = connection.execute(
                "SELECT * FROM knowledge_chunks WHERE version_id = ? "
                "ORDER BY chunk_index",
                (version_id,),
            ).fetchall()
            connection.executemany(
                "INSERT INTO knowledge_chunks_fts(chunk_id, title, heading, content) "
                "VALUES (?, ?, ?, ?)",
                [
                    (
                        row["chunk_id"],
                        title,
                        " / ".join(json.loads(row["heading_path_json"])),
                        row["content"],
                    )
                    for row in chunks
                ],
            )
            self._increment_generation(connection)
            self._audit(
                connection,
                knowledge_id,
                version_id,
                "publish",
                approved_by,
                "",
            )

    def disable_version(self, version_id: str, *, actor: str, reason: str) -> None:
        if not actor or not reason:
            raise ValueError("actor and reason are required")
        with self.database.transaction(immediate=True) as connection:
            version = connection.execute(
                "SELECT * FROM knowledge_versions WHERE version_id = ?",
                (version_id,),
            ).fetchone()
            if version is None:
                raise AppError(
                    code="KNOWLEDGE_NOT_FOUND",
                    message="知识版本不存在",
                    recoverable=True,
                    suggested_action="请检查知识版本 ID。",
                )
            knowledge_id = str(version["knowledge_id"])
            connection.execute(
                "UPDATE knowledge_versions SET status = ? WHERE version_id = ?",
                (KnowledgeStatus.DISABLED.value, version_id),
            )
            connection.execute(
                "UPDATE knowledge_chunks SET status = ? WHERE version_id = ?",
                (KnowledgeStatus.DISABLED.value, version_id),
            )
            connection.execute(
                """
                UPDATE knowledge_documents
                SET status = ?, current_version_id = NULL, updated_at = ?
                WHERE knowledge_id = ? AND current_version_id = ?
                """,
                (
                    KnowledgeStatus.DISABLED.value,
                    _timestamp(_now()),
                    knowledge_id,
                    version_id,
                ),
            )
            self._delete_fts_version(connection, version_id)
            self._increment_generation(connection)
            self._audit(
                connection,
                knowledge_id,
                version_id,
                "disable",
                actor,
                reason,
            )

    def get_document(self, knowledge_id: str) -> KnowledgeDocument | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM knowledge_documents WHERE knowledge_id = ?",
                (knowledge_id,),
            ).fetchone()
        return self._document(row) if row else None

    def get_version(self, version_id: str) -> KnowledgeVersion | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT * FROM knowledge_versions WHERE version_id = ?",
                (version_id,),
            ).fetchone()
        return self._version(row) if row else None

    def get_chunks(self, version_id: str) -> list[KnowledgeChunk]:
        with self.database.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM knowledge_chunks WHERE version_id = ? "
                "ORDER BY chunk_index",
                (version_id,),
            ).fetchall()
        return [self._chunk(row) for row in rows]

    def list_versions(self, knowledge_id: str) -> list[KnowledgeVersion]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM knowledge_versions
                WHERE knowledge_id = ?
                ORDER BY version_number DESC, version_id
                """,
                (knowledge_id,),
            ).fetchall()
        return [self._version(row) for row in rows]

    def get_case_profile(self, version_id: str) -> CaseProfile | None:
        with self.database.connect() as connection:
            row = connection.execute(
                "SELECT profile_json FROM knowledge_case_profiles WHERE version_id = ?",
                (version_id,),
            ).fetchone()
        return CaseProfile.model_validate_json(row[0]) if row else None

    def list_documents(
        self,
        *,
        status: KnowledgeStatus | None = None,
        knowledge_type: KnowledgeType | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[KnowledgeDocument], int]:
        if offset < 0 or not 1 <= limit <= 100:
            raise ValueError("invalid knowledge page")
        clauses: list[str] = []
        parameters: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            parameters.append(status.value)
        if knowledge_type is not None:
            clauses.append("knowledge_type = ?")
            parameters.append(knowledge_type.value)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.database.connect() as connection:
            total = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM knowledge_documents {where}", parameters
                ).fetchone()[0]
            )
            rows = connection.execute(
                f"""
                SELECT * FROM knowledge_documents {where}
                ORDER BY updated_at DESC, knowledge_id
                LIMIT ? OFFSET ?
                """,
                [*parameters, limit, offset],
            ).fetchall()
        return [self._document(row) for row in rows], total

    async def keyword_search(
        self, query: KnowledgeQuery, *, limit: int
    ) -> list[RetrievalCandidate]:
        return self.keyword_search_sync(query, limit=limit)

    def keyword_search_sync(
        self, query: KnowledgeQuery, *, limit: int
    ) -> list[RetrievalCandidate]:
        if not 1 <= limit <= 100:
            raise ValueError("keyword search limit must be between 1 and 100")
        terms = [*query.keywords]
        if not terms:
            terms = [query.query_text]
        expression = " OR ".join(
            f'"{term.replace(chr(34), chr(34) * 2)}"'
            for term in terms
            if len(term.strip()) >= 3
        )
        if not expression:
            return []
        type_clause = ""
        parameters: list[object] = [expression]
        if query.knowledge_types:
            placeholders = ",".join("?" for _ in query.knowledge_types)
            type_clause = f" AND d.knowledge_type IN ({placeholders})"
            parameters.extend(item.value for item in query.knowledge_types)
        parameters.append(limit * 3)
        with self.database.connect() as connection:
            rows = connection.execute(
                f"""
                SELECT c.*, d.title, d.knowledge_type, d.authority,
                       d.applicability_json, v.source_name,
                       bm25(knowledge_chunks_fts) AS keyword_score
                FROM knowledge_chunks_fts f
                JOIN knowledge_chunks c ON c.chunk_id = f.chunk_id
                JOIN knowledge_documents d ON d.knowledge_id = c.knowledge_id
                JOIN knowledge_versions v ON v.version_id = c.version_id
                WHERE knowledge_chunks_fts MATCH ?
                  AND c.status = 'approved'
                  AND d.status = 'approved'
                  AND v.status = 'approved'
                  {type_clause}
                ORDER BY keyword_score ASC, c.chunk_id ASC
                LIMIT ?
                """,
                parameters,
            ).fetchall()
        candidates = [
            self._candidate(row, keyword_rank=index + 1)
            for index, row in enumerate(rows)
        ]
        applicable = [
            item for item in candidates if self._direction_matches(item, query)
        ]
        return applicable[:limit]

    async def vector_search(
        self,
        query: KnowledgeQuery,
        vector: Sequence[float],
        *,
        limit: int,
    ) -> list[RetrievalCandidate]:
        if not 1 <= limit <= 100:
            raise ValueError("vector search limit must be between 1 and 100")
        from packetmaster.rag.embedding import normalize_vector

        try:
            normalized = normalize_vector(
                vector, expected_dimension=self.embedding_dimension
            )
        except ValueError as exc:
            raise AppError(
                code="INVALID_QUERY_VECTOR",
                message="query vector dimension or value is invalid",
                recoverable=True,
                suggested_action="请使用与知识索引相同的 Embedding 模型。",
            ) from exc
        rows = self._approved_vectors(len(normalized))
        scored: list[tuple[float, dict[str, object]]] = []
        for row, stored in rows:
            pairs = zip(normalized, stored, strict=True)
            score = sum(left * right for left, right in pairs)
            scored.append((score, row))
        scored.sort(key=lambda item: (-item[0], str(item[1]["chunk_id"])))
        candidates = [
            self._candidate(
                row,
                vector_rank=index + 1,
                semantic_score=max(0.0, min(1.0, (score + 1.0) / 2.0)),
            )
            for index, (score, row) in enumerate(scored[: limit * 3])
        ]
        applicable = [
            item for item in candidates if self._direction_matches(item, query)
        ]
        return applicable[:limit]

    async def get_candidate(self, chunk_id: str) -> RetrievalCandidate | None:
        with self.database.connect() as connection:
            row = connection.execute(
                """
                SELECT c.*, d.title, d.knowledge_type, d.authority,
                       d.applicability_json, v.source_name
                FROM knowledge_chunks c
                JOIN knowledge_documents d ON d.knowledge_id = c.knowledge_id
                JOIN knowledge_versions v ON v.version_id = c.version_id
                WHERE c.chunk_id = ? AND c.status = 'approved'
                  AND d.status = 'approved' AND v.status = 'approved'
                """,
                (chunk_id,),
            ).fetchone()
        return self._candidate(row) if row else None

    def _approved_vectors(
        self, dimension: int
    ) -> list[tuple[dict[str, object], tuple[float, ...]]]:
        from packetmaster.rag.embedding import decode_vector

        with self.database.connect() as connection:
            generation = int(
                connection.execute(
                    "SELECT value FROM knowledge_metadata "
                    "WHERE key = 'index_generation'"
                ).fetchone()[0]
            )
            if (
                self._vector_cache is not None
                and self._vector_cache[0] == generation
                and self._vector_cache[1] == dimension
            ):
                return self._vector_cache[2]
            model_clause = ""
            parameters: list[object] = [dimension]
            if self.embedding_model:
                model_clause = " AND e.model_name = ?"
                parameters.append(self.embedding_model)
            records = connection.execute(
                f"""
                SELECT c.*, d.title, d.knowledge_type, d.authority,
                       d.applicability_json, v.source_name,
                       e.vector, e.dimension, e.model_name
                FROM knowledge_embeddings e
                JOIN knowledge_chunks c ON c.chunk_id = e.chunk_id
                JOIN knowledge_documents d ON d.knowledge_id = c.knowledge_id
                JOIN knowledge_versions v ON v.version_id = c.version_id
                WHERE c.status = 'approved' AND d.status = 'approved'
                  AND v.status = 'approved' AND e.dimension = ?
                  {model_clause}
                ORDER BY c.chunk_id
                """,
                parameters,
            ).fetchall()
        decoded = [
            (dict(row), decode_vector(row["vector"], int(row["dimension"])))
            for row in records
        ]
        self._vector_cache = (generation, dimension, decoded)
        return decoded

    @staticmethod
    def _document(row: sqlite3.Row) -> KnowledgeDocument:
        return KnowledgeDocument(
            knowledge_id=row["knowledge_id"],
            title=row["title"],
            knowledge_type=row["knowledge_type"],
            language=row["language"],
            authority=row["authority"],
            status=row["status"],
            summary=row["summary"],
            applicability=json.loads(row["applicability_json"]),
            current_version_id=row["current_version_id"],
        )

    @staticmethod
    def _version(row: sqlite3.Row) -> KnowledgeVersion:
        return KnowledgeVersion(
            version_id=row["version_id"],
            knowledge_id=row["knowledge_id"],
            version_number=row["version_number"],
            source_name=row["source_name"],
            source_location=row["source_location"],
            content_hash=row["content_hash"],
            status=row["status"],
            created_at=_datetime(row["created_at"]),
            valid_from=_datetime(row["valid_from"]),
            valid_to=_datetime(row["valid_to"]),
            approved_at=_datetime(row["approved_at"]),
            approved_by=row["approved_by"],
            supersedes_version_id=row["supersedes_version_id"],
        )

    @staticmethod
    def _chunk(row: sqlite3.Row) -> KnowledgeChunk:
        return KnowledgeChunk(
            chunk_id=row["chunk_id"],
            knowledge_id=row["knowledge_id"],
            version_id=row["version_id"],
            chunk_index=row["chunk_index"],
            heading_path=json.loads(row["heading_path_json"]),
            source_location=row["source_location"],
            content=row["content"],
            content_hash=row["content_hash"],
            status=row["status"],
        )

    @staticmethod
    def _candidate(
        row: sqlite3.Row | dict[str, object],
        *,
        keyword_rank: int | None = None,
        vector_rank: int | None = None,
        semantic_score: float = 0.0,
    ) -> RetrievalCandidate:
        rank = keyword_rank or vector_rank
        return RetrievalCandidate(
            knowledge_id=row["knowledge_id"],
            version_id=row["version_id"],
            chunk_id=row["chunk_id"],
            title=row["title"],
            knowledge_type=row["knowledge_type"],
            authority=row["authority"],
            status=row["status"],
            source_name=row["source_name"],
            source_location=row["source_location"],
            applicability=json.loads(row["applicability_json"]),
            content=row["content"],
            keyword_rank=keyword_rank,
            vector_rank=vector_rank,
            fusion_score=(1 / (60 + rank)) if rank else 0,
            rerank_score=semantic_score or ((1 / (60 + rank)) if rank else 0),
        )

    @staticmethod
    def _direction_matches(
        candidate: RetrievalCandidate, query: KnowledgeQuery
    ) -> bool:
        directions = candidate.applicability.directions
        return not directions or query.direction in directions

    @staticmethod
    def _delete_fts_version(
        connection: sqlite3.Connection, version_id: str
    ) -> None:
        chunk_ids = connection.execute(
            "SELECT chunk_id FROM knowledge_chunks WHERE version_id = ?",
            (version_id,),
        ).fetchall()
        connection.executemany(
            "DELETE FROM knowledge_chunks_fts WHERE chunk_id = ?",
            [(row[0],) for row in chunk_ids],
        )

    @staticmethod
    def _increment_generation(connection: sqlite3.Connection) -> None:
        connection.execute(
            """
            UPDATE knowledge_metadata
            SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT)
            WHERE key = 'index_generation'
            """
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        knowledge_id: str,
        version_id: str | None,
        action: str,
        actor: str,
        reason: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO knowledge_audit_events (
                knowledge_id, version_id, action, actor, reason, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                knowledge_id,
                version_id,
                action,
                actor,
                reason,
                _timestamp(_now()),
            ),
        )
