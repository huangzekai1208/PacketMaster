"""Deterministic, review-first knowledge parsing and chunking."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from packetmaster.platform import is_absolute_path
from packetmaster.rag.contracts import (
    AuthorityLevel,
    CaseProfile,
    Identifier,
    KnowledgeApplicability,
    KnowledgeChunk,
    KnowledgeDocument,
    KnowledgeStatus,
    KnowledgeType,
    KnowledgeVersion,
    RagContract,
)

_SUPPORTED_SUFFIXES = {".md", ".markdown", ".txt", ".json"}
_PROMPT_INJECTION_PATTERNS = (
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:the\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"忽略(?:以上|之前|前面).{0,12}(?:指令|要求|提示)"),
    re.compile(r"(?:执行|运行).{0,12}(?:系统命令|shell|powershell)", re.IGNORECASE),
)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_EMAIL = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_CUSTOMER = re.compile(r"\b[A-Z0-9][A-Z0-9_-]{2,}-(?:CUSTOMER|CLIENT)\b")
_WORK_ORDER = re.compile(r"\b(?:INC|WO|TICKET)[-_]?\d{4,}\b", re.IGNORECASE)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _placeholder(kind: str, value: str) -> str:
    return f"<{kind}:{_digest(value)[:8]}>"


def redact_text(value: str) -> str:
    replacements = (
        (_IPV4, "IP"),
        (_EMAIL, "EMAIL"),
        (_CUSTOMER, "CUSTOMER"),
        (_WORK_ORDER, "WORK_ORDER"),
    )
    result = value
    for pattern, kind in replacements:
        result = pattern.sub(lambda match: _placeholder(kind, match.group(0)), result)
    return result


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _redact_value(item) for key, item in value.items()}
    return value


class ImportMetadata(RagContract):
    knowledge_id: Identifier
    title: str = Field(min_length=1, max_length=256)
    knowledge_type: KnowledgeType
    authority: AuthorityLevel
    source_name: str = Field(min_length=1, max_length=256)
    source_location: str = Field(default="", max_length=512)
    language: str = Field(default="zh-CN", min_length=2, max_length=32)
    summary: str = Field(default="", max_length=2_000)
    version_number: int = Field(default=1, ge=1)
    applicability: KnowledgeApplicability = Field(
        default_factory=KnowledgeApplicability
    )

    @field_validator("source_location")
    @classmethod
    def reject_local_source_path(cls, value: str) -> str:
        if value and is_absolute_path(value):
            raise ValueError("source_location must not contain a local absolute path")
        return value


class ImportPreview(RagContract):
    document: KnowledgeDocument
    version: KnowledgeVersion
    chunks: list[KnowledgeChunk] = Field(min_length=1, max_length=512)
    case_profile: CaseProfile | None = None
    warnings: list[str] = Field(default_factory=list, max_length=32)
    risk_flags: list[str] = Field(default_factory=list, max_length=16)
    requires_risk_acknowledgement: bool = False


class KnowledgeImporter:
    def __init__(
        self,
        *,
        max_file_bytes: int = 5 * 1024 * 1024,
        target_chunk_chars: int = 800,
        max_chunk_chars: int = 1_500,
        overlap_chars: int = 100,
    ) -> None:
        if not 1 <= overlap_chars < target_chunk_chars <= max_chunk_chars <= 8_000:
            raise ValueError("invalid knowledge chunk limits")
        self.max_file_bytes = max_file_bytes
        self.target_chunk_chars = target_chunk_chars
        self.max_chunk_chars = max_chunk_chars
        self.overlap_chars = overlap_chars

    def preview(self, path: Path, metadata: ImportMetadata) -> ImportPreview:
        source = path.expanduser()
        if source.suffix.lower() not in _SUPPORTED_SUFFIXES:
            raise ValueError("unsupported knowledge file type")
        size = source.stat().st_size
        if size < 1 or size > self.max_file_bytes:
            raise ValueError("knowledge file size is outside the allowed range")
        try:
            raw_text = source.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("knowledge files must use UTF-8 encoding") from exc
        risks = [
            "prompt_injection"
            for pattern in _PROMPT_INJECTION_PATTERNS
            if pattern.search(raw_text)
        ][:1]
        case_profile: CaseProfile | None = None
        if source.suffix.lower() == ".json":
            sections, case_profile = self._json_sections(raw_text, metadata)
        elif source.suffix.lower() in {".md", ".markdown"}:
            sections = self._markdown_sections(redact_text(raw_text))
        else:
            sections = self._text_sections(redact_text(raw_text))
        chunks = self._chunks(sections, metadata)
        canonical = "\n\n".join(chunk.content for chunk in chunks)
        version_id = f"{metadata.knowledge_id}:v{metadata.version_number}"
        document = KnowledgeDocument(
            knowledge_id=metadata.knowledge_id,
            title=metadata.title,
            knowledge_type=metadata.knowledge_type,
            language=metadata.language,
            authority=metadata.authority,
            status=KnowledgeStatus.DRAFT,
            summary=redact_text(metadata.summary),
            applicability=metadata.applicability,
        )
        version = KnowledgeVersion(
            version_id=version_id,
            knowledge_id=metadata.knowledge_id,
            version_number=metadata.version_number,
            source_name=redact_text(metadata.source_name),
            source_location=metadata.source_location,
            content_hash=_digest(canonical),
            status=KnowledgeStatus.DRAFT,
            created_at=datetime.now(UTC),
        )
        normalized_chunks = [
            chunk.model_copy(update={"version_id": version_id}) for chunk in chunks
        ]
        warnings = []
        if len(chunks) >= 512:
            warnings.append("切片数量达到单文档上限")
        return ImportPreview(
            document=document,
            version=version,
            chunks=normalized_chunks,
            case_profile=case_profile,
            warnings=warnings,
            risk_flags=risks,
            requires_risk_acknowledgement=bool(risks),
        )

    def _json_sections(
        self, raw_text: str, metadata: ImportMetadata
    ) -> tuple[list[tuple[list[str], str]], CaseProfile | None]:
        try:
            value = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid JSON knowledge document") from exc
        if not isinstance(value, dict):
            raise ValueError("JSON knowledge document must be an object")
        sanitized = _redact_value(value)
        if metadata.knowledge_type is not KnowledgeType.CASE:
            content = json.dumps(sanitized, ensure_ascii=False, indent=2)
            return [([metadata.title], content)], None
        case_profile = CaseProfile.model_validate(
            {
                **sanitized,
                "applicability": metadata.applicability.model_dump(mode="json"),
            }
        )
        fields = (
            ("现象", case_profile.anomaly_summaries),
            ("TCP 特征", case_profile.tcp_features),
            ("已确认主因", case_profile.confirmed_primary_cause),
            ("候选原因", case_profile.candidate_causes),
            ("支持证据", case_profile.supporting_evidence),
            ("反向证据", case_profile.contradicting_evidence),
            ("外部因素", case_profile.external_factors),
            ("处置结果", case_profile.resolution),
        )
        sections = [
            (
                [metadata.title, heading],
                json.dumps(content, ensure_ascii=False, indent=2)
                if isinstance(content, dict | list)
                else str(content),
            )
            for heading, content in fields
            if content not in (None, "", [], {})
        ]
        return sections, case_profile

    @staticmethod
    def _markdown_sections(value: str) -> list[tuple[list[str], str]]:
        headings: list[str] = []
        sections: list[tuple[list[str], str]] = []
        body: list[str] = []
        for line in value.splitlines():
            match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
            if match:
                if any(item.strip() for item in body):
                    sections.append((list(headings), "\n".join(body).strip()))
                level = len(match.group(1))
                headings = [*headings[: level - 1], match.group(2).strip()]
                body = []
            else:
                body.append(line)
        if any(item.strip() for item in body):
            sections.append((list(headings), "\n".join(body).strip()))
        return sections or [([], value.strip())]

    @staticmethod
    def _text_sections(value: str) -> list[tuple[list[str], str]]:
        paragraphs = [
            item.strip()
            for item in re.split(r"\n\s*\n", value)
            if item.strip()
        ]
        return [([], paragraph) for paragraph in paragraphs]

    def _chunks(
        self,
        sections: list[tuple[list[str], str]],
        metadata: ImportMetadata,
    ) -> list[KnowledgeChunk]:
        pieces: list[tuple[list[str], str]] = []
        for headings, content in sections:
            for piece in self._split_content(content):
                if piece.strip():
                    pieces.append((headings or [metadata.title], piece.strip()))
        if not pieces:
            raise ValueError("knowledge document contains no usable content")
        if len(pieces) > 512:
            raise ValueError("knowledge document produces more than 512 chunks")
        version_id = f"{metadata.knowledge_id}:v{metadata.version_number}"
        return [
            KnowledgeChunk(
                chunk_id=f"{version_id}:chunk-{index}",
                knowledge_id=metadata.knowledge_id,
                version_id=version_id,
                chunk_index=index,
                heading_path=headings,
                source_location=(
                    f"{metadata.source_location} / {' / '.join(headings)}"
                    if metadata.source_location
                    else " / ".join(headings)
                )[:512],
                content=content,
                content_hash=_digest(content),
                status=KnowledgeStatus.DRAFT,
            )
            for index, (headings, content) in enumerate(pieces)
        ]

    def _split_content(self, content: str) -> list[str]:
        if len(content) <= self.max_chunk_chars:
            return [content]
        paragraphs = re.split(r"(?<=\n)\s*\n|(?<=[。！？.!?])\s+", content)
        chunks: list[str] = []
        current = ""
        for paragraph in paragraphs:
            if not paragraph:
                continue
            if len(paragraph) > self.max_chunk_chars:
                if current:
                    chunks.append(current)
                    current = ""
                step = self.max_chunk_chars - self.overlap_chars
                chunks.extend(
                    paragraph[start : start + self.max_chunk_chars]
                    for start in range(0, len(paragraph), step)
                )
                continue
            candidate = f"{current}\n\n{paragraph}".strip() if current else paragraph
            if len(candidate) > self.target_chunk_chars and current:
                chunks.append(current)
                prefix = current[-self.overlap_chars :]
                current = f"{prefix}\n\n{paragraph}".strip()
            else:
                current = candidate
        if current:
            chunks.append(current)
        return chunks
