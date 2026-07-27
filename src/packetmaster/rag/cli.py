"""Typer commands for review-first local knowledge management."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.rag.contracts import (
    AuthorityLevel,
    KnowledgeStatus,
    KnowledgeType,
)
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.embedding import EmbeddingIndexer, LocalEmbeddingProvider
from packetmaster.rag.evaluation import RagEvaluator, load_evaluation_cases
from packetmaster.rag.importer import ImportMetadata, KnowledgeImporter
from packetmaster.rag.retrieval import HybridKnowledgeRetriever

knowledge_app = typer.Typer(help="管理 PacketMaster RAG 知识库")


def _database(settings: Settings) -> KnowledgeDatabase:
    database = KnowledgeDatabase(settings.knowledge_database_path)
    database.initialize()
    return database


def _embedding_provider(settings: Settings) -> LocalEmbeddingProvider:
    return LocalEmbeddingProvider(
        settings.embedding_model,
        model_path=settings.embedding_model_path,
    )


def _error(exc: Exception) -> None:
    if isinstance(exc, AppError):
        error = exc
        code = 2
    else:
        error = AppError(
            code="KNOWLEDGE_COMMAND_FAILED",
            message="知识库命令执行失败",
            recoverable=True,
            suggested_action="请检查输入、知识库状态和 RAG 依赖。",
            details={"exception_type": exc.__class__.__name__},
        )
        code = 1
    typer.echo(json.dumps(error.to_dict(), ensure_ascii=False), err=True)
    raise typer.Exit(code=code) from exc


@knowledge_app.command(name="import")
def import_command(
    path: Annotated[Path, typer.Argument(help="Markdown、文本或 JSON 案例路径")],
    knowledge_id: Annotated[str, typer.Option("--knowledge-id")],
    title: Annotated[str, typer.Option("--title")],
    knowledge_type: Annotated[KnowledgeType, typer.Option("--type")],
    authority: Annotated[AuthorityLevel, typer.Option("--authority")],
    source_name: Annotated[str, typer.Option("--source-name")],
    source_location: Annotated[str, typer.Option("--source-location")] = "",
    language: Annotated[str, typer.Option("--language")] = "zh-CN",
    summary: Annotated[str, typer.Option("--summary")] = "",
    version: Annotated[int, typer.Option("--version", min=1)] = 1,
    ack_risk: Annotated[bool, typer.Option("--ack-risk")] = False,
) -> None:
    try:
        metadata = ImportMetadata(
            knowledge_id=knowledge_id,
            title=title,
            knowledge_type=knowledge_type,
            authority=authority,
            source_name=source_name,
            source_location=source_location,
            language=language,
            summary=summary,
            version_number=version,
        )
        preview = KnowledgeImporter().preview(path, metadata)
        typer.echo(
            f"导入预览：{preview.document.knowledge_id} "
            f"版本 {preview.version.version_number}，{len(preview.chunks)} 个切片"
        )
        if preview.risk_flags:
            typer.echo("风险标记：" + "、".join(preview.risk_flags))
        if preview.requires_risk_acknowledgement and not ack_risk:
            raise AppError(
                code="KNOWLEDGE_RISK_ACK_REQUIRED",
                message="知识内容存在风险标记，需要显式确认",
                recoverable=True,
                suggested_action="审核原文后使用 --ack-risk 重新导入。",
            )
        store = SQLiteKnowledgeStore(_database(Settings.load()))
        store.save_draft(
            preview.document,
            preview.version,
            preview.chunks,
            case_profile=preview.case_profile,
        )
        typer.echo(f"知识草稿已保存：{preview.version.version_id}")
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="list")
def list_command(
    status: Annotated[KnowledgeStatus | None, typer.Option("--status")] = None,
    knowledge_type: Annotated[
        KnowledgeType | None, typer.Option("--type")
    ] = None,
    offset: Annotated[int, typer.Option("--offset", min=0)] = 0,
    limit: Annotated[int, typer.Option("--limit", min=1, max=100)] = 50,
) -> None:
    try:
        store = SQLiteKnowledgeStore(_database(Settings.load()))
        items, total = store.list_documents(
            status=status,
            knowledge_type=knowledge_type,
            offset=offset,
            limit=limit,
        )
        typer.echo(f"知识总数：{total}")
        for item in items:
            typer.echo(
                f"{item.knowledge_id}\t{item.status.value}\t"
                f"{item.knowledge_type.value}\t{item.title}"
            )
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="show")
def show_command(
    knowledge_id: Annotated[str, typer.Argument(help="知识 ID")],
) -> None:
    try:
        store = SQLiteKnowledgeStore(_database(Settings.load()))
        document = store.get_document(knowledge_id)
        if document is None:
            raise AppError(
                code="KNOWLEDGE_NOT_FOUND",
                message="知识不存在",
                recoverable=True,
                suggested_action="请使用 pkm knowledge list 检查知识 ID。",
            )
        versions = store.list_versions(knowledge_id)
        payload = {
            "document": document.model_dump(mode="json"),
            "versions": [item.model_dump(mode="json") for item in versions],
            "chunk_counts": {
                item.version_id: len(store.get_chunks(item.version_id))
                for item in versions
            },
        }
        typer.echo(json.dumps(payload, ensure_ascii=False, indent=2))
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="approve")
def approve_command(
    version_id: Annotated[str, typer.Argument(help="知识版本 ID")],
    reviewer: Annotated[str, typer.Option("--reviewer")],
) -> None:
    try:
        settings = Settings.load()
        database = _database(settings)
        provider = _embedding_provider(settings)
        store = SQLiteKnowledgeStore(
            database,
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
        indexed = asyncio.run(
            EmbeddingIndexer(store, provider).index_version(version_id)
        )
        store.publish_version(version_id, approved_by=reviewer)
        typer.echo(f"知识版本已发布：{version_id}（新增索引 {indexed} 个）")
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="disable")
def disable_command(
    version_id: Annotated[str, typer.Argument(help="知识版本 ID")],
    actor: Annotated[str, typer.Option("--actor")],
    reason: Annotated[str, typer.Option("--reason")],
) -> None:
    try:
        store = SQLiteKnowledgeStore(_database(Settings.load()))
        store.disable_version(version_id, actor=actor, reason=reason)
        typer.echo(f"知识版本已停用：{version_id}")
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="reindex")
def reindex_command(
    version_id: Annotated[str, typer.Argument(help="知识版本 ID")],
    force: Annotated[bool, typer.Option("--force")] = False,
) -> None:
    try:
        settings = Settings.load()
        provider = _embedding_provider(settings)
        store = SQLiteKnowledgeStore(
            _database(settings),
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
        indexed = asyncio.run(
            EmbeddingIndexer(store, provider).index_version(version_id, force=force)
        )
        typer.echo(f"向量索引已更新：{version_id}（处理 {indexed} 个）")
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="health")
def health_command() -> None:
    try:
        database = _database(Settings.load())
        with database.connect() as connection:
            documents = int(
                connection.execute(
                    "SELECT COUNT(*) FROM knowledge_documents"
                ).fetchone()[0]
            )
            approved = int(
                connection.execute(
                    "SELECT COUNT(*) FROM knowledge_documents "
                    "WHERE status = 'approved'"
                ).fetchone()[0]
            )
            generation = connection.execute(
                "SELECT value FROM knowledge_metadata WHERE key = 'index_generation'"
            ).fetchone()[0]
        typer.echo(
            "知识库状态正常；FTS5 可用；"
            f"文档 {documents}，已发布 {approved}，索引代次 {generation}"
        )
    except Exception as exc:
        _error(exc)


@knowledge_app.command(name="evaluate")
def evaluate_command(
    dataset: Annotated[Path, typer.Argument(help="脱敏后的 JSON 评估集")],
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    try:
        settings = Settings.load()
        database = _database(settings)
        provider = _embedding_provider(settings)
        store = SQLiteKnowledgeStore(
            database,
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
        retriever = HybridKnowledgeRetriever(
            store,
            provider,
            keyword_top_k=settings.rag_keyword_top_k,
            vector_top_k=settings.rag_vector_top_k,
            final_top_k=settings.rag_final_top_k,
            max_context_bytes=settings.rag_max_context_bytes,
            timeout_seconds=settings.rag_timeout_seconds,
        )
        cases = load_evaluation_cases(dataset)
        report = asyncio.run(RagEvaluator(retriever).evaluate(cases))
        store.record_evaluation(report)
        rendered = json.dumps(
            report.model_dump(mode="json"), ensure_ascii=False, indent=2
        )
        if output is not None:
            destination = output.expanduser().resolve()
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(rendered + "\n", encoding="utf-8")
            typer.echo(f"评估报告已保存：{destination}")
        typer.echo(rendered)
        if not report.production_ready:
            typer.echo("当前评估尚未达到 active 模式启用门槛。")
    except Exception as exc:
        _error(exc)
