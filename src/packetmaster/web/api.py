"""PacketMaster 本机 FastAPI 服务工厂及公开 Web API 路由。"""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, File, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException

from packetmaster.config import Settings
from packetmaster.domain import EvidenceRequest, EvidenceResponse, EvidenceType, Target
from packetmaster.errors import AppError
from packetmaster.llm_observability import (
    JsonlLLMCallObserver,
    LLMObservationCollector,
    LLMObservationSummary,
    load_llm_calls,
    summarize_llm_calls,
)
from packetmaster.model import DiagnosisModel
from packetmaster.rag.contracts import KnowledgeStatus, KnowledgeType
from packetmaster.rag.database import KnowledgeDatabase, SQLiteKnowledgeStore
from packetmaster.rag.embedding import EmbeddingIndexer, build_embedding_provider
from packetmaster.rag.importer import ImportMetadata, KnowledgeImporter
from packetmaster.rag.runtime import build_rag_runtime
from packetmaster.web.analysis import AnalysisReadService
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.chat_service import AnalysisChatService
from packetmaster.web.contracts import (
    AnalysisDetail,
    AnalysisSummary,
    ApiError,
    ApproveKnowledgeRequest,
    CaptureSummary,
    ChatRequest,
    ChatTurnResult,
    ConfirmAnalysisRequest,
    ConversationResult,
    CreateSessionRequest,
    DeleteResult,
    DisableKnowledgeRequest,
    ErrorEnvelope,
    FlowSummary,
    HealthStatus,
    KnowledgeDetail,
    KnowledgeEvaluationStatus,
    KnowledgeImportPreview,
    KnowledgeImportRequest,
    KnowledgeMutationResult,
    KnowledgeSummary,
    KnowledgeVersionSummary,
    MetricSeries,
    Page,
    RegisterCaptureRequest,
    ReindexKnowledgeRequest,
    ReportResult,
    SessionDetail,
    SessionSummary,
    SubmitMessageRequest,
    SuccessEnvelope,
)
from packetmaster.web.conversation import WebConversationService
from packetmaster.web.database import (
    ChatTurnRepository,
    MessageRepository,
    PendingIntentRepository,
    SessionRepository,
    WebDatabase,
)
from packetmaster.web.tasks import AnalysisTaskRepository

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}
_MAX_CAPTURE_UPLOAD_BYTES = 5 * 1024 * 1024 * 1024


def create_app(
    settings: Settings | None = None,
    *,
    testing: bool = False,
    conversation_model=None,
    static_directory: Path | None = None,
) -> FastAPI:
    runtime = settings or Settings.load()
    database = WebDatabase(runtime.web_database_path)
    database.initialize()
    app = FastAPI(
        title="PacketMaster Web API",
        version=_version(),
        docs_url="/docs" if testing else None,
        redoc_url=None,
    )
    app.state.settings = runtime
    app.state.database = database
    # 浏览器无法把本机绝对路径交给服务端；所选报文统一落入受管目录。
    capture_upload_root = (
        runtime.artifact_root / "web-captures"
    ).expanduser().resolve()
    llm_calls_path = (
        runtime.artifact_root / "llm-observability" / "llm_calls.jsonl"
    ).expanduser().resolve()
    llm_observer = (
        LLMObservationCollector(JsonlLLMCallObserver(llm_calls_path))
        if runtime.llm_observability_enabled
        else None
    )
    model = conversation_model or DiagnosisModel(
        settings=runtime, observer=llm_observer
    )
    if conversation_model is not None and isinstance(model, DiagnosisModel):
        model.observer = llm_observer or model.observer
    conversation = WebConversationService(
        sessions=SessionRepository(database),
        messages=MessageRepository(database),
        intents=PendingIntentRepository(database),
        captures=CaptureRegistry(
            CaptureRepository(database),
            allowed_roots=[*runtime.web_allowed_capture_roots, capture_upload_root],
        ),
        tasks=AnalysisTaskRepository(database),
        model=model,
        rag_runtime=build_rag_runtime(runtime),
        llm_observer=llm_observer,
    )
    app.state.conversation = conversation
    tasks = AnalysisTaskRepository(database)
    analysis_reads = AnalysisReadService(runtime, tasks)
    analysis_chat = AnalysisChatService(
        reads=analysis_reads,
        turns=ChatTurnRepository(database),
        model=conversation.model,
        rag_runtime=conversation.rag_runtime,
        llm_observer=llm_observer,
    )
    app.state.analysis_reads = analysis_reads
    app.state.analysis_chat = analysis_chat
    allowed_hosts = {*_LOOPBACK_HOSTS, *( ["testserver"] if testing else [])}

    def knowledge_store() -> tuple[KnowledgeDatabase, SQLiteKnowledgeStore]:
        knowledge_database = KnowledgeDatabase(runtime.knowledge_database_path)
        knowledge_database.initialize()
        return knowledge_database, SQLiteKnowledgeStore(knowledge_database)

    def import_preview(body: KnowledgeImportRequest):
        metadata = ImportMetadata(
            knowledge_id=body.knowledge_id,
            title=body.title,
            knowledge_type=body.knowledge_type,
            authority=body.authority,
            source_name=body.source_name,
            source_location=body.source_location,
            language=body.language,
            summary=body.summary,
            version_number=body.version,
        )
        try:
            return KnowledgeImporter().preview_text(
                body.content, body.file_name, metadata
            )
        except ValueError as exc:
            raise AppError(
                code="KNOWLEDGE_IMPORT_INVALID",
                message="知识文件或导入元数据无效",
                recoverable=True,
                suggested_action="请检查文件格式、大小和导入字段后重试。",
            ) from exc

    def knowledge_summary(document) -> KnowledgeSummary:
        return KnowledgeSummary(
            knowledge_id=document.knowledge_id,
            title=document.title,
            knowledge_type=document.knowledge_type,
            authority=document.authority,
            status=document.status,
            language=document.language,
            summary=document.summary,
            current_version_id=document.current_version_id,
        )

    @app.middleware("http")
    async def local_security(request: Request, call_next):
        request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
        request.state.request_id = request_id[:128]
        host = request.url.hostname
        if host not in allowed_hosts:
            return _error_response(
                request,
                ApiError(
                    code="HOST_NOT_ALLOWED",
                    message="Web 服务只接受本机访问",
                    recoverable=False,
                    suggested_action="请通过 127.0.0.1 或 localhost 访问。",
                ),
                403,
            )
        origin = request.headers.get("origin")
        if origin and not _allowed_origin(origin, testing=testing):
            return _error_response(
                request,
                ApiError(
                    code="ORIGIN_NOT_ALLOWED",
                    message="请求来源不受信任",
                    recoverable=False,
                    suggested_action="请使用 PacketMaster 本机工作台。",
                ),
                403,
            )
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(AppError)
    async def app_error(request: Request, exc: AppError) -> JSONResponse:
        return _error_response(
            request,
            ApiError(
                code=exc.code,
                message=exc.message,
                recoverable=exc.recoverable,
                suggested_action=exc.suggested_action,
                details={
                    str(key): value
                    for key, value in exc.details.items()
                    if isinstance(value, str | int | float | bool) or value is None
                },
            ),
            _app_error_status(exc.code),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return _error_response(
            request,
            ApiError(
                code="INVALID_REQUEST",
                message="请求参数无效",
                recoverable=True,
                suggested_action="请检查输入后重试。",
                details={"error_count": len(exc.errors())},
            ),
            422,
        )

    @app.exception_handler(HTTPException)
    async def http_error(request: Request, exc: HTTPException) -> JSONResponse:
        code = "API_NOT_FOUND" if exc.status_code == 404 else "HTTP_ERROR"
        return _error_response(
            request,
            ApiError(
                code=code,
                message="请求的 API 不存在"
                if exc.status_code == 404
                else "HTTP 请求失败",
                recoverable=False,
                suggested_action="请刷新页面并重试。",
            ),
            exc.status_code,
        )

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        return _error_response(
            request,
            ApiError(
                code="WEB_INTERNAL_ERROR",
                message="PacketMaster Web 服务异常",
                recoverable=True,
                suggested_action="请稍后重试或重启本地服务。",
            ),
            500,
        )

    @app.get(
        "/api/health",
        response_model=SuccessEnvelope[HealthStatus],
        tags=["system"],
    )
    async def health(request: Request) -> SuccessEnvelope[HealthStatus]:
        return SuccessEnvelope(
            data=HealthStatus(
                version=_version(),
                model_configured=runtime.model_api_key is not None,
                model_cost_configured=(
                    runtime.model_input_cost_per_million_usd is not None
                    and runtime.model_output_cost_per_million_usd is not None
                ),
                tshark_configured=_tshark_available(runtime.tshark_path),
            ),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/llm-observability/summary",
        response_model=SuccessEnvelope[LLMObservationSummary],
        tags=["system"],
    )
    async def llm_observability_summary(
        request: Request,
        limit: int = Query(default=10_000, ge=1, le=100_000),
    ) -> SuccessEnvelope[LLMObservationSummary]:
        values = (
            load_llm_calls(llm_calls_path, limit=limit)
            if runtime.llm_observability_enabled
            else []
        )
        return SuccessEnvelope(
            data=summarize_llm_calls(values),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/knowledge",
        response_model=SuccessEnvelope[Page[KnowledgeSummary]],
        tags=["knowledge"],
    )
    async def list_knowledge(
        request: Request,
        status: KnowledgeStatus | None = None,
        knowledge_type: KnowledgeType | None = None,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> SuccessEnvelope[Page[KnowledgeSummary]]:
        _, store = knowledge_store()
        items, total = store.list_documents(
            status=status, knowledge_type=knowledge_type, offset=offset, limit=limit
        )
        return SuccessEnvelope(
            data=Page(
                items=[knowledge_summary(item) for item in items],
                total=total,
                offset=offset,
                limit=limit,
            ),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/knowledge/evaluation-status",
        response_model=SuccessEnvelope[KnowledgeEvaluationStatus],
        tags=["knowledge"],
    )
    async def knowledge_evaluation_status(
        request: Request,
    ) -> SuccessEnvelope[KnowledgeEvaluationStatus]:
        knowledge_database, store = knowledge_store()
        with knowledge_database.connect() as connection:
            row = connection.execute(
                "SELECT value FROM knowledge_metadata WHERE key = 'last_evaluation'"
            ).fetchone()
        report = json.loads(str(row[0])) if row else None
        requested = runtime.effective_rag_mode.value
        effective = requested
        if requested == "active" and not store.active_gate_passed():
            effective = "shadow"
        return SuccessEnvelope(
            data=KnowledgeEvaluationStatus(
                active_gate_passed=store.active_gate_passed(),
                requested_mode=requested,
                effective_mode=effective,
                last_report=report,
            ),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/knowledge/{knowledge_id}",
        response_model=SuccessEnvelope[KnowledgeDetail],
        tags=["knowledge"],
    )
    async def get_knowledge(
        knowledge_id: str, request: Request
    ) -> SuccessEnvelope[KnowledgeDetail]:
        _, store = knowledge_store()
        document = store.get_document(knowledge_id)
        if document is None:
            raise AppError(
                code="KNOWLEDGE_NOT_FOUND",
                message="知识不存在",
                recoverable=True,
                suggested_action="请刷新知识列表后重试。",
            )
        versions = store.list_versions(knowledge_id)
        return SuccessEnvelope(
            data=KnowledgeDetail(
                document=knowledge_summary(document),
                versions=[
                    KnowledgeVersionSummary(
                        version_id=item.version_id,
                        version_number=item.version_number,
                        source_name=item.source_name,
                        source_location=item.source_location,
                        status=item.status,
                        created_at=item.created_at,
                        approved_at=item.approved_at,
                        approved_by=item.approved_by,
                        chunk_count=len(store.get_chunks(item.version_id)),
                    )
                    for item in versions
                ],
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/knowledge/preview",
        response_model=SuccessEnvelope[KnowledgeImportPreview],
        tags=["knowledge"],
    )
    async def preview_knowledge(
        request: Request, body: KnowledgeImportRequest
    ) -> SuccessEnvelope[KnowledgeImportPreview]:
        preview = import_preview(body)
        return SuccessEnvelope(
            data=KnowledgeImportPreview(
                knowledge_id=preview.document.knowledge_id,
                version_id=preview.version.version_id,
                chunk_count=len(preview.chunks),
                risk_flags=preview.risk_flags,
                warnings=preview.warnings,
                requires_risk_acknowledgement=preview.requires_risk_acknowledgement,
                chunks=[
                    {
                        "chunk_id": item.chunk_id,
                        "heading_path": item.heading_path,
                        "content": item.content,
                    }
                    for item in preview.chunks[:16]
                ],
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/knowledge/import",
        response_model=SuccessEnvelope[KnowledgeMutationResult],
        tags=["knowledge"],
    )
    async def import_knowledge(
        request: Request, body: KnowledgeImportRequest
    ) -> SuccessEnvelope[KnowledgeMutationResult]:
        preview = import_preview(body)
        if preview.requires_risk_acknowledgement and not body.ack_risk:
            raise AppError(
                code="KNOWLEDGE_RISK_ACK_REQUIRED",
                message="知识内容包含风险标记，需要确认后才能保存草稿",
                recoverable=True,
                suggested_action="审核预览内容后确认风险提示。",
            )
        _, store = knowledge_store()
        store.save_draft(
            preview.document,
            preview.version,
            preview.chunks,
            case_profile=preview.case_profile,
        )
        return SuccessEnvelope(
            data=KnowledgeMutationResult(
                version_id=preview.version.version_id,
                status=KnowledgeStatus.DRAFT,
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/knowledge/versions/{version_id}/approve",
        response_model=SuccessEnvelope[KnowledgeMutationResult],
        tags=["knowledge"],
    )
    async def approve_knowledge(
        version_id: str, request: Request, body: ApproveKnowledgeRequest
    ) -> SuccessEnvelope[KnowledgeMutationResult]:
        knowledge_database, _ = knowledge_store()
        provider = build_embedding_provider(runtime)
        store = SQLiteKnowledgeStore(
            knowledge_database,
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
        indexed = await EmbeddingIndexer(store, provider).index_version(version_id)
        store.publish_version(version_id, approved_by=body.reviewer)
        return SuccessEnvelope(
            data=KnowledgeMutationResult(
                version_id=version_id,
                indexed_chunks=indexed,
                status=KnowledgeStatus.APPROVED,
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/knowledge/versions/{version_id}/disable",
        response_model=SuccessEnvelope[KnowledgeMutationResult],
        tags=["knowledge"],
    )
    async def disable_knowledge(
        version_id: str, request: Request, body: DisableKnowledgeRequest
    ) -> SuccessEnvelope[KnowledgeMutationResult]:
        _, store = knowledge_store()
        store.disable_version(version_id, actor=body.actor, reason=body.reason)
        return SuccessEnvelope(
            data=KnowledgeMutationResult(
                version_id=version_id, status=KnowledgeStatus.DISABLED
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/knowledge/versions/{version_id}/reindex",
        response_model=SuccessEnvelope[KnowledgeMutationResult],
        tags=["knowledge"],
    )
    async def reindex_knowledge(
        version_id: str, request: Request, body: ReindexKnowledgeRequest
    ) -> SuccessEnvelope[KnowledgeMutationResult]:
        knowledge_database, _ = knowledge_store()
        provider = build_embedding_provider(runtime)
        store = SQLiteKnowledgeStore(
            knowledge_database,
            embedding_model=provider.model_name,
            embedding_dimension=provider.dimension,
        )
        indexed = await EmbeddingIndexer(store, provider).index_version(
            version_id, force=body.force
        )
        version = store.get_version(version_id)
        return SuccessEnvelope(
            data=KnowledgeMutationResult(
                version_id=version_id,
                indexed_chunks=indexed,
                status=version.status if version else None,
            ),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/sessions",
        response_model=SuccessEnvelope[SessionSummary],
        tags=["sessions"],
    )
    async def create_session(
        request: Request, body: CreateSessionRequest
    ) -> SuccessEnvelope[SessionSummary]:
        return SuccessEnvelope(
            data=conversation.create_session(title=body.title),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/sessions",
        response_model=SuccessEnvelope[Page[SessionSummary]],
        tags=["sessions"],
    )
    async def list_sessions(
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> SuccessEnvelope[Page[SessionSummary]]:
        return SuccessEnvelope(
            data=conversation.list_sessions(offset=offset, limit=limit),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/sessions/{session_id}",
        response_model=SuccessEnvelope[SessionDetail],
        tags=["sessions"],
    )
    async def session_detail(
        session_id: str,
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=100, ge=1, le=100),
    ) -> SuccessEnvelope[SessionDetail]:
        return SuccessEnvelope(
            data=conversation.session_detail(
                session_id, offset=offset, limit=limit
            ),
            request_id=request.state.request_id,
        )

    @app.delete(
        "/api/sessions/{session_id}",
        response_model=SuccessEnvelope[DeleteResult],
        tags=["sessions"],
    )
    async def delete_session(
        session_id: str, request: Request
    ) -> SuccessEnvelope[DeleteResult]:
        return SuccessEnvelope(
            data=DeleteResult(deleted=conversation.delete_session(session_id)),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/sessions/{session_id}/messages",
        response_model=SuccessEnvelope[ConversationResult],
        tags=["messages"],
    )
    async def submit_message(
        session_id: str,
        body: SubmitMessageRequest,
        request: Request,
    ) -> SuccessEnvelope[ConversationResult]:
        result = await conversation.submit_message(
            session_id, content=body.content, capture_id=body.capture_id
        )
        return SuccessEnvelope(data=result, request_id=request.state.request_id)

    @app.post(
        "/api/sessions/{session_id}/confirm",
        response_model=SuccessEnvelope[AnalysisSummary],
        tags=["analyses"],
    )
    async def confirm_analysis(
        session_id: str,
        body: ConfirmAnalysisRequest,
        request: Request,
    ) -> SuccessEnvelope[AnalysisSummary]:
        del body
        return SuccessEnvelope(
            data=conversation.confirm(session_id),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/captures/register",
        response_model=SuccessEnvelope[CaptureSummary],
        tags=["captures"],
    )
    async def register_capture(
        body: RegisterCaptureRequest, request: Request
    ) -> SuccessEnvelope[CaptureSummary]:
        return SuccessEnvelope(
            data=conversation.register_capture(body.path),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/captures/upload",
        response_model=SuccessEnvelope[CaptureSummary],
        tags=["captures"],
    )
    async def upload_capture(
        request: Request, file: UploadFile = File(...)
    ) -> SuccessEnvelope[CaptureSummary]:
        original_name = Path(file.filename or "").name
        if not original_name or Path(original_name).suffix.casefold() not in {
            ".pcap",
            ".pcapng",
        }:
            raise AppError(
                code="UNSUPPORTED_CAPTURE_TYPE",
                message="只支持 pcap 和 pcapng 报文",
                recoverable=True,
                suggested_action="请选择后缀为 .pcap 或 .pcapng 的文件。",
            )
        # 使用随机文件名避免客户端文件名覆盖或路径穿越，原名只作为展示元数据。
        capture_upload_root.mkdir(parents=True, exist_ok=True)
        suffix = Path(original_name).suffix.casefold()
        destination = capture_upload_root / f"{uuid.uuid4().hex}{suffix}"
        total_bytes = 0
        try:
            with destination.open("xb") as output:
                # 分块落盘，避免将大报文整体读入 Web 进程内存。
                while chunk := await file.read(1024 * 1024):
                    total_bytes += len(chunk)
                    if total_bytes > _MAX_CAPTURE_UPLOAD_BYTES:
                        raise AppError(
                            code="CAPTURE_UPLOAD_TOO_LARGE",
                            message="报文文件超过 Web 上传大小限制",
                            recoverable=True,
                            suggested_action=(
                                "请使用较小的报文文件，或通过 CLI 注册本机路径。"
                            ),
                        )
                    output.write(chunk)
            if total_bytes == 0:
                raise AppError(
                    code="EMPTY_CAPTURE_UPLOAD",
                    message="报文文件为空",
                    recoverable=True,
                    suggested_action="请选择包含报文数据的 pcap 或 pcapng 文件。",
                )
            capture = conversation.captures.register_uploaded(
                destination, original_name=original_name
            )
        except AppError:
            # 无效或超限上传不保留半成品；成功注册后才由受管目录持久化。
            destination.unlink(missing_ok=True)
            raise
        except OSError as exc:
            destination.unlink(missing_ok=True)
            raise AppError(
                code="CAPTURE_UPLOAD_FAILED",
                message="报文文件上传失败",
                recoverable=True,
                suggested_action="请检查本机磁盘空间和文件读取权限后重试。",
            ) from exc
        finally:
            await file.close()
        return SuccessEnvelope(data=capture, request_id=request.state.request_id)

    @app.get(
        "/api/captures/recent",
        response_model=SuccessEnvelope[list[CaptureSummary]],
        tags=["captures"],
    )
    async def recent_captures(
        request: Request,
        limit: int = Query(default=20, ge=1, le=100),
    ) -> SuccessEnvelope[list[CaptureSummary]]:
        return SuccessEnvelope(
            data=conversation.captures.recent(limit=limit),
            request_id=request.state.request_id,
        )

    @app.delete(
        "/api/captures/{capture_id}",
        response_model=SuccessEnvelope[DeleteResult],
        tags=["captures"],
    )
    async def delete_capture(
        capture_id: str, request: Request
    ) -> SuccessEnvelope[DeleteResult]:
        deleted = conversation.captures.delete(capture_id)
        if not deleted:
            raise AppError(
                code="CAPTURE_REFERENCE_NOT_FOUND",
                message="报文引用不存在",
                recoverable=True,
                suggested_action="请刷新最近报文列表。",
            )
        return SuccessEnvelope(
            data=DeleteResult(deleted=True),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}",
        response_model=SuccessEnvelope[AnalysisDetail],
        tags=["analyses"],
    )
    async def analysis_detail(
        analysis_id: str, request: Request
    ) -> SuccessEnvelope[AnalysisDetail]:
        return SuccessEnvelope(
            data=analysis_reads.detail(analysis_id),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/analyses/{analysis_id}/cancel",
        response_model=SuccessEnvelope[AnalysisSummary],
        tags=["analyses"],
    )
    async def cancel_analysis(
        analysis_id: str, request: Request
    ) -> SuccessEnvelope[AnalysisSummary]:
        return SuccessEnvelope(
            data=tasks.request_cancel(analysis_id),
            request_id=request.state.request_id,
        )

    @app.post(
        "/api/analyses/{analysis_id}/retry",
        response_model=SuccessEnvelope[AnalysisSummary],
        tags=["analyses"],
    )
    async def retry_analysis(
        analysis_id: str, request: Request
    ) -> SuccessEnvelope[AnalysisSummary]:
        return SuccessEnvelope(
            data=tasks.retry(analysis_id),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}/report",
        response_model=SuccessEnvelope[ReportResult],
        tags=["reports"],
    )
    async def analysis_report(
        analysis_id: str, request: Request
    ) -> SuccessEnvelope[ReportResult]:
        return SuccessEnvelope(
            data=analysis_reads.report(analysis_id),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}/metrics",
        response_model=SuccessEnvelope[MetricSeries],
        tags=["reports"],
    )
    async def analysis_metrics(
        analysis_id: str, request: Request
    ) -> SuccessEnvelope[MetricSeries]:
        return SuccessEnvelope(
            data=analysis_reads.metrics(analysis_id),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}/flows",
        response_model=SuccessEnvelope[Page[FlowSummary]],
        tags=["reports"],
    )
    async def analysis_flows(
        analysis_id: str,
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=100),
        direction: Target | None = None,
        sort_by: str = "throughput_mbps",
        descending: bool = True,
    ) -> SuccessEnvelope[Page[FlowSummary]]:
        return SuccessEnvelope(
            data=analysis_reads.flows(
                analysis_id,
                offset=offset,
                limit=limit,
                direction=direction,
                sort_by=sort_by,
                descending=descending,
            ),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}/evidence",
        response_model=SuccessEnvelope[EvidenceResponse],
        tags=["evidence"],
    )
    async def analysis_evidence(
        analysis_id: str,
        request: Request,
        evidence_type: EvidenceType = EvidenceType.SUMMARY,
        flow_id: str | None = None,
        time_start: float | None = Query(default=None, ge=0),
        time_end: float | None = Query(default=None, ge=0),
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=500),
    ) -> SuccessEnvelope[EvidenceResponse]:
        result = await analysis_reads.evidence(
            EvidenceRequest(
                analysis_id=analysis_id,
                evidence_type=evidence_type,
                flow_id=flow_id,
                time_start=time_start,
                time_end=time_end,
                offset=offset,
                limit=limit,
            )
        )
        return SuccessEnvelope(data=result, request_id=request.state.request_id)

    @app.get("/api/analyses/{analysis_id}/events", tags=["events"])
    async def analysis_events(
        analysis_id: str,
        request: Request,
        after_event_id: int = Query(default=0, ge=0),
    ) -> StreamingResponse:
        analysis_reads.detail(analysis_id)
        header = request.headers.get("last-event-id")
        cursor = max(after_event_id, int(header) if header and header.isdigit() else 0)
        return StreamingResponse(
            _event_stream(request, tasks, analysis_id, cursor),
            media_type="text/event-stream",
            headers={"X-Accel-Buffering": "no"},
        )

    @app.post(
        "/api/analyses/{analysis_id}/chat",
        response_model=SuccessEnvelope[ChatTurnResult],
        tags=["chat"],
    )
    async def analysis_question(
        analysis_id: str, body: ChatRequest, request: Request
    ) -> SuccessEnvelope[ChatTurnResult]:
        return SuccessEnvelope(
            data=await analysis_chat.ask(analysis_id, body.question),
            request_id=request.state.request_id,
        )

    @app.get(
        "/api/analyses/{analysis_id}/chat",
        response_model=SuccessEnvelope[Page[ChatTurnResult]],
        tags=["chat"],
    )
    async def analysis_chat_history(
        analysis_id: str,
        request: Request,
        offset: int = Query(default=0, ge=0),
        limit: int = Query(default=50, ge=1, le=100),
    ) -> SuccessEnvelope[Page[ChatTurnResult]]:
        return SuccessEnvelope(
            data=analysis_chat.history(analysis_id, offset=offset, limit=limit),
            request_id=request.state.request_id,
        )

    @app.api_route(
        "/api/{unknown_path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        include_in_schema=False,
    )
    async def unknown_api(unknown_path: str) -> None:
        del unknown_path
        raise HTTPException(status_code=404)

    if not testing or static_directory is not None:
        static_root = static_directory or Path(__file__).with_name("static")
        if static_root.joinpath("index.html").is_file():
            app.mount("/", StaticFiles(directory=static_root, html=True), name="webui")

    return app


async def _event_stream(request, tasks, analysis_id: str, cursor: int):
    terminal = {
        "completed",
        "partial",
        "failed",
        "cancelled",
        "interrupted",
    }
    idle_ticks = 0
    while not await request.is_disconnected():
        events = tasks.events(analysis_id, after_event_id=cursor, limit=100)
        for event in events:
            cursor = event.event_id
            payload = json.dumps(event.model_dump(mode="json"), ensure_ascii=False)
            yield f"id: {cursor}\nevent: {event.event_type.value}\ndata: {payload}\n\n"
        current = tasks.get(analysis_id)
        if current is None or current.status.value in terminal:
            return
        idle_ticks += 1
        if idle_ticks % 30 == 0:
            yield ": heartbeat\n\n"
        await asyncio.sleep(0.5)


def _allowed_origin(value: str, *, testing: bool) -> bool:
    parsed = urlsplit(value)
    allowed = {*_LOOPBACK_HOSTS, *( ["testserver"] if testing else [])}
    return parsed.scheme in {"http", "https"} and parsed.hostname in allowed


def _error_response(
    request: Request, error: ApiError, status_code: int
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    envelope = ErrorEnvelope(error=error, request_id=request_id)
    response = JSONResponse(
        status_code=status_code,
        content=envelope.model_dump(mode="json"),
    )
    if request_id:
        response.headers["X-Request-ID"] = request_id
    return response


def _app_error_status(code: str) -> int:
    if code.endswith("_NOT_FOUND"):
        return 404
    if code in {
        "ANALYSIS_ALREADY_ACTIVE",
        "CAPTURE_IN_USE",
        "SESSION_IN_USE",
        "KNOWLEDGE_RISK_ACK_REQUIRED",
    }:
        return 409
    if code in {"INVALID_TASK_TRANSITION", "ANALYSIS_NOT_RETRYABLE"}:
        return 409
    return 400


def _tshark_available(value: str) -> bool:
    candidate = Path(value).expanduser()
    if candidate.is_absolute():
        return candidate.is_file()
    return shutil.which(value) is not None


def _version() -> str:
    try:
        return version("packetmaster")
    except PackageNotFoundError:
        return "0.1.0"
