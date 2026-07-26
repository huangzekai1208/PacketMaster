"""FastAPI application factory for the local PacketMaster Web service."""

from __future__ import annotations

import asyncio
import json
import shutil
import uuid
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.exceptions import HTTPException

from packetmaster.config import Settings
from packetmaster.domain import EvidenceRequest, EvidenceResponse, EvidenceType, Target
from packetmaster.errors import AppError
from packetmaster.model import DiagnosisModel
from packetmaster.web.analysis import AnalysisReadService
from packetmaster.web.captures import CaptureRegistry, CaptureRepository
from packetmaster.web.chat_service import AnalysisChatService
from packetmaster.web.contracts import (
    AnalysisDetail,
    AnalysisSummary,
    ApiError,
    CaptureSummary,
    ChatRequest,
    ChatTurnResult,
    ConfirmAnalysisRequest,
    ConversationResult,
    CreateSessionRequest,
    DeleteResult,
    ErrorEnvelope,
    FlowSummary,
    HealthStatus,
    MetricSeries,
    Page,
    RegisterCaptureRequest,
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


def create_app(
    settings: Settings | None = None,
    *,
    testing: bool = False,
    conversation_model=None,
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
    conversation = WebConversationService(
        sessions=SessionRepository(database),
        messages=MessageRepository(database),
        intents=PendingIntentRepository(database),
        captures=CaptureRegistry(
            CaptureRepository(database),
            allowed_roots=runtime.web_allowed_capture_roots,
        ),
        tasks=AnalysisTaskRepository(database),
        model=conversation_model or DiagnosisModel(settings=runtime),
    )
    app.state.conversation = conversation
    tasks = AnalysisTaskRepository(database)
    analysis_reads = AnalysisReadService(runtime, tasks)
    analysis_chat = AnalysisChatService(
        reads=analysis_reads,
        turns=ChatTurnRepository(database),
        model=conversation.model,
    )
    app.state.analysis_reads = analysis_reads
    app.state.analysis_chat = analysis_chat
    allowed_hosts = {*_LOOPBACK_HOSTS, *( ["testserver"] if testing else [])}

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
                tshark_configured=_tshark_available(runtime.tshark_path),
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
    if code in {"ANALYSIS_ALREADY_ACTIVE", "CAPTURE_IN_USE", "SESSION_IN_USE"}:
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
