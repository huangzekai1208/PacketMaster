"""FastAPI application factory for the local PacketMaster Web service."""

from __future__ import annotations

import shutil
import uuid
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException

from packetmaster.config import Settings
from packetmaster.errors import AppError
from packetmaster.web.contracts import (
    ApiError,
    ErrorEnvelope,
    HealthStatus,
    SuccessEnvelope,
)
from packetmaster.web.database import WebDatabase

_LOOPBACK_HOSTS = {"127.0.0.1", "localhost"}


def create_app(
    settings: Settings | None = None, *, testing: bool = False
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

    return app


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
    if code in {"ANALYSIS_ALREADY_ACTIVE", "CAPTURE_IN_USE"}:
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
