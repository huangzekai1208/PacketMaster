"""FastMCP 标准输入输出或进程内传输的类型化客户端封装。"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from fastmcp import Client
from fastmcp.client.transports import StdioTransport

from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
)
from packetmaster.errors import AppError

ProgressCallback = Callable[[float | None, str | None], Awaitable[None] | None]


class SpeedMCPClient:
    def __init__(
        self,
        transport: Any,
        *,
        progress_callback: ProgressCallback | None = None,
        timeout: float | None = None,
    ) -> None:
        self._client = Client(
            transport,
            progress_handler=self._on_progress,
            timeout=timeout,
        )
        self._progress_callback = progress_callback

    @classmethod
    def from_stdio(
        cls,
        command: str,
        args: list[str],
        *,
        cwd: str | None = None,
        log_file: str | None = None,
        progress_callback: ProgressCallback | None = None,
        timeout: float | None = None,
    ) -> SpeedMCPClient:
        """Build a stdio client from an executable and argument array."""
        if not command or any(not isinstance(arg, str) for arg in args):
            raise ValueError("stdio command and arguments must be strings")
        transport = StdioTransport(
            command=command,
            args=list(args),
            cwd=cwd,
            log_file=Path(log_file) if log_file is not None else None,
        )
        return cls(
            transport,
            progress_callback=progress_callback,
            timeout=timeout,
        )

    async def _on_progress(
        self, progress: float, total: float | None, message: str | None
    ) -> None:
        if self._progress_callback is None:
            return
        value = None if total in (None, 0) else progress / total
        result = self._progress_callback(value, message)
        if result is not None:
            await result

    async def __aenter__(self) -> SpeedMCPClient:
        await self._client.__aenter__()
        return self

    async def __aexit__(self, exc_type: object, exc: object, traceback: object) -> None:
        await self._client.__aexit__(exc_type, exc, traceback)

    @staticmethod
    def _data(result: Any) -> dict[str, Any]:
        if getattr(result, "is_error", False):
            raise AppError(
                code="MCP_TOOL_ERROR",
                message="FastMCP tool returned an error",
                recoverable=True,
                suggested_action="Inspect the tool error and retry if appropriate.",
            )
        data = getattr(result, "data", None)
        if not isinstance(data, dict):
            structured = getattr(result, "structured_content", None)
            data = structured
        if not isinstance(data, dict):
            raise AppError(
                code="INVALID_MCP_OUTPUT",
                message="FastMCP tool returned an invalid structured result",
                recoverable=False,
                suggested_action="Check the PacketMaster MCP server version.",
            )
        if data.get("ok") is False:
            error = data.get("error")
            if not isinstance(error, dict):
                raise AppError(
                    code="INVALID_MCP_OUTPUT",
                    message="FastMCP returned an invalid error envelope",
                    recoverable=False,
                    suggested_action="Check the PacketMaster MCP server version.",
                )
            raise AppError(
                code=str(error.get("code", "MCP_TOOL_ERROR")),
                message=str(error.get("message", "FastMCP tool failed")),
                recoverable=bool(error.get("recoverable", False)),
                suggested_action=str(
                    error.get("suggested_action", "Inspect the MCP server log.")
                ),
                details=dict(error.get("details") or {}),
            )
        if data.get("ok") is True:
            payload = data.get("data")
            if not isinstance(payload, dict):
                raise AppError(
                    code="INVALID_MCP_OUTPUT",
                    message="FastMCP returned an invalid success envelope",
                    recoverable=False,
                    suggested_action="Check the PacketMaster MCP server version.",
                )
            return payload
        return data

    async def analyze_speed_capture(self, request: AnalyzeRequest) -> AnalyzeResponse:
        try:
            result = await self._client.call_tool(
                "analyze_speed_capture", {"request": request.model_dump(mode="json")}
            )
        except Exception as exc:
            raise AppError(
                code="MCP_TOOL_ERROR",
                message="FastMCP analyze tool failed",
                recoverable=True,
                suggested_action="Inspect the MCP server log and retry.",
            ) from exc
        try:
            return AnalyzeResponse.model_validate(self._data(result))
        except Exception as exc:
            if isinstance(exc, AppError):
                raise
            raise AppError(
                code="INVALID_MCP_OUTPUT",
                message="MCP analyze response does not match AnalyzeResponse",
                recoverable=False,
                suggested_action="Check the PacketMaster MCP server output.",
            ) from exc

    async def get_tcp_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        try:
            result = await self._client.call_tool(
                "get_tcp_evidence", {"request": request.model_dump(mode="json")}
            )
        except Exception as exc:
            raise AppError(
                code="MCP_TOOL_ERROR",
                message="FastMCP evidence tool failed",
                recoverable=True,
                suggested_action="Inspect the MCP server log and retry.",
            ) from exc
        try:
            return EvidenceResponse.model_validate(self._data(result))
        except Exception as exc:
            if isinstance(exc, AppError):
                raise
            raise AppError(
                code="INVALID_MCP_OUTPUT",
                message="MCP evidence response does not match EvidenceResponse",
                recoverable=False,
                suggested_action="Check the PacketMaster MCP server output.",
            ) from exc
