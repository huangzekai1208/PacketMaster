"""FastMCP server exposing only structured PacketMaster operations."""

from __future__ import annotations

from typing import Any

from fastmcp import Context, FastMCP
from pydantic import ValidationError

from packetmaster.analyzer.base import AnalyzerAdapter
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.config import Settings
from packetmaster.domain import AnalyzeRequest, EvidenceRequest
from packetmaster.errors import AppError


def _error_envelope(error: AppError) -> dict[str, Any]:
    return {"ok": False, "error": error.to_dict()}


def _invalid_request(error: ValidationError) -> dict[str, Any]:
    return _error_envelope(
        AppError(
            code="INVALID_REQUEST",
            message="MCP request does not match the PacketMaster schema",
            recoverable=False,
            suggested_action="Correct the structured request and retry.",
            details={"validation": error.errors(include_url=False)},
        )
    )


def create_server(adapter: AnalyzerAdapter) -> FastMCP:
    server = FastMCP("packetmaster")

    @server.tool(name="analyze_speed_capture")
    async def analyze_speed_capture(
        request: dict[str, Any], context: Context
    ) -> dict[str, Any]:
        try:
            parsed = AnalyzeRequest.model_validate(request)

            async def progress(
                current: float, total: float | None, message: str | None
            ) -> None:
                await context.report_progress(current, total, message)

            result = await adapter.analyze(parsed, progress_callback=progress)
            return {"ok": True, "data": result.model_dump(mode="json")}
        except ValidationError as exc:
            return _invalid_request(exc)
        except AppError as exc:
            return _error_envelope(exc)
        except Exception as exc:
            return _error_envelope(
                AppError(
                    code="MCP_INTERNAL_ERROR",
                    message="PacketMaster analyze tool failed unexpectedly",
                    recoverable=False,
                    suggested_action="Inspect the MCP server log.",
                    details={"exception_type": exc.__class__.__name__},
                )
            )

    @server.tool(name="get_tcp_evidence")
    async def get_tcp_evidence(request: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed = EvidenceRequest.model_validate(request)
            result = await adapter.get_evidence(parsed)
            return {"ok": True, "data": result.model_dump(mode="json")}
        except ValidationError as exc:
            return _invalid_request(exc)
        except AppError as exc:
            return _error_envelope(exc)
        except Exception as exc:
            return _error_envelope(
                AppError(
                    code="MCP_INTERNAL_ERROR",
                    message="PacketMaster evidence tool failed unexpectedly",
                    recoverable=False,
                    suggested_action="Inspect the MCP server log.",
                    details={"exception_type": exc.__class__.__name__},
                )
            )

    return server


def create_default_server(settings: Settings | None = None) -> FastMCP:
    """Create the production server; tests should inject a Mock adapter."""
    runtime = settings or Settings.load()
    return create_server(
        RealAnalyzerAdapter(
            artifact_root=runtime.artifact_root,
            tshark_path=runtime.tshark_path,
        )
    )


def main() -> None:
    create_default_server().run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
