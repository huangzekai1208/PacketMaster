"""FastMCP server exposing only structured PacketMaster operations."""

from __future__ import annotations

from typing import Any

from fastmcp import FastMCP

from packetmaster.analyzer.base import AnalyzerAdapter
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.config import Settings
from packetmaster.domain import AnalyzeRequest, EvidenceRequest


def create_server(adapter: AnalyzerAdapter) -> FastMCP:
    server = FastMCP("packetmaster")

    @server.tool(name="analyze_speed_capture")
    async def analyze_speed_capture(request: dict[str, Any]) -> dict[str, Any]:
        parsed = AnalyzeRequest.model_validate(request)
        return (await adapter.analyze(parsed)).model_dump(mode="json")

    @server.tool(name="get_tcp_evidence")
    async def get_tcp_evidence(request: dict[str, Any]) -> dict[str, Any]:
        parsed = EvidenceRequest.model_validate(request)
        return (await adapter.get_evidence(parsed)).model_dump(mode="json")

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
