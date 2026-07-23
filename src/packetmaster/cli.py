"""PacketMaster command-line entry point."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Annotated

import typer

from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.artifacts import ArtifactManager, create_request_id
from packetmaster.config import Settings
from packetmaster.context import ContextBuilder
from packetmaster.domain import DiagnosticReport, Target
from packetmaster.errors import AppError
from packetmaster.graph import build_graph
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server
from packetmaster.model import DiagnosisModel
from packetmaster.report import render_terminal, write_report

app = typer.Typer(help="PacketMaster TCP 测速不达标诊断")


@app.callback()
def main() -> None:
    """PacketMaster TCP 测速不达标诊断。"""


async def run_diagnosis(
    *,
    pcap_path: str,
    standard: float,
    actual: float,
    target: Target,
    request_id: str,
    settings: Settings,
) -> DiagnosticReport:
    adapter = RealAnalyzerAdapter(
        artifact_root=settings.artifact_root,
        tshark_path=settings.tshark_path,
    )
    server = create_server(adapter)

    def progress(value: float | None, message: str | None) -> None:
        if message:
            typer.echo(f"[进度] {message}")

    async with SpeedMCPClient(server, progress_callback=progress) as client:
        graph = build_graph(
            mcp_client=client,
            diagnosis_model=DiagnosisModel(settings=settings),
            context_builder=ContextBuilder(),
        )
        result = await graph.ainvoke(
            {
                "request": {
                    "request_id": request_id,
                    "pcap_path": pcap_path,
                    "target": target.value,
                },
                "standard_bandwidth_mbps": standard,
                "actual_bandwidth_mbps": actual,
            }
        )
    graph_error = result.get("error")
    if graph_error is not None:
        if not isinstance(graph_error, dict):
            raise AppError(
                code="INVALID_GRAPH_OUTPUT",
                message="PacketMaster graph returned an invalid error",
                recoverable=False,
                suggested_action="Check the PacketMaster graph version.",
            )
        details = graph_error.get("details")
        raise AppError(
            code=str(graph_error.get("code", "DIAGNOSIS_FAILED")),
            message=str(graph_error.get("message", "Diagnosis failed")),
            recoverable=bool(graph_error.get("recoverable", False)),
            suggested_action=str(
                graph_error.get(
                    "suggested_action", "Inspect local artifacts and retry."
                )
            ),
            details=details if isinstance(details, dict) else {},
        )
    return DiagnosticReport.model_validate(result["report"])


@app.command()
def diagnose(
    pcap_path: Annotated[str, typer.Argument(help="pcap/pcapng 绝对路径")],
    standard: Annotated[float, typer.Option("--standard", min=0.000001)],
    actual: Annotated[float, typer.Option("--actual", min=0.000001)],
    target: Annotated[Target, typer.Option("--target")] = Target.DOWNLOAD,
    output_dir: Annotated[str | None, typer.Option("--output-dir")] = None,
    keep_artifacts: Annotated[bool, typer.Option("--keep-artifacts")] = False,
) -> None:
    try:
        settings = Settings.load()
        request_id = create_request_id()
        destination = (
            Path(output_dir).expanduser().resolve()
            if output_dir is not None
            else (settings.artifact_root / request_id).expanduser().resolve()
        )
        report = asyncio.run(
            run_diagnosis(
                pcap_path=pcap_path,
                standard=standard,
                actual=actual,
                target=target,
                request_id=request_id,
                settings=settings,
            )
        )
        report_path = write_report(report, destination / "report.json")
        if keep_artifacts:
            manager = ArtifactManager(
                settings.artifact_root, settings.artifact_ttl_hours
            )
            manager.mark_keep(manager.create(request_id))
        typer.echo(render_terminal(report))
        typer.echo(f"JSON 报告: {report_path}")
    except AppError as exc:
        typer.echo(json.dumps(exc.to_dict(), ensure_ascii=False), err=True)
        raise typer.Exit(code=2) from exc
    except Exception as exc:
        error = AppError(
            code="CLI_FAILED",
            message="PacketMaster CLI failed",
            recoverable=False,
            suggested_action="Inspect local configuration and retry.",
            details={"exception_type": exc.__class__.__name__},
        )
        typer.echo(json.dumps(error.to_dict(), ensure_ascii=False), err=True)
        raise typer.Exit(code=1) from exc


if __name__ == "__main__":
    app()
