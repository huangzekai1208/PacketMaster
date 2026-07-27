"""Shared diagnosis orchestration for CLI and future Web interfaces."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.artifacts import ArtifactManager
from packetmaster.config import Settings
from packetmaster.context import ContextBuilder, DiagnosisContext
from packetmaster.domain import AnalyzeResponse, DiagnosticReport, Target
from packetmaster.errors import AppError
from packetmaster.graph import build_graph
from packetmaster.mcp.client import SpeedMCPClient
from packetmaster.mcp.server import create_server
from packetmaster.model import DiagnosisModel
from packetmaster.rag.runtime import build_rag_runtime
from packetmaster.report import write_report


@dataclass(frozen=True)
class DiagnosisProgress:
    fraction: float | None
    message: str | None


ProgressHandler = Callable[[DiagnosisProgress], Awaitable[None] | None]


@dataclass(frozen=True)
class DiagnosisOutcome:
    report: DiagnosticReport
    error: AppError | None = None
    analysis: AnalyzeResponse | None = None
    context: DiagnosisContext | None = None
    report_path: Path | None = None


class DiagnosisService:
    """Run one diagnosis without depending on a user-interface framework."""

    def __init__(
        self,
        settings: Settings,
        *,
        adapter: Any | None = None,
        diagnosis_model: Any | None = None,
        context_builder: Any | None = None,
        server_factory: Callable[[Any], Any] = create_server,
        client_factory: Callable[..., Any] = SpeedMCPClient,
        graph_factory: Callable[..., Any] = build_graph,
        artifact_manager: ArtifactManager | None = None,
        rag_runtime: Any | None = None,
    ) -> None:
        self.settings = settings
        self.adapter = adapter or RealAnalyzerAdapter(
            artifact_root=settings.artifact_root,
            pipeline_script=settings.speed_analyzer_script,
            tshark_path=settings.tshark_path,
            evidence_timeout_seconds=settings.evidence_timeout_seconds,
        )
        self.diagnosis_model = diagnosis_model or DiagnosisModel(settings=settings)
        self.context_builder = context_builder or ContextBuilder()
        self.server_factory = server_factory
        self.client_factory = client_factory
        self.graph_factory = graph_factory
        self.artifact_manager = artifact_manager or ArtifactManager(
            settings.artifact_root, settings.artifact_ttl_hours
        )
        self.rag_runtime = (
            rag_runtime
            if rag_runtime is not None
            else build_rag_runtime(settings)
        )

    async def run(
        self,
        *,
        pcap_path: str,
        standard: float,
        actual: float,
        target: Target,
        request_id: str,
        progress_handler: ProgressHandler | None = None,
    ) -> DiagnosisOutcome:
        def progress(value: float | None, message: str | None):
            if progress_handler is None:
                return None
            return progress_handler(DiagnosisProgress(value, message))

        server = self.server_factory(self.adapter)
        async with self.client_factory(
            server, progress_callback=progress
        ) as client:
            graph = self.graph_factory(
                mcp_client=client,
                diagnosis_model=self.diagnosis_model,
                context_builder=self.context_builder,
                rag_runtime=self.rag_runtime,
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
        return self._finalize(result, request_id)

    def _finalize(self, result: dict[str, Any], request_id: str) -> DiagnosisOutcome:
        paths = self.artifact_manager.create(request_id)
        for event in result.get("trace", []):
            self.artifact_manager.append_trace(paths, event)

        report = DiagnosticReport.model_validate(result["report"])
        raw_analysis = result.get("analysis")
        analysis = (
            AnalyzeResponse.model_validate(raw_analysis)
            if raw_analysis is not None
            else None
        )
        raw_context = result.get("context")
        context = (
            DiagnosisContext.model_validate(raw_context)
            if raw_context is not None
            else None
        )
        error = _graph_error(result.get("error"))
        if error is not None and analysis is None:
            raise error

        write_report(report, paths.report_json)
        return DiagnosisOutcome(
            report=report,
            error=error,
            analysis=analysis,
            context=context,
            report_path=paths.report_json,
        )


def _graph_error(value: object) -> AppError | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise AppError(
            code="INVALID_GRAPH_OUTPUT",
            message="PacketMaster graph returned an invalid error",
            recoverable=False,
            suggested_action="Check the PacketMaster graph version.",
        )
    details = value.get("details")
    return AppError(
        code=str(value.get("code", "DIAGNOSIS_FAILED")),
        message=str(value.get("message", "Diagnosis failed")),
        recoverable=bool(value.get("recoverable", False)),
        suggested_action=str(
            value.get("suggested_action", "Inspect local artifacts and retry.")
        ),
        details=details if isinstance(details, dict) else {},
    )
