"""CLI 与 Web 共用的诊断编排层，不依赖具体用户界面。"""

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
from packetmaster.llm_observability import (
    LLMCallRecord,
    LLMObservationCollector,
    LLMObservationSummary,
    summarize_llm_calls,
)
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
    llm_calls_path: Path | None = None
    llm_call_count: int = 0
    llm_summary: LLMObservationSummary | None = None


class DiagnosisService:
    """执行一次诊断，并把流程产物收敛为可持久化的报告与审计轨迹。"""

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
        llm_observer: LLMObservationCollector | None = None,
    ) -> None:
        self.settings = settings
        self.adapter = adapter or RealAnalyzerAdapter(
            artifact_root=settings.artifact_root,
            pipeline_script=settings.speed_analyzer_script,
            tshark_path=settings.tshark_path,
            evidence_timeout_seconds=settings.evidence_timeout_seconds,
        )
        self.llm_observer = llm_observer or LLMObservationCollector()
        self.diagnosis_model = diagnosis_model or DiagnosisModel(
            settings=settings, observer=self.llm_observer
        )
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
        # MCP Server 与 Client 在一次调用内成对创建和关闭，避免跨任务共享状态。
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
            with self.llm_observer.scope(request_id) as llm_calls:
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
        return self._finalize(result, request_id, llm_calls=llm_calls)

    def _finalize(
        self,
        result: dict[str, Any],
        request_id: str,
        *,
        llm_calls: list[LLMCallRecord] | None = None,
    ) -> DiagnosisOutcome:
        # 无论诊断完整或部分完成，都先持久化 trace 和报告，便于后续排查。
        paths = self.artifact_manager.create(request_id)
        for event in result.get("trace", []):
            self.artifact_manager.append_trace(paths, event)
        for call in llm_calls or []:
            self.artifact_manager.append_llm_call(
                paths, call.model_dump(mode="json")
            )

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
            llm_calls_path=(paths.llm_calls_jsonl if llm_calls else None),
            llm_call_count=len(llm_calls or []),
            llm_summary=summarize_llm_calls(llm_calls or []),
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
