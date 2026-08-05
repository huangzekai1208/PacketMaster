"""为 Web API 提供有界的报告、指标、TCP 流和证据读取。"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from packetmaster.analyzer.base import validate_evidence_request
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.config import Settings
from packetmaster.domain import (
    DiagnosticReport,
    EvidenceField,
    EvidenceRequest,
    EvidenceResponse,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.web.contracts import (
    AnalysisDetail,
    FlowSummary,
    MetricSeries,
    Page,
    ReportResult,
)
from packetmaster.web.tasks import AnalysisTaskRepository

_MAX_JSON_BYTES = 16 * 1024 * 1024
_METRIC_KEYS = {
    "packet_count",
    "payload_bytes",
    "flow_count",
    "window_min",
    "window_max",
    "retransmission_count",
    "duplicate_ack_count",
    "out_of_order_count",
    "zero_window_count",
    "window_full_count",
    "time_start",
    "time_end",
    "duration_seconds",
    "throughput_mbps",
    "interval_start",
    "interval_end",
}
_EVIDENCE_KEYS = {field.value for field in EvidenceField} | {
    "evidence_id",
    "event_type",
    "flow_id",
    "direction",
}


class AnalysisReadService:
    def __init__(
        self,
        settings: Settings,
        tasks: AnalysisTaskRepository,
        *,
        adapter: Any | None = None,
    ) -> None:
        self.settings = settings
        self.tasks = tasks
        self.artifact_root = settings.artifact_root.expanduser().resolve()
        self.adapter = adapter or RealAnalyzerAdapter(
            artifact_root=self.artifact_root,
            pipeline_script=settings.speed_analyzer_script,
            tshark_path=settings.tshark_path,
            evidence_timeout_seconds=settings.evidence_timeout_seconds,
        )

    def detail(self, analysis_id: str) -> AnalysisDetail:
        analysis = self._analysis(analysis_id)
        private = self.tasks.private_details(analysis_id) or {}
        report_path = private.get("report_path")
        try:
            error_details = json.loads(str(private.get("error_details_json") or "{}"))
        except (TypeError, ValueError, json.JSONDecodeError):
            error_details = {}
        if not isinstance(error_details, dict):
            error_details = {}
        return AnalysisDetail(
            analysis=analysis,
            report_available=bool(
                report_path and self._safe_path(report_path).is_file()
            ),
            recoverable=bool(private.get("recoverable", False)),
            error_message=str(private.get("error_message") or ""),
            suggested_action=str(private.get("suggested_action") or ""),
            error_details=error_details,
        )

    def report(self, analysis_id: str) -> ReportResult:
        self._analysis(analysis_id)
        path = self._report_path(analysis_id)
        report = DiagnosticReport.model_validate(self._read_object(path))
        return ReportResult(analysis_id=analysis_id, report=report)

    def metrics(self, analysis_id: str) -> MetricSeries:
        self._analysis(analysis_id)
        data = self._read_object(self._artifact_dir(analysis_id) / "tcp_analysis.json")
        intervals = [
            _safe_metrics(item, interval=True)
            for item in data.get("interval_summary", [])[:5_000]
            if isinstance(item, dict)
        ]
        flows = self._flows(data)
        tcp = _safe_metrics(data.get("tcp_summary"))
        histogram = tcp.pop("rtt_histogram", [])
        return MetricSeries(
            tcp_summary=tcp,
            coverage_summary=_safe_coverage(data.get("coverage_summary")),
            intervals=intervals,
            rtt_histogram=histogram,
            top_flows=[item.model_dump(mode="json") for item in flows[:256]],
            downsampled=len(data.get("interval_summary", [])) > 5_000,
        )

    def flows(
        self,
        analysis_id: str,
        *,
        offset: int = 0,
        limit: int = 50,
        direction: Target | None = None,
        sort_by: str = "throughput_mbps",
        descending: bool = True,
    ) -> Page[FlowSummary]:
        self._analysis(analysis_id)
        data = self._read_object(self._artifact_dir(analysis_id) / "tcp_analysis.json")
        flows = self._flows(data)
        if direction is not None and direction is not Target.BOTH:
            flows = [item for item in flows if item.direction is direction]
        allowed_sort = {
            "throughput_mbps",
            "payload_bytes",
            "packet_count",
            "retransmission_count",
        }
        if sort_by not in allowed_sort:
            raise _invalid_query("不支持的 TCP 流排序字段")
        flows.sort(key=lambda item: getattr(item, sort_by), reverse=descending)
        return Page(
            items=flows[offset : offset + limit],
            total=len(flows),
            offset=offset,
            limit=limit,
        )

    async def evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        self._analysis(request.analysis_id)
        validate_evidence_request(request)
        response = await self.adapter.get_evidence(request)
        if (
            response.analysis_id != request.analysis_id
            or len(response.items) > request.limit
        ):
            raise AppError(
                code="INVALID_EVIDENCE_OUTPUT",
                message="证据响应与当前分析不匹配",
                recoverable=False,
                suggested_action="请重新运行分析并生成证据索引。",
            )
        return response.model_copy(
            update={
                "items": [_safe_evidence_item(item) for item in response.items],
                "summary": {"returned": len(response.items)},
                "source": (
                    "sqlite" if response.source.endswith(".sqlite") else "adapter"
                ),
            }
        )

    def _analysis(self, analysis_id: str):
        analysis = self.tasks.get(analysis_id)
        if analysis is None:
            raise AppError(
                code="ANALYSIS_NOT_FOUND",
                message="分析任务不存在",
                recoverable=True,
                suggested_action="请刷新会话后重新选择任务。",
            )
        return analysis

    def _report_path(self, analysis_id: str) -> Path:
        private = self.tasks.private_details(analysis_id) or {}
        value = private.get("report_path")
        if not value:
            raise AppError(
                code="REPORT_NOT_READY",
                message="诊断报告尚未生成",
                recoverable=True,
                suggested_action="请等待任务完成后重试。",
            )
        path = self._safe_path(value)
        if not path.is_file():
            raise AppError(
                code="REPORT_NOT_FOUND",
                message="诊断报告产物不存在",
                recoverable=True,
                suggested_action="请重试该分析任务。",
            )
        return path

    def _artifact_dir(self, analysis_id: str) -> Path:
        path = (self.artifact_root / analysis_id).resolve()
        if not path.is_relative_to(self.artifact_root):
            raise _invalid_artifact()
        return path

    def _safe_path(self, value: object) -> Path:
        path = Path(str(value)).expanduser().resolve()
        if not path.is_relative_to(self.artifact_root):
            raise _invalid_artifact()
        return path

    def _read_object(self, path: Path) -> dict[str, Any]:
        try:
            if path.stat().st_size > _MAX_JSON_BYTES:
                raise ValueError("artifact exceeds size limit")
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            raise _invalid_artifact() from exc
        if not isinstance(value, dict):
            raise _invalid_artifact()
        return value

    def _flows(self, data: dict[str, Any]) -> list[FlowSummary]:
        output: list[FlowSummary] = []
        raw = data.get("flow_summary")
        if not isinstance(raw, dict):
            return output
        for flow_id, metrics in raw.items():
            if not isinstance(flow_id, str) or not isinstance(metrics, dict):
                continue
            direction = metrics.get("direction", "download")
            try:
                target = Target(direction)
            except ValueError:
                continue
            output.append(
                FlowSummary(
                    flow_id=flow_id[:512],
                    direction=target,
                    **{
                        key: value
                        for key in FlowSummary.model_fields
                        if key not in {"flow_id", "direction"}
                        and (value := metrics.get(key)) is not None
                    },
                )
            )
        return output


def _safe_metrics(value: object, *, interval: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output = {
        key: item
        for key in _METRIC_KEYS
        if (item := value.get(key)) is not None
        and isinstance(item, int | float)
        and not isinstance(item, bool)
    }
    direction = value.get("direction")
    if direction in {"download", "upload", "both"}:
        output["direction"] = direction
    histogram = value.get("rtt_histogram")
    if isinstance(histogram, list):
        output["rtt_histogram"] = [
            {
                "upper_bound_ms": bucket.get("upper_bound_ms"),
                "count": bucket.get("count"),
            }
            for bucket in histogram[:64]
            if isinstance(bucket, dict)
            and isinstance(bucket.get("count"), int)
            and (
                bucket.get("upper_bound_ms") == "inf"
                or isinstance(bucket.get("upper_bound_ms"), int | float)
            )
        ]
    return output


def _safe_coverage(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        key: value[key]
        for key in (
            "input_size_bytes",
            "total_packets_seen",
            "tcp_packets_seen",
            "speed_packets_analyzed",
            "analyzed_bytes",
            "analyzed_duration_seconds",
            "complete",
            "truncated",
        )
        if isinstance(value.get(key), int | float | bool)
    }


def _safe_evidence_item(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        key: item
        for key, item in value.items()
        if key in _EVIDENCE_KEYS and isinstance(item, str | int | float | bool)
    }


def _invalid_artifact() -> AppError:
    return AppError(
        code="INVALID_ANALYSIS_ARTIFACT",
        message="分析产物缺失、损坏或超出安全边界",
        recoverable=True,
        suggested_action="请重试分析任务。",
    )


def _invalid_query(message: str) -> AppError:
    return AppError(
        code="INVALID_QUERY",
        message=message,
        recoverable=True,
        suggested_action="请修改筛选或排序条件后重试。",
    )
