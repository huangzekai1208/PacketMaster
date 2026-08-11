"""Deterministic generic TCP stall analysis built on the local TShark pipeline."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any

from packetmaster.analyzer.real import default_pipeline_script
from packetmaster.config import Settings
from packetmaster.domain import (
    CoverageSummary,
    Hypothesis,
    HypothesisType,
    Observability,
    StallDiagnosticReport,
)
from packetmaster.errors import AppError

ProgressCallback = Callable[[float | None, str], None]


@dataclass(frozen=True)
class StallAnalysisOutcome:
    report_path: Path
    partial: bool


class StallDiagnosisService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.artifact_root = settings.artifact_root.expanduser().resolve()
        self.pipeline_script = (
            (settings.speed_analyzer_script or default_pipeline_script())
            .expanduser()
            .resolve()
        )

    async def run(
        self,
        *,
        pcap_path: str,
        request_id: str,
        progress: ProgressCallback | None = None,
    ) -> StallAnalysisOutcome:
        output = (self.artifact_root / request_id).resolve()
        if not output.is_relative_to(self.artifact_root):
            raise _stall_error("INVALID_ANALYSIS_ID", "分析任务 ID 非法")
        output.mkdir(parents=True, exist_ok=True)
        if progress is not None:
            progress(0.05, "正在准备通用卡顿分析")
        command = [
            sys.executable,
            str(self.pipeline_script),
            "--input",
            pcap_path,
            "--target",
            "both",
            "--output",
            str(output),
            "--analysis-id",
            request_id,
            "--interval",
            "1",
            "--build-evidence-index",
            "--min-ratio",
            "0",
            "--min-bytes",
            "0",
        ]
        if self.settings.tshark_path:
            command.extend(["--tshark-path", self.settings.tshark_path])
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
        except OSError as exc:
            raise _stall_error(
                "STALL_ANALYZER_UNAVAILABLE", "无法启动通用卡顿分析器"
            ) from exc
        try:
            returncode = await process.wait()
        except asyncio.CancelledError:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5)
            except TimeoutError:
                process.kill()
                await process.wait()
            raise
        manifest = _read_object(output / "manifest.json")
        if returncode != 0 or manifest.get("status") == "failed":
            error = (
                manifest.get("error") if isinstance(manifest.get("error"), dict) else {}
            )
            code = str(error.get("code") or "STALL_ANALYSIS_FAILED")
            message = str(error.get("message") or "通用卡顿分析失败")
            if code in {"NO_TCP_PACKETS", "NO_SPEED_FLOW"}:
                message = "当前通用卡顿 MVP 未在报文中识别到可分析的 TCP 流"
            raise AppError(
                code=code,
                message=message,
                recoverable=True,
                suggested_action="确认抓包包含卡顿时段和 TCP 业务流后重试。",
            )
        if progress is not None:
            progress(0.8, "正在归纳卡顿事件和候选原因")
        summary = _read_object(output / "tcp_analysis.json")
        report = build_stall_report(request_id, summary, manifest)
        report_path = output / "stall_report.json"
        _atomic_write(report_path, report.model_dump(mode="json"))
        if progress is not None:
            progress(1.0, "通用卡顿分析完成")
        return StallAnalysisOutcome(
            report_path=report_path,
            partial=manifest.get("status") == "partial",
        )


def build_stall_report(
    analysis_id: str,
    summary: dict[str, Any],
    manifest: dict[str, Any],
) -> StallDiagnosticReport:
    coverage = CoverageSummary.model_validate(summary.get("coverage_summary", {}))
    tcp = (
        summary.get("tcp_summary")
        if isinstance(summary.get("tcp_summary"), dict)
        else {}
    )
    intervals = [
        item for item in summary.get("interval_summary", []) if isinstance(item, dict)
    ]
    flows = (
        summary.get("flow_summary")
        if isinstance(summary.get("flow_summary"), dict)
        else {}
    )
    events, throughput_drops, gaps = _stall_events(intervals)
    candidates: list[Hypothesis] = []

    retransmissions = _count(tcp, "retransmission_count")
    packets = max(1, _count(tcp, "packet_count"))
    if retransmissions >= 3 or retransmissions / packets >= 0.01:
        candidates.append(
            _hypothesis(
                "TCP 丢包或重传导致有效数据交付中断",
                min(95.0, 55.0 + retransmissions / packets * 1000),
                [f"检测到 {retransmissions} 个 TCP 重传事件"],
                "检查链路丢包、无线质量、接口错误和拥塞队列。",
                list(flows)[:16],
            )
        )
    zero_windows = _count(tcp, "zero_window_count")
    window_full = _count(tcp, "window_full_count")
    if zero_windows or window_full >= 3:
        candidates.append(
            _hypothesis(
                "接收端窗口受限或应用读取不及时",
                min(92.0, 62.0 + zero_windows * 3 + window_full),
                [
                    f"零窗口事件 {zero_windows} 个",
                    f"窗口满事件 {window_full} 个",
                ],
                "检查接收端应用处理能力、Socket 缓冲区和系统资源。",
                list(flows)[:16],
            )
        )
    rtt_upper = _high_rtt_upper_bound(tcp.get("rtt_histogram"))
    if rtt_upper is not None and rtt_upper >= 300:
        candidates.append(
            _hypothesis(
                "网络时延偏高或波动较大",
                min(88.0, 55.0 + rtt_upper / 20),
                [f"RTT 高位分布达到约 {rtt_upper:g} ms"],
                "对照卡顿时段检查路径时延、跨地域链路和队列拥塞。",
                list(flows)[:16],
            )
        )
    if throughput_drops:
        candidates.append(
            _hypothesis(
                "有效吞吐在卡顿窗口内显著下降",
                min(90.0, 58.0 + len(throughput_drops) * 4),
                [f"检测到 {len(throughput_drops)} 个吞吐突降区间"],
                "结合对应时间窗检查重传、RTT、窗口和服务端响应。",
                list(flows)[:16],
            )
        )
    if gaps:
        candidates.append(
            _hypothesis(
                "业务流存在较长的有效数据空洞",
                min(86.0, 52.0 + len(gaps) * 5),
                [f"检测到 {len(gaps)} 个超过 2 秒的数据空洞"],
                "确认空洞期间是否在等待服务端、DNS、应用调度或网络恢复。",
                list(flows)[:16],
                observability=Observability.INDIRECT,
            )
        )

    candidates.sort(key=lambda item: item.confidence, reverse=True)
    limitations = [
        "当前通用卡顿 MVP 主要分析 TCP 传输层时序，"
        "尚未覆盖 UDP、DNS、TLS SNI 和应用层播放器缓冲。",
        "仅凭报文无法直接证明用户界面发生卡顿，结论表示与卡顿一致的网络或业务等待现象。",
    ]
    if manifest.get("status") == "partial":
        limitations.append("报文分析覆盖不完整，候选原因置信度需要谨慎解释。")
    primary = candidates[0].cause if candidates else "未发现明确的 TCP 传输层卡顿原因"
    confidence = candidates[0].confidence if candidates else 30.0
    return StallDiagnosticReport(
        analysis_id=analysis_id,
        primary_cause=primary,
        candidate_causes=candidates,
        key_evidence=events[:32],
        confidence=confidence,
        coverage_summary=coverage,
        stall_events=events[:512],
        protocol_summary={
            "tcp_flow_count": len(flows),
            "tcp_packet_count": _count(tcp, "packet_count"),
            "retransmission_count": retransmissions,
            "zero_window_count": zero_windows,
            "window_full_count": window_full,
            "throughput_drop_count": len(throughput_drops),
            "data_gap_count": len(gaps),
        },
        limitations=limitations,
        troubleshooting_steps=[
            "先按卡顿事件时间窗定位受影响流。",
            "对照同一时间窗检查重传、RTT、接收窗口和吞吐变化。",
            "若 TCP 指标正常，继续采集 DNS、TLS、应用日志或播放器缓冲信息。",
        ],
        optimization_suggestions=[
            "抓包应覆盖卡顿前至少 10 秒、卡顿期间和恢复后至少 10 秒。",
            "尽量同时记录用户操作时间点和终端、服务端日志。",
        ],
        analysis_metadata={"analysis_mode": "stall", "analyzer": "generic-tcp-mvp"},
    )


def _stall_events(
    intervals: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    events: list[dict[str, Any]] = []
    drops: list[dict[str, Any]] = []
    gaps: list[dict[str, Any]] = []
    by_direction: dict[str, list[dict[str, Any]]] = {}
    for item in intervals:
        direction = str(item.get("direction", "unknown"))
        by_direction.setdefault(direction, []).append(item)
        abnormal = {
            key: _count(item, key)
            for key in (
                "retransmission_count",
                "duplicate_ack_count",
                "zero_window_count",
                "window_full_count",
            )
            if _count(item, key)
        }
        if abnormal:
            events.append(
                {
                    "event_type": "transport_anomaly",
                    "start_time": _number(item.get("interval_start")),
                    "end_time": _number(item.get("interval_end")),
                    "direction": direction,
                    "severity": "high"
                    if abnormal.get("zero_window_count")
                    else "medium",
                    "evidence": abnormal,
                }
            )
    for direction, items in by_direction.items():
        items.sort(key=lambda item: _number(item.get("interval_start")))
        positive = [
            _number(item.get("throughput_mbps"))
            for item in items
            if _number(item.get("throughput_mbps")) > 0
        ]
        baseline = median(positive) if positive else 0.0
        previous_end: float | None = None
        for item in items:
            start = _number(item.get("interval_start"))
            end = _number(item.get("interval_end"))
            throughput = _number(item.get("throughput_mbps"))
            if baseline > 0 and throughput < baseline * 0.35:
                event = {
                    "event_type": "throughput_drop",
                    "start_time": start,
                    "end_time": end,
                    "direction": direction,
                    "severity": "medium",
                    "evidence": {
                        "throughput_mbps": throughput,
                        "baseline_mbps": round(baseline, 4),
                    },
                }
                drops.append(event)
                events.append(event)
            if previous_end is not None and start - previous_end > 2:
                event = {
                    "event_type": "data_gap",
                    "start_time": previous_end,
                    "end_time": start,
                    "duration_seconds": start - previous_end,
                    "direction": direction,
                    "severity": "medium",
                }
                gaps.append(event)
                events.append(event)
            previous_end = max(previous_end or end, end)
    events.sort(key=lambda item: _number(item.get("start_time")))
    return events, drops, gaps


def _hypothesis(
    cause: str,
    confidence: float,
    evidence: list[str],
    suggestion: str,
    flows: list[str],
    *,
    observability: Observability = Observability.DIRECT,
) -> Hypothesis:
    return Hypothesis(
        cause=cause,
        hypothesis_type=HypothesisType.DATA_DISCOVERED,
        observability=observability,
        confidence=max(0.0, min(100.0, confidence)),
        supporting_evidence=evidence,
        affected_flows=flows,
        explanation="该原因由卡顿时间线附近的传输层聚合指标推断。",
        suggestion=suggestion,
    )


def _high_rtt_upper_bound(value: object) -> float | None:
    if not isinstance(value, list):
        return None
    buckets = [item for item in value if isinstance(item, dict)]
    total = sum(_count(item, "count") for item in buckets)
    if total <= 0:
        return None
    threshold = total * 0.95
    cumulative = 0
    for item in buckets:
        cumulative += _count(item, "count")
        if cumulative >= threshold:
            bound = item.get("upper_bound_ms")
            return 2000.0 if bound == "inf" else _number(bound)
    return None


def _count(value: object, key: str) -> int:
    if not isinstance(value, dict):
        return 0
    item = value.get(key, 0)
    return (
        int(item) if isinstance(item, int | float) and not isinstance(item, bool) else 0
    )


def _number(value: object) -> float:
    return (
        float(value)
        if isinstance(value, int | float) and not isinstance(value, bool)
        else 0.0
    )


def _read_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise _stall_error("INVALID_ANALYSIS_ARTIFACT", "卡顿分析产物不可用") from exc
    if not isinstance(value, dict):
        raise _stall_error("INVALID_ANALYSIS_ARTIFACT", "卡顿分析产物格式错误")
    return value


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def _stall_error(code: str, message: str) -> AppError:
    return AppError(
        code=code,
        message=message,
        recoverable=True,
        suggested_action="请检查报文和 TShark 配置后重试。",
    )
