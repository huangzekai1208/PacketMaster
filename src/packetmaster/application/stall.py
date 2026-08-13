"""Deterministic multi-protocol stall analysis built on local TShark metadata."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from statistics import median
from typing import Any

from packetmaster.analyzer.real import default_pipeline_script
from packetmaster.application.stall_protocol import (
    extract_protocol_summary,
    find_tshark,
)
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

_CONTEXT_TERMS = {
    "video": ("视频", "直播", "播放器", "video", "stream"),
    "web": ("网页", "网站", "页面", "浏览器", "web", "http"),
    "download": ("下载", "文件", "下载速度", "download"),
    "game": ("游戏", "对战", "game", "fps"),
    "meeting": ("会议", "通话", "语音", "视频会议", "zoom", "teams"),
    "dns": ("dns", "解析", "域名"),
    "latency": ("延迟", "延时", "ping", "响应慢", "慢"),
    "buffering": ("卡顿", "缓冲", "转圈", "加载", "停顿", "黑屏"),
    "disconnect": ("断流", "断开", "掉线", "重连", "连接失败"),
}


def parse_stall_context(value: str) -> dict[str, Any]:
    text = " ".join(value.split()).strip()[:500]
    if text in {
        "请对所选报文进行通用卡顿分析",
        "请对所选报文进行通用分析",
    }:
        text = ""
    lowered = text.lower()
    tags = [
        tag
        for tag, terms in _CONTEXT_TERMS.items()
        if any(term.lower() in lowered for term in terms)
    ]
    requested_hosts = sorted(
        {
            match.group(1).lower().rstrip(".")
            for match in re.finditer(
                r"(?:https?://)?\b((?:[a-z0-9-]+\.)+[a-z]{2,63})\b",
                lowered,
            )
        }
    )[:8]
    if requested_hosts and "web" not in tags:
        tags.append("web")
    time_match = re.search(
        r"(?P<value>\d+(?:\.\d+)?)\s*(?P<unit>秒|s|分钟|min)(?:左右|附近|后)?",
        lowered,
    )
    time_offset_seconds: float | None = None
    if time_match:
        time_offset_seconds = float(time_match.group("value"))
        if time_match.group("unit") in {"分钟", "min"}:
            time_offset_seconds *= 60
    summary_parts = [context_tag_label(tag) for tag in tags]
    summary_parts.extend(requested_hosts)
    if time_offset_seconds is not None:
        summary_parts.append(f"约 {time_offset_seconds:g} 秒")
    return {
        "provided": bool(text),
        "summary": "、".join(summary_parts) if summary_parts else "未提供具体现象描述",
        "tags": tags,
        "specificity": "specific" if tags else "generic",
        "time_offset_seconds": time_offset_seconds,
        "requested_hosts": requested_hosts,
    }


def context_tag_label(tag: str) -> str:
    return {
        "video": "视频",
        "web": "网页",
        "download": "下载",
        "game": "游戏",
        "meeting": "会议/通话",
        "dns": "DNS",
        "latency": "高延迟",
        "buffering": "缓冲卡顿",
        "disconnect": "断流/重连",
    }.get(tag, tag)


def _match_context_endpoints(
    context: dict[str, Any], protocol: dict[str, Any]
) -> list[dict[str, Any]]:
    requested = set(context.get("requested_hosts", []))
    if not requested:
        return []
    matched = []
    for endpoint in _list_of_mappings(protocol.get("endpoint_summary")):
        names = {
            str(item).lower()
            for key in ("domains", "sni")
            for item in endpoint.get(key, [])
        }
        if requested & names:
            matched.append(
                {
                    "ip": endpoint.get("ip"),
                    "matched_hosts": sorted(requested & names),
                    "protocols": endpoint.get("protocols", []),
                }
            )
    return matched[:32]


def _prioritize_events(
    events: list[dict[str, Any]], context: dict[str, Any]
) -> list[dict[str, Any]]:
    offset = context.get("time_offset_seconds")
    if not isinstance(offset, int | float):
        return events
    return sorted(
        events,
        key=lambda event: abs(_number(event.get("start_time")) - float(offset)),
    )


def _personalize_candidates(
    candidates: list[Hypothesis], context: dict[str, Any]
) -> list[Hypothesis]:
    tags = set(context.get("tags", []))
    if not tags:
        return candidates
    boosts = {
        "video": ("吞吐", "数据空洞", "UDP", "QUIC", "HTTP"),
        "web": ("HTTP", "DNS", "响应", "TLS"),
        "download": ("吞吐", "TCP", "重传"),
        "game": ("UDP", "QUIC", "时延", "延迟"),
        "meeting": ("UDP", "QUIC", "时延", "丢包"),
        "dns": ("DNS", "解析"),
        "latency": ("时延", "响应", "RTT"),
        "buffering": ("卡顿", "吞吐", "空洞", "数据"),
        "disconnect": ("断流", "连接", "TLS", "重传"),
    }
    terms = tuple(term for tag in tags for term in boosts.get(tag, ()))
    adjusted: list[Hypothesis] = []
    for candidate in candidates:
        haystack = f"{candidate.cause} {candidate.explanation}"
        boost = 8.0 if any(term in haystack for term in terms) else 0.0
        if boost:
            adjusted.append(
                candidate.model_copy(
                    update={"confidence": min(100.0, candidate.confidence + boost)}
                )
            )
        else:
            adjusted.append(candidate)
    return adjusted


def _context_first_step(context: dict[str, Any]) -> str:
    time_offset = context.get("time_offset_seconds")
    prefix = (
        f"优先检查抓包开始后约 {time_offset:g} 秒附近；"
        if isinstance(time_offset, int | float)
        else ""
    )
    tags = context.get("tags", [])
    if "video" in tags or "buffering" in tags:
        return prefix + "按视频/播放器卡顿时间点对照吞吐、空洞、DNS 和 QUIC 事件。"
    if "web" in tags:
        return prefix + "按网页加载时间点对照 DNS、TLS、HTTP 响应和 TCP 传输事件。"
    if "game" in tags or "meeting" in tags:
        return prefix + "按实时业务时间点对照 UDP/QUIC 间断、时延和丢包迹象。"
    return prefix + "按卡顿事件时间窗定位受影响流。"


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
        symptom_context: str = "",
        progress: ProgressCallback | None = None,
    ) -> StallAnalysisOutcome:
        output = (self.artifact_root / request_id).resolve()
        if not output.is_relative_to(self.artifact_root):
            raise _stall_error("INVALID_ANALYSIS_ID", "分析任务 ID 非法")
        output.mkdir(parents=True, exist_ok=True)
        if progress is not None:
            progress(0.05, "正在准备通用卡顿分析")
        tshark_path = find_tshark(self.settings.tshark_path)
        protocol_task = asyncio.create_task(
            asyncio.to_thread(
                extract_protocol_summary,
                Path(pcap_path).expanduser().resolve(),
                tshark_path=tshark_path,
            )
        )
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
        command.extend(["--tshark-path", str(tshark_path)])
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
        try:
            protocol = await protocol_task
        except AppError as exc:
            protocol = {"extraction_error": exc.message}
        manifest = _read_object(output / "manifest.json")
        pipeline_failed = returncode != 0 or manifest.get("status") == "failed"
        if pipeline_failed:
            error = (
                manifest.get("error") if isinstance(manifest.get("error"), dict) else {}
            )
            code = str(error.get("code") or "STALL_ANALYSIS_FAILED")
            message = str(error.get("message") or "通用卡顿分析失败")
            packet_count = _count(protocol.get("capture_summary"), "packet_count")
            if code not in {"NO_TCP_PACKETS", "NO_SPEED_FLOW"} or packet_count == 0:
                raise AppError(
                    code=code,
                    message=message,
                    recoverable=True,
                    suggested_action="确认抓包包含卡顿时段的业务流后重试。",
                )
            manifest = {**manifest, "status": "partial"}
        if progress is not None:
            progress(0.8, "正在归纳卡顿事件和候选原因")
        summary = (
            _read_object(output / "tcp_analysis.json")
            if (output / "tcp_analysis.json").is_file()
            else {}
        )
        report = build_stall_report(
            request_id,
            summary,
            manifest,
            protocol,
            symptom_context=symptom_context,
        )
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
    protocol: dict[str, Any] | None = None,
    *,
    symptom_context: str = "",
) -> StallDiagnosticReport:
    protocol = protocol or {}
    user_context = parse_stall_context(symptom_context)
    user_context["matched_endpoints"] = _match_context_endpoints(user_context, protocol)
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
    events = _prioritize_events(events, user_context)
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

    dns = _mapping(protocol.get("dns_summary"))
    dns_latency = _mapping(dns.get("latency_ms"))
    dns_failures = _count(dns, "failure_count")
    dns_unanswered = _count(dns, "unanswered_count")
    dns_p95 = _number(dns_latency.get("p95"))
    if dns_failures or dns_unanswered:
        candidates.append(
            _hypothesis(
                "DNS 解析失败或请求未获得响应",
                min(94.0, 65.0 + dns_failures * 4 + dns_unanswered * 2),
                [f"DNS 失败响应 {dns_failures} 个", f"未响应查询 {dns_unanswered} 个"],
                "检查 DNS 服务器可达性、域名配置、缓存和上游解析链路。",
                [],
            )
        )
    elif dns_p95 >= 500:
        candidates.append(
            _hypothesis(
                "DNS 解析时延偏高",
                min(90.0, 55.0 + dns_p95 / 25),
                [f"DNS 响应时延 P95 为 {dns_p95:g} ms"],
                "检查递归 DNS 距离、丢包、缓存命中和域名 CNAME 链。",
                [],
            )
        )

    tls = _mapping(protocol.get("tls_summary"))
    tls_alerts = _count(tls, "alert_count")
    client_hellos = _count(tls, "client_hello_count")
    server_hellos = _count(tls, "server_hello_count")
    if tls_alerts or client_hellos > server_hellos + 2:
        candidates.append(
            _hypothesis(
                "TLS 握手异常或服务端未完成协商",
                min(92.0, 62.0 + tls_alerts * 5 + (client_hellos - server_hellos) * 2),
                [
                    f"TLS 告警 {tls_alerts} 个",
                    f"ClientHello/ServerHello 为 {client_hellos}/{server_hellos}",
                ],
                "检查证书、协议版本、SNI 路由、服务端握手日志和中间设备。",
                [],
            )
        )

    http = _mapping(protocol.get("http_summary"))
    http_errors = _count(http, "error_response_count")
    http_latency = _mapping(http.get("latency_ms"))
    http_p95 = _number(http_latency.get("p95"))
    if http_errors:
        candidates.append(
            _hypothesis(
                "HTTP 服务返回错误响应",
                min(94.0, 68.0 + http_errors * 3),
                [f"检测到 {http_errors} 个 HTTP 4xx/5xx 响应"],
                "检查源站、网关、鉴权、限流和 CDN 回源日志。",
                [],
            )
        )
    elif http_p95 >= 1000:
        candidates.append(
            _hypothesis(
                "HTTP 响应等待时间过长",
                min(92.0, 58.0 + http_p95 / 100),
                [f"HTTP 响应时延 P95 为 {http_p95:g} ms"],
                "检查服务端处理、上游依赖、CDN 回源和连接复用。",
                [],
                observability=Observability.INDIRECT,
            )
        )

    udp = _mapping(protocol.get("udp_summary"))
    udp_long_gaps = _count(udp, "long_gap_flow_count")
    quic_packets = _count(udp, "quic_packet_count")
    if udp_long_gaps and quic_packets:
        candidates.append(
            _hypothesis(
                "QUIC/UDP 业务流存在长时间数据间断",
                min(86.0, 52.0 + udp_long_gaps * 4),
                [
                    f"发现 {udp_long_gaps} 条存在长间断的 UDP 流",
                    f"QUIC/UDP 443 报文 {quic_packets} 个",
                ],
                "检查 UDP 丢包、NAT 映射、防火墙策略及 QUIC 回退情况。",
                [],
                observability=Observability.INDIRECT,
            )
        )

    keywords = _mapping(protocol.get("keyword_summary"))
    keyword_hits = {
        key: _int_value(value) for key, value in keywords.items() if _int_value(value)
    }
    if keyword_hits:
        candidates.append(
            _hypothesis(
                "应用载荷出现卡顿或错误关键词",
                min(82.0, 48.0 + sum(keyword_hits.values()) * 2),
                [
                    "受控关键词命中："
                    + "、".join(f"{key}={value}" for key, value in keyword_hits.items())
                ],
                "结合应用日志确认关键词所在请求、响应及业务状态。",
                [],
                observability=Observability.INDIRECT,
            )
        )

    candidates = _personalize_candidates(candidates, user_context)
    candidates.sort(key=lambda item: item.confidence, reverse=True)
    limitations = [
        "仅凭报文无法直接证明用户界面发生卡顿，结论表示与卡顿一致的网络或业务等待现象。",
        "加密后的应用内容和播放器缓冲状态不可见，需结合终端、播放器和服务端日志确认。",
        "IP 关联仅来自报文中的 DNS、SNI、HTTP 和端点元数据，"
        "不执行外部归属或地理位置查询。",
    ]
    if manifest.get("status") == "partial":
        limitations.append("报文分析覆盖不完整，候选原因置信度需要谨慎解释。")
    primary = (
        candidates[0].cause if candidates else "未发现明确的网络层或应用协议卡顿原因"
    )
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
            **_mapping(protocol.get("capture_summary")),
        },
        endpoint_summary=_list_of_mappings(protocol.get("endpoint_summary")),
        dns_summary=dns,
        tls_summary=tls,
        http_summary=http,
        udp_summary=udp,
        keyword_summary={key: _int_value(value) for key, value in keywords.items()},
        user_context=user_context,
        limitations=limitations,
        troubleshooting_steps=[
            _context_first_step(user_context),
            "对照同一时间窗检查重传、RTT、接收窗口和吞吐变化。",
            "按端点关联的 DNS、SNI 和 HTTP Host 确认受影响业务。",
            "若协议指标正常，结合终端、播放器、服务端和无线侧日志继续定位。",
        ],
        optimization_suggestions=[
            "抓包应覆盖卡顿前至少 10 秒、卡顿期间和恢复后至少 10 秒。",
            "尽量同时记录用户操作时间点和终端、服务端日志。",
        ],
        analysis_metadata={
            "analysis_mode": "stall",
            "analyzer": "generic-multiprotocol-v1",
        },
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


def _mapping(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list_of_mappings(value: object) -> list[dict[str, Any]]:
    return (
        [item for item in value if isinstance(item, dict)]
        if isinstance(value, list)
        else []
    )


def _int_value(value: object) -> int:
    return (
        int(value)
        if isinstance(value, int | float) and not isinstance(value, bool)
        else 0
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
