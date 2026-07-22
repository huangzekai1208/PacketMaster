from __future__ import annotations

import ipaddress
import math
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from packetmaster.domain import CoverageSummary, Target

RTT_BUCKETS_MS: tuple[int | float, ...] = (
    1,
    5,
    10,
    20,
    50,
    100,
    200,
    500,
    1000,
    math.inf,
)
EVENT_FIELDS = {
    "retransmission": "tcp.analysis.retransmission",
    "fast_retransmission": "tcp.analysis.fast_retransmission",
    "duplicate_ack": "tcp.analysis.duplicate_ack",
    "out_of_order": "tcp.analysis.out_of_order",
    "zero_window": "tcp.analysis.zero_window",
    "window_full": "tcp.analysis.window_full",
}
METRIC_EVENT_TYPES = (
    "retransmission",
    "duplicate_ack",
    "out_of_order",
    "zero_window",
    "window_full",
)


@dataclass(frozen=True)
class AggregationResult:
    coverage_summary: CoverageSummary
    tcp_summary: dict[str, Any]
    flows: dict[str, dict[str, Any]]
    intervals: list[dict[str, Any]]
    events: list[dict[str, Any]]
    syn_options: dict[str, Any]

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "coverage_summary": self.coverage_summary.model_dump(mode="json"),
            "tcp_summary": self.tcp_summary,
            "flow_summary": self.flows,
            "interval_summary": self.intervals,
            "syn_options": self.syn_options,
        }


def _row_address(row: dict[str, str], side: str) -> str:
    ipv4 = row.get(f"ip.{side}", "").strip()
    ipv6 = row.get(f"ipv6.{side}", "").strip()
    value = ipv4 or ipv6
    if not value:
        raise ValueError(f"missing source or destination address ({side})")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise ValueError(f"invalid {side} address: {value}") from exc


def _row_port(row: dict[str, str], side: str) -> int:
    value = row.get(f"tcp.{side}port", "").strip()
    if not value:
        raise ValueError(f"missing TCP {side} port")
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid TCP {side} port: {value}") from exc
    if not 0 <= port <= 65535:
        raise ValueError(f"invalid TCP {side} port: {value}")
    return port


def normalized_flow_id(row: dict[str, str]) -> str:
    """Return a stable TCP five-tuple identifier for either packet direction."""
    source_address = _row_address(row, "src")
    destination_address = _row_address(row, "dst")
    source_port = _row_port(row, "src")
    destination_port = _row_port(row, "dst")
    source_ip = ipaddress.ip_address(source_address)
    destination_ip = ipaddress.ip_address(destination_address)
    if source_ip.version != destination_ip.version:
        raise ValueError("source and destination address families differ")

    endpoints = sorted(
        ((source_ip, source_port), (destination_ip, destination_port)),
        key=lambda endpoint: (endpoint[0].packed, endpoint[1]),
    )

    def format_endpoint(endpoint: tuple[Any, int]) -> str:
        address, port = endpoint
        if address.version == 6:
            return f"[{address}]:{port}"
        return f"{address}:{port}"

    return f"tcp|{format_endpoint(endpoints[0])}|{format_endpoint(endpoints[1])}"


def _new_metrics() -> dict[str, Any]:
    metrics: dict[str, Any] = {
        "packet_count": 0,
        "payload_bytes": 0,
        "window_min": None,
        "window_max": None,
    }
    for event_type in METRIC_EVENT_TYPES:
        metrics[f"{event_type}_count"] = 0
    return metrics


def _is_set(value: str | None) -> bool:
    return bool(value and value.strip().lower() not in {"0", "false", "no"})


def _parse_int(value: str | None, field: str, *, default: int | None = None) -> int:
    if value is None or not value.strip():
        if default is not None:
            return default
        raise ValueError(f"missing {field}")
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field}: {value}") from exc
    return parsed


def _parse_float(value: str | None, field: str) -> float:
    if value is None or not value.strip():
        raise ValueError(f"missing {field}")
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"invalid {field}: {value}") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"invalid {field}: {value}")
    return parsed


def detect_events(row: dict[str, str]) -> list[str]:
    return [
        event_type
        for event_type, field in EVENT_FIELDS.items()
        if _is_set(row.get(field))
    ]


def _optional_int(value: str | None) -> int | None:
    if value is None or not value.strip():
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    try:
        parsed = float(value)
    except ValueError:
        return None
    return parsed if math.isfinite(parsed) else None


def event_record(
    row: dict[str, str], event_type: str, flow_id: str, direction: Target | str
) -> dict[str, Any]:
    direction_value = Target(direction).value
    frame_number = _parse_int(row.get("frame.number"), "frame.number")
    if frame_number <= 0:
        raise ValueError("frame.number must be a positive integer")
    time_relative = _optional_float(row.get("frame.time_relative"))
    return {
        "evidence_id": (
            f"{frame_number}:{event_type}:{direction_value}:{flow_id}"
        ),
        "event_type": event_type,
        "frame.number": frame_number,
        "frame.time_relative": time_relative,
        "flow_id": flow_id,
        "direction": direction_value,
        "tcp.seq": _optional_int(row.get("tcp.seq")),
        "tcp.ack": _optional_int(row.get("tcp.ack")),
        "tcp.window_size": _optional_int(
            row.get("tcp.window_size") or row.get("tcp.window_size_value")
        ),
        "tcp.len": _optional_int(row.get("tcp.len")),
        "tcp.analysis.ack_rtt": _optional_float(
            row.get("tcp.analysis.ack_rtt")
        ),
    }


class TcpAccumulator:
    def __init__(
        self,
        interval_seconds: int = 1,
        target: Target | str = Target.DOWNLOAD,
        event_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        if isinstance(interval_seconds, bool) or not isinstance(interval_seconds, int):
            raise TypeError("interval_seconds must be an integer")
        if not 1 <= interval_seconds <= 60:
            raise ValueError("interval_seconds must be between 1 and 60")
        try:
            self.target = Target(target)
        except (TypeError, ValueError) as exc:
            raise ValueError("target must be download, upload, or both") from exc
        if event_sink is not None and not callable(event_sink):
            raise TypeError("event_sink must be callable")

        self.interval_seconds = interval_seconds
        self.event_sink = event_sink
        self.total_packets_seen = 0
        self.tcp_packets_seen = 0
        self.speed_packets_analyzed = 0
        self.analyzed_bytes = 0
        self._min_time: float | None = None
        self._max_time: float | None = None
        self._timed_packets = 0
        self._untimed_packets = 0
        self._metrics = _new_metrics()
        self._payload_bytes_by_direction = {"download": 0, "upload": 0}
        self._flows: dict[str, dict[str, Any]] = {}
        self._intervals: dict[tuple[float, str], dict[str, Any]] = {}
        self._rtt_counts = [0] * len(RTT_BUCKETS_MS)
        self._events: list[dict[str, Any]] = []
        self._syn_packet_count = 0
        self._mss_values: defaultdict[str, int] = defaultdict(int)
        self._window_scale_shifts: defaultdict[str, int] = defaultdict(int)
        self._sack_permitted_count = 0

    def observe(self, row: dict[str, str], direction: Target | str) -> None:
        self.total_packets_seen += 1
        try:
            packet_direction = Target(direction)
        except (TypeError, ValueError) as exc:
            raise ValueError("direction must be download or upload") from exc
        if packet_direction is Target.BOTH:
            raise ValueError("direction must describe one packet, not both")

        if not row.get("tcp.srcport", "").strip() or not row.get(
            "tcp.dstport", ""
        ).strip():
            return
        self.tcp_packets_seen += 1
        if self.target is not Target.BOTH and packet_direction is not self.target:
            return

        flow_id = normalized_flow_id(row)
        raw_time = row.get("frame.time_relative", "").strip()
        time_relative = (
            _parse_float(raw_time, "frame.time_relative") if raw_time else None
        )
        if time_relative is not None and time_relative < 0:
            raise ValueError("frame.time_relative must be non-negative")
        payload_bytes = _parse_int(row.get("tcp.len"), "tcp.len", default=0)
        if payload_bytes < 0:
            raise ValueError("tcp.len must be non-negative")

        self.speed_packets_analyzed += 1
        self.analyzed_bytes += payload_bytes
        self._payload_bytes_by_direction[packet_direction.value] += payload_bytes
        if time_relative is None:
            self._untimed_packets += 1
        else:
            self._timed_packets += 1
            self._min_time = (
                time_relative
                if self._min_time is None
                else min(self._min_time, time_relative)
            )
            self._max_time = (
                time_relative
                if self._max_time is None
                else max(self._max_time, time_relative)
            )

        event_types = detect_events(row)
        metric_events = set(event_types)
        if "fast_retransmission" in metric_events:
            metric_events.add("retransmission")
        window = _optional_int(
            row.get("tcp.window_size") or row.get("tcp.window_size_value")
        )

        flow_metrics = self._flows.setdefault(flow_id, _new_metrics())
        metric_groups = [self._metrics, flow_metrics]
        if time_relative is not None:
            interval_start = (
                math.floor(time_relative / self.interval_seconds)
                * self.interval_seconds
            )
            interval_key = (float(interval_start), packet_direction.value)
            metric_groups.append(
                self._intervals.setdefault(interval_key, _new_metrics())
            )
        for metrics in metric_groups:
            metrics["packet_count"] += 1
            metrics["payload_bytes"] += payload_bytes
            for event_type in METRIC_EVENT_TYPES:
                if event_type in metric_events:
                    metrics[f"{event_type}_count"] += 1
            if window is not None:
                current_min = metrics["window_min"]
                current_max = metrics["window_max"]
                metrics["window_min"] = (
                    window if current_min is None else min(current_min, window)
                )
                metrics["window_max"] = (
                    window if current_max is None else max(current_max, window)
                )

        rtt = _optional_float(row.get("tcp.analysis.ack_rtt"))
        if rtt is not None and rtt >= 0:
            rtt_ms = rtt * 1000
            for index, upper_bound in enumerate(RTT_BUCKETS_MS):
                if rtt_ms <= upper_bound:
                    self._rtt_counts[index] += 1
                    break

        self._observe_syn_options(row)
        for event_type in event_types:
            event = event_record(row, event_type, flow_id, packet_direction)
            if self.event_sink is None:
                self._events.append(event)
            else:
                self.event_sink(event)

    def _observe_syn_options(self, row: dict[str, str]) -> None:
        if not _is_set(row.get("tcp.flags.syn")):
            return
        self._syn_packet_count += 1
        mss = row.get("tcp.options.mss_val", "").strip()
        if mss:
            self._mss_values[mss] += 1
        window_scale = row.get("tcp.options.wscale.shift", "").strip()
        if window_scale:
            self._window_scale_shifts[window_scale] += 1
        if _is_set(row.get("tcp.options.sack_perm")):
            self._sack_permitted_count += 1

    def finalize(self) -> AggregationResult:
        duration = 0.0
        if self._min_time is not None and self._max_time is not None:
            duration = self._max_time - self._min_time
        coverage = CoverageSummary(
            total_packets_seen=self.total_packets_seen,
            tcp_packets_seen=self.tcp_packets_seen,
            speed_packets_analyzed=self.speed_packets_analyzed,
            analyzed_bytes=self.analyzed_bytes,
            analyzed_duration_seconds=duration,
            complete=True,
            truncated=False,
        )
        histogram = []
        for upper_bound, count in zip(RTT_BUCKETS_MS, self._rtt_counts, strict=True):
            histogram.append(
                {
                    "upper_bound_ms": "inf" if math.isinf(upper_bound) else upper_bound,
                    "count": count,
                }
            )
        tcp_summary = dict(self._metrics)
        tcp_summary.update(
            {
                "flow_count": len(self._flows),
                "payload_bytes_by_direction": dict(
                    self._payload_bytes_by_direction
                ),
                "rtt_histogram": histogram,
                "timing": {
                    "available": self._timed_packets > 0,
                    "complete": self._untimed_packets == 0,
                    "timed_packets": self._timed_packets,
                    "untimed_packets": self._untimed_packets,
                },
            }
        )

        intervals = []
        for (interval_start, direction), metrics in sorted(self._intervals.items()):
            item = {
                "interval_start": interval_start,
                "interval_end": interval_start + self.interval_seconds,
                "direction": direction,
                **metrics,
                "throughput_mbps": (
                    metrics["payload_bytes"] * 8
                    / (self.interval_seconds * 1_000_000)
                ),
            }
            intervals.append(item)
        syn_options = {
            "syn_packet_count": self._syn_packet_count,
            "mss_values": dict(self._mss_values),
            "window_scale_shifts": dict(self._window_scale_shifts),
            "sack_permitted_count": self._sack_permitted_count,
        }
        return AggregationResult(
            coverage_summary=coverage,
            tcp_summary=tcp_summary,
            flows={key: dict(value) for key, value in self._flows.items()},
            intervals=intervals,
            events=list(self._events),
            syn_options=syn_options,
        )
