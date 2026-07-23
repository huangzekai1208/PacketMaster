"""Build bounded, allowlisted model context from aggregate analysis artifacts."""

from __future__ import annotations

import json
from collections import Counter
from statistics import median
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from packetmaster.domain import AnalyzeResponse, EvidenceResponse, Target

_EVENT_COUNT_KEYS = (
    "retransmission_count",
    "duplicate_ack_count",
    "out_of_order_count",
    "zero_window_count",
    "window_full_count",
)
_METRIC_KEYS = {
    "packet_count",
    "payload_bytes",
    "payload_bytes_by_direction",
    "flow_count",
    "window_min",
    "window_max",
    "rtt_histogram",
    "timing",
    "time_start",
    "time_end",
    "duration_seconds",
    "throughput_mbps",
    *_EVENT_COUNT_KEYS,
}
_INTERVAL_KEYS = {
    "interval_start",
    "interval_end",
    "direction",
    *_METRIC_KEYS,
}
_EVIDENCE_KEYS = {
    "evidence_id",
    "event_type",
    "frame.number",
    "frame.time_relative",
    "flow_id",
    "direction",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.len",
    "tcp.analysis.ack_rtt",
    "time_relative",
}


def _scalar(value: Any) -> Any:
    if isinstance(value, str):
        return value[:256]
    if isinstance(value, bool | int | float) or value is None:
        return value
    return None


def _small_value(value: Any, *, depth: int = 0) -> Any:
    scalar = _scalar(value)
    if scalar is not None or value is None:
        return scalar
    if isinstance(value, dict) and depth < 2:
        return {
            str(key)[:64]: _small_value(item, depth=depth + 1)
            for key, item in list(value.items())[:32]
            if _small_value(item, depth=depth + 1) is not None
        }
    if isinstance(value, list):
        return [_small_value(item, depth=depth + 1) for item in value[:32]]
    return None


def _project(mapping: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    return {
        key: _small_value(mapping[key])
        for key in allowed
        if key in mapping and _small_value(mapping[key]) is not None
    }


def _metric_value(item: dict[str, Any], key: str) -> float | None:
    value = item.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


def _rtt_value(item: dict[str, Any]) -> float | None:
    histogram = item.get("rtt_histogram")
    if not isinstance(histogram, list):
        return None
    total = 0
    weighted = 0.0
    for bucket in histogram:
        if not isinstance(bucket, dict):
            continue
        count = bucket.get("count")
        bound = bucket.get("upper_bound_ms")
        if not isinstance(count, int) or count < 0:
            continue
        if bound == "inf":
            numeric_bound = 2000.0
        elif isinstance(bound, int | float) and not isinstance(bound, bool):
            numeric_bound = float(bound)
        else:
            continue
        total += count
        weighted += count * numeric_bound
    return weighted / total if total else None


def _baselines(items: list[dict[str, Any]]) -> dict[str, dict[str, float]]:
    grouped: dict[str, dict[str, list[float]]] = {}
    for item in items:
        direction = str(item.get("direction", "unknown"))
        values = grouped.setdefault(direction, {})
        for key in ("throughput_mbps", "window_min"):
            if (value := _metric_value(item, key)) is not None:
                values.setdefault(key, []).append(value)
        if (rtt := _rtt_value(item)) is not None:
            values.setdefault("rtt", []).append(rtt)
    return {
        direction: {key: float(median(samples)) for key, samples in values.items()}
        for direction, values in grouped.items()
    }


def _relative_anomaly(
    item: dict[str, Any],
    baselines: dict[str, dict[str, float]],
    previous: dict[str, Any] | None = None,
) -> bool:
    baseline = baselines.get(str(item.get("direction", "unknown")), {})
    throughput = _metric_value(item, "throughput_mbps")
    window = _metric_value(item, "window_min")
    rtt = _rtt_value(item)
    if throughput is not None and baseline.get("throughput_mbps", 0) > 0:
        if throughput < baseline["throughput_mbps"] * 0.5:
            return True
    if window is not None and baseline.get("window_min", 0) > 0:
        if window < baseline["window_min"] * 0.5:
            return True
    if rtt is not None and baseline.get("rtt", 0) > 0:
        if rtt > baseline["rtt"] * 2:
            return True
    if previous is None:
        return False
    previous_throughput = _metric_value(previous, "throughput_mbps")
    previous_window = _metric_value(previous, "window_min")
    previous_rtt = _rtt_value(previous)
    return any(
        (
            (
            throughput is not None
            and previous_throughput is not None
            and previous_throughput > 0
            and throughput < previous_throughput * 0.5
            ),
            (
            window is not None
            and previous_window is not None
            and previous_window > 0
            and window < previous_window * 0.5
            ),
            (
            rtt is not None
            and previous_rtt is not None
            and previous_rtt > 0
            and rtt > previous_rtt * 2
            ),
        )
    )


def bounded_evidence(
    responses: list[EvidenceResponse], *, max_layers: int = 8, max_items: int = 80
) -> dict[str, dict[str, Any]]:
    selected_types: list[str] = []
    for response in reversed(responses):
        if response.evidence_type not in selected_types:
            selected_types.append(response.evidence_type)
        if len(selected_types) == max_layers:
            break
    selected = set(selected_types)
    entries: list[tuple[str, dict[str, Any]]] = []
    metadata: dict[str, dict[str, Any]] = {}
    for response in responses:
        if response.evidence_type not in selected:
            continue
        for item in response.items:
            entries.append((response.evidence_type, _project(item, _EVIDENCE_KEYS)))
        metadata[response.evidence_type] = {
            "total": response.total,
            "total_exact": response.total_exact,
            "next_offset": response.next_offset,
            "truncated": response.truncated,
            "coverage_range": _small_value(response.coverage_range),
            "warning_count": len(response.warnings),
        }
    kept = entries[-max_items:]
    layers = {
        evidence_type: {**metadata[evidence_type], "items": []}
        for evidence_type in selected_types
        if evidence_type in metadata
    }
    for evidence_type, item in kept:
        layers[evidence_type]["items"].append(item)
    return layers


class DiagnosisContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    target: Target
    bandwidth: dict[str, float]
    coverage: dict[str, Any]
    global_metrics: dict[str, Any]
    flow_metrics: dict[str, Any]
    flow_compression: dict[str, int] = Field(default_factory=dict)
    anomaly_intervals: list[dict[str, Any]] = Field(default_factory=list)
    normal_interval_summary: dict[str, Any] = Field(default_factory=dict)
    syn_options: dict[str, Any] = Field(default_factory=dict)
    evidence_layers: dict[str, dict[str, Any]] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ContextBuilder:
    def __init__(
        self,
        *,
        max_intervals: int = 24,
        max_flows: int = 32,
        max_evidence_items: int = 80,
        max_evidence_layers: int = 8,
        max_context_chars: int = 100_000,
    ) -> None:
        limits = (
            max_intervals,
            max_flows,
            max_evidence_items,
            max_evidence_layers,
            max_context_chars,
        )
        if any(limit < 1 for limit in limits):
            raise ValueError("context limits must be positive")
        self.max_intervals = max_intervals
        self.max_flows = max_flows
        self.max_evidence_items = max_evidence_items
        self.max_evidence_layers = max_evidence_layers
        self.max_context_chars = max_context_chars

    @staticmethod
    def _has_event_anomaly(interval: dict[str, Any]) -> bool:
        return any(
            isinstance(interval.get(key), int | float) and interval[key] > 0
            for key in _EVENT_COUNT_KEYS
        )

    def _intervals(
        self, intervals: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        projected = [_project(item, _INTERVAL_KEYS) for item in intervals]
        baselines = _baselines(projected)
        previous_by_direction: dict[str, dict[str, Any]] = {}
        anomalies: list[dict[str, Any]] = []
        normals: list[dict[str, Any]] = []
        for item in projected:
            direction = str(item.get("direction", "unknown"))
            is_anomalous = self._has_event_anomaly(item) or _relative_anomaly(
                item, baselines, previous_by_direction.get(direction)
            )
            (anomalies if is_anomalous else normals).append(item)
            previous_by_direction[direction] = item
        starts = [
            float(item["interval_start"])
            for item in normals
            if isinstance(item.get("interval_start"), int | float)
        ]
        summary: dict[str, Any] = {
            "compressed_count": len(normals),
            "direction_counts": dict(
                Counter(str(item.get("direction", "unknown")) for item in normals)
            ),
            "payload_bytes": sum(
                int(item.get("payload_bytes", 0)) for item in normals
            ),
            "anomaly_total": len(anomalies),
        }
        if starts:
            summary.update(
                first_interval_start=min(starts), last_interval_start=max(starts)
            )
        if len(anomalies) > self.max_intervals:
            head_count = (self.max_intervals + 1) // 2
            tail_count = self.max_intervals - head_count
            returned = anomalies[:head_count]
            if tail_count:
                returned.extend(anomalies[-tail_count:])
            compression = "head_tail"
        else:
            returned = anomalies
            compression = "none"
        anomaly_starts = [
            float(item["interval_start"])
            for item in anomalies
            if isinstance(item.get("interval_start"), int | float)
        ]
        summary.update(
            anomaly_returned=len(returned),
            anomaly_omitted=len(anomalies) - len(returned),
            anomaly_compression=compression,
            anomaly_coverage={
                "first": min(anomaly_starts) if anomaly_starts else None,
                "last": max(anomaly_starts) if anomaly_starts else None,
            },
        )
        return returned, summary

    def _flows(self, flows: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
        projected = {
            str(flow_id)[:256]: _project(data, _METRIC_KEYS | {"direction"})
            for flow_id, data in flows.items()
            if isinstance(data, dict)
        }
        baselines = _baselines(list(projected.values()))
        anomalous = [
            item
            for item in projected.items()
            if self._has_event_anomaly(item[1])
            or _relative_anomaly(item[1], baselines)
        ]
        anomalous_ids = {flow_id for flow_id, _ in anomalous}
        normal = [
            item for item in projected.items() if item[0] not in anomalous_ids
        ]
        def payload_rank(item: tuple[str, dict[str, Any]]) -> float:
            return float(item[1].get("payload_bytes", 0))

        anomalous.sort(key=payload_rank, reverse=True)
        normal.sort(key=payload_rank, reverse=True)
        ranked = [*anomalous, *normal]
        returned = ranked[: self.max_flows]
        anomaly_returned = sum(flow_id in anomalous_ids for flow_id, _ in returned)
        return dict(returned), {
            "total": len(projected),
            "returned": len(returned),
            "omitted": len(projected) - len(returned),
            "anomaly_total": len(anomalous),
            "anomaly_returned": anomaly_returned,
        }

    def build(
        self,
        analysis: AnalyzeResponse,
        evidence: list[EvidenceResponse],
        *,
        standard_bandwidth_mbps: float,
        actual_bandwidth_mbps: float,
    ) -> DiagnosisContext:
        if standard_bandwidth_mbps <= 0 or actual_bandwidth_mbps <= 0:
            raise ValueError("bandwidth values must be positive")
        anomalies, normal_summary = self._intervals(analysis.interval_summary)
        flows, flow_compression = self._flows(analysis.flow_summary)
        raw_coverage = analysis.coverage_summary
        coverage = {
            "input_size_bytes": raw_coverage.input_size_bytes,
            "total_packets_seen": raw_coverage.total_packets_seen,
            "tcp_packets_seen": raw_coverage.tcp_packets_seen,
            "speed_packets_analyzed": raw_coverage.speed_packets_analyzed,
            "analyzed_bytes": raw_coverage.analyzed_bytes,
            "analyzed_duration_seconds": raw_coverage.analyzed_duration_seconds,
            "complete": raw_coverage.complete,
            "truncated": raw_coverage.truncated,
        }
        limitations: list[str] = []
        if not coverage["complete"] or coverage["truncated"]:
            limitations.append("Capture coverage is incomplete or truncated.")
        if analysis.status.value == "partial":
            limitations.append("Analysis status is partial.")
        context = DiagnosisContext(
            analysis_id=analysis.analysis_id,
            target=analysis.target,
            bandwidth={
                "standard_mbps": float(standard_bandwidth_mbps),
                "actual_mbps": float(actual_bandwidth_mbps),
                "achievement_ratio_pct": round(
                    actual_bandwidth_mbps / standard_bandwidth_mbps * 100, 3
                ),
            },
            coverage=coverage,
            global_metrics=_project(analysis.tcp_summary, _METRIC_KEYS),
            flow_metrics=flows,
            flow_compression=flow_compression,
            anomaly_intervals=anomalies,
            normal_interval_summary=normal_summary,
            syn_options=_small_value(analysis.syn_options),
            evidence_layers=bounded_evidence(
                evidence,
                max_layers=self.max_evidence_layers,
                max_items=self.max_evidence_items,
            ),
            limitations=limitations,
            warnings=[],
        )
        serialized_size = len(
            json.dumps(context.model_dump(mode="json"), ensure_ascii=False)
        )
        if serialized_size > self.max_context_chars:
            raise ValueError("bounded diagnosis context exceeds max_context_chars")
        return context
