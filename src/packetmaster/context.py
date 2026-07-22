"""Build bounded, allowlisted model context from aggregate analysis artifacts."""

from __future__ import annotations

import json
from collections import Counter
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


def _small_value(value: Any) -> Any:
    scalar = _scalar(value)
    if scalar is not None or value is None:
        return scalar
    if isinstance(value, dict):
        return {
            str(key)[:64]: _scalar(item)
            for key, item in list(value.items())[:32]
            if _scalar(item) is not None
        }
    if isinstance(value, list):
        return [_small_value(item) for item in value[:32]]
    return None


def _project(mapping: dict[str, Any], allowed: set[str]) -> dict[str, Any]:
    return {
        key: _small_value(mapping[key])
        for key in allowed
        if key in mapping and _small_value(mapping[key]) is not None
    }


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
            "next_offset": response.next_offset,
            "truncated": response.truncated,
            "coverage_range": _small_value(response.coverage_range),
            "warnings": [warning[:256] for warning in response.warnings[:10]],
            "source": response.source[:256],
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
    def _is_anomalous(interval: dict[str, Any]) -> bool:
        return any(
            isinstance(interval.get(key), int | float) and interval[key] > 0
            for key in _EVENT_COUNT_KEYS
        )

    def _intervals(
        self, intervals: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        projected = [_project(item, _INTERVAL_KEYS) for item in intervals]
        anomalies = [item for item in projected if self._is_anomalous(item)]
        normals = [item for item in projected if not self._is_anomalous(item)]
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
        }
        if starts:
            summary.update(
                first_interval_start=min(starts), last_interval_start=max(starts)
            )
        return anomalies[-self.max_intervals :], summary

    def _flows(self, flows: dict[str, Any]) -> dict[str, Any]:
        projected = {
            str(flow_id)[:256]: _project(data, _METRIC_KEYS | {"direction"})
            for flow_id, data in flows.items()
            if isinstance(data, dict)
        }
        ranked = sorted(
            projected.items(),
            key=lambda item: float(item[1].get("payload_bytes", 0)),
            reverse=True,
        )
        return dict(ranked[: self.max_flows])

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
        coverage = analysis.coverage_summary.model_dump(mode="json")
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
            flow_metrics=self._flows(analysis.flow_summary),
            anomaly_intervals=anomalies,
            normal_interval_summary=normal_summary,
            syn_options=_small_value(analysis.syn_options),
            evidence_layers=bounded_evidence(
                evidence,
                max_layers=self.max_evidence_layers,
                max_items=self.max_evidence_items,
            ),
            limitations=limitations,
            warnings=[warning[:256] for warning in analysis.warnings[:20]],
        )
        serialized_size = len(
            json.dumps(context.model_dump(mode="json"), ensure_ascii=False)
        )
        if serialized_size > self.max_context_chars:
            raise ValueError("bounded diagnosis context exceeds max_context_chars")
        return context
