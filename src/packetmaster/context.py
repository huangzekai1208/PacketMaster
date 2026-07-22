"""Build a bounded, payload-free diagnosis context from local analysis artifacts."""

from __future__ import annotations

from collections import Counter
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from packetmaster.domain import AnalyzeResponse, EvidenceResponse, Target

_FORBIDDEN_KEY_PARTS = ("payload", "api_key", "apikey", "secret")
_FORBIDDEN_KEYS = {"logs", "log", "artifact_paths", "resource_usage"}
_ANOMALY_KEYS = (
    "retransmissions",
    "fast_retransmissions",
    "duplicate_acks",
    "out_of_order",
    "zero_window",
    "window_full",
)


def sanitize_for_model(value: Any) -> Any:
    """Recursively remove local-only or sensitive fields before model use."""
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for raw_key, item in value.items():
            key = str(raw_key)
            lowered = key.lower()
            if lowered in _FORBIDDEN_KEYS or any(
                fragment in lowered for fragment in _FORBIDDEN_KEY_PARTS
            ):
                continue
            sanitized[key] = sanitize_for_model(item)
        return sanitized
    if isinstance(value, list | tuple):
        return [sanitize_for_model(item) for item in value]
    if isinstance(value, str):
        return value[:2000]
    return value


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
    evidence_layers: dict[str, list[dict[str, Any]]] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ContextBuilder:
    def __init__(
        self,
        *,
        max_intervals: int = 24,
        max_flows: int = 32,
        max_evidence_items: int = 80,
    ) -> None:
        if max_intervals < 1 or max_flows < 1 or max_evidence_items < 1:
            raise ValueError("context limits must be positive")
        self.max_intervals = max_intervals
        self.max_flows = max_flows
        self.max_evidence_items = max_evidence_items

    @staticmethod
    def _is_anomalous(interval: dict[str, Any]) -> bool:
        for key in _ANOMALY_KEYS:
            value = interval.get(key, 0)
            if isinstance(value, int | float) and value > 0:
                return True
        return False

    def _intervals(
        self, intervals: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        safe_intervals = [sanitize_for_model(item) for item in intervals]
        anomalies = [item for item in safe_intervals if self._is_anomalous(item)]
        normals = [item for item in safe_intervals if not self._is_anomalous(item)]
        kept_anomalies = anomalies[-self.max_intervals :]
        directions = Counter(str(item.get("direction", "unknown")) for item in normals)
        starts = [
            float(item["interval_start"])
            for item in normals
            if isinstance(item.get("interval_start"), int | float)
        ]
        total_bytes = sum(
            int(item.get("bytes", 0))
            for item in normals
            if isinstance(item.get("bytes", 0), int | float)
        )
        summary: dict[str, Any] = {
            "compressed_count": len(normals),
            "direction_counts": dict(directions),
            "total_bytes": total_bytes,
        }
        if starts:
            summary["first_interval_start"] = min(starts)
            summary["last_interval_start"] = max(starts)
        return kept_anomalies, summary

    def _flows(self, flows: dict[str, Any]) -> dict[str, Any]:
        safe = sanitize_for_model(flows)
        ranked = sorted(
            safe.items(),
            key=lambda item: (
                float(item[1].get("bytes", item[1].get("payload_bytes", 0)))
                if isinstance(item[1], dict)
                else 0
            ),
            reverse=True,
        )
        return dict(ranked[: self.max_flows])

    def _evidence(
        self, responses: list[EvidenceResponse]
    ) -> dict[str, list[dict[str, Any]]]:
        layers: dict[str, list[dict[str, Any]]] = {}
        for response in responses:
            items = [sanitize_for_model(item) for item in response.items]
            current = layers.setdefault(response.evidence_type, [])
            remaining = self.max_evidence_items - len(current)
            if remaining > 0:
                current.extend(items[-remaining:])
        return layers

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
        coverage = sanitize_for_model(analysis.coverage_summary)
        limitations: list[str] = []
        if (
            not analysis.coverage_summary.complete
            or analysis.coverage_summary.truncated
        ):
            limitations.append("Capture coverage is incomplete or truncated.")
        if analysis.status.value == "partial":
            limitations.append("Analysis status is partial.")
        return DiagnosisContext(
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
            global_metrics=sanitize_for_model(analysis.tcp_summary),
            flow_metrics=self._flows(analysis.flow_summary),
            anomaly_intervals=anomalies,
            normal_interval_summary=normal_summary,
            syn_options=sanitize_for_model(analysis.syn_options),
            evidence_layers=self._evidence(evidence),
            limitations=limitations,
            warnings=[
                warning[:500]
                for warning in analysis.warnings
                if "payload" not in warning.lower() and ".log" not in warning.lower()
            ][:20],
        )
