"""FastMCP server exposing only structured PacketMaster operations."""

from __future__ import annotations

import json
from typing import Any

from fastmcp import Context, FastMCP
from pydantic import ValidationError

from packetmaster.analyzer.base import (
    SUPPORTED_EVIDENCE_TYPES,
    AnalyzerAdapter,
)
from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.config import Settings
from packetmaster.context import bounded_flow_metrics, bounded_interval_series
from packetmaster.domain import AnalyzeRequest, AnalyzeResponse, EvidenceRequest
from packetmaster.errors import AppError


def _error_envelope(error: AppError) -> dict[str, Any]:
    return {"ok": False, "error": error.to_dict()}


def _invalid_request(error: ValidationError) -> dict[str, Any]:
    validation = error.errors(include_url=False, include_input=False)[:10]
    return _error_envelope(
        AppError(
            code="INVALID_REQUEST",
            message="MCP request does not match the PacketMaster schema",
            recoverable=False,
            suggested_action="Correct the structured request and retry.",
            details={"validation": validation},
        )
    )


_METRIC_FIELDS = {
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
    "retransmissions",
    "duplicate_acks",
    "time_start",
    "time_end",
    "duration_seconds",
    "throughput_mbps",
}


def _number(value: object) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return value


def _safe_metrics(value: object, *, interval: bool = False) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output = {
        key: number
        for key in _METRIC_FIELDS
        if (number := _number(value.get(key))) is not None
    }
    direction = value.get("direction")
    if direction in {"download", "upload", "both"}:
        output["direction"] = direction
    if interval:
        for key in ("interval_start", "interval_end"):
            if (number := _number(value.get(key))) is not None:
                output[key] = number
    directions = value.get("payload_bytes_by_direction")
    if isinstance(directions, dict):
        output["payload_bytes_by_direction"] = {
            key: number
            for key in ("download", "upload")
            if (number := _number(directions.get(key))) is not None
        }
    timing = value.get("timing")
    if isinstance(timing, dict):
        output["timing"] = {
            key: timing[key]
            for key in ("available", "complete", "timed_packets", "untimed_packets")
            if isinstance(timing.get(key), bool | int)
        }
    histogram = value.get("rtt_histogram")
    if isinstance(histogram, list):
        safe_histogram = []
        for bucket in histogram[:64]:
            if not isinstance(bucket, dict):
                continue
            bound = bucket.get("upper_bound_ms")
            count = bucket.get("count")
            bound_is_safe = (
                bound == "inf"
                or isinstance(bound, int | float)
                and not isinstance(bound, bool)
            )
            if (
                bound_is_safe
                and isinstance(count, int)
                and not isinstance(count, bool)
                and count >= 0
            ):
                safe_histogram.append({"upper_bound_ms": bound, "count": count})
        output["rtt_histogram"] = safe_histogram
    return output


def _safe_coverage(response: AnalyzeResponse) -> dict[str, Any]:
    coverage = response.coverage_summary
    return {
        "input_size_bytes": coverage.input_size_bytes,
        "total_packets_seen": coverage.total_packets_seen,
        "tcp_packets_seen": coverage.tcp_packets_seen,
        "speed_packets_analyzed": coverage.speed_packets_analyzed,
        "analyzed_bytes": coverage.analyzed_bytes,
        "analyzed_duration_seconds": coverage.analyzed_duration_seconds,
        "complete": coverage.complete,
        "truncated": coverage.truncated,
        "truncation_reason": (
            "ANALYSIS_TRUNCATED" if coverage.truncation_reason else None
        ),
    }


def _safe_syn_options(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key in ("syn_packet_count", "sack_permitted_count"):
        if (number := _number(value.get(key))) is not None:
            output[key] = number
    for key in ("mss_values", "window_scale_shifts"):
        mapping = value.get(key)
        if isinstance(mapping, dict):
            output[key] = {
                str(item_key)[:32]: number
                for item_key, item_value in list(mapping.items())[:64]
                if (number := _number(item_value)) is not None
            }
    return output


def _safe_warning(value: str) -> str:
    if value.startswith("No matching ") and value.endswith(" speed flow was found."):
        return "MISSING_SPEED_FLOW"
    if value.startswith("Packet timestamps are unavailable"):
        return "INCOMPLETE_PACKET_TIMESTAMPS"
    return "ANALYZER_WARNING_REDACTED"


def _safe_analysis_data(response: AnalyzeResponse) -> dict[str, Any]:
    data = response.model_dump(mode="json")
    data["coverage_summary"] = _safe_coverage(response)
    data["tcp_summary"] = _safe_metrics(response.tcp_summary)
    safe_flows = {
        str(flow_id)[:256]: _safe_metrics(metrics)
        for flow_id, metrics in response.flow_summary.items()
    }
    safe_intervals = [
        _safe_metrics(interval, interval=True)
        for interval in response.interval_summary
    ]
    data["flow_summary"], flow_summary = bounded_flow_metrics(safe_flows, 256)
    data["interval_summary"], interval_summary = bounded_interval_series(
        safe_intervals, 1000
    )
    data["transport_summary"] = {
        "flows": flow_summary,
        "intervals": interval_summary,
    }
    data["syn_options"] = _safe_syn_options(response.syn_options)
    data["available_evidence"] = [
        item
        for item in response.available_evidence[:64]
        if item in SUPPORTED_EVIDENCE_TYPES
    ]
    data["resource_usage"] = {
        key: response.resource_usage[key]
        for key in ("rss_peak_bytes", "timeout_seconds", "returncode", "reused")
        if isinstance(response.resource_usage.get(key), bool | int | float)
    }
    data["warnings"] = [_safe_warning(item) for item in response.warnings[:20]]
    data["artifact_paths"] = {}
    if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) > 1_000_000:
        raise AppError(
            code="INVALID_ANALYSIS_OUTPUT",
            message="Sanitized MCP analysis response exceeds 1 MiB",
            recoverable=False,
            suggested_action="Reduce aggregate cardinality and rerun.",
        )
    return data


def create_server(adapter: AnalyzerAdapter) -> FastMCP:
    server = FastMCP("packetmaster")

    @server.tool(name="analyze_speed_capture")
    async def analyze_speed_capture(
        request: dict[str, Any], context: Context
    ) -> dict[str, Any]:
        try:
            parsed = AnalyzeRequest.model_validate(request)

            async def progress(
                current: float, total: float | None, message: str | None
            ) -> None:
                await context.report_progress(current, total, message)

            result = await adapter.analyze(parsed, progress_callback=progress)
            return {"ok": True, "data": _safe_analysis_data(result)}
        except ValidationError as exc:
            return _invalid_request(exc)
        except AppError as exc:
            return _error_envelope(exc)
        except Exception as exc:
            return _error_envelope(
                AppError(
                    code="MCP_INTERNAL_ERROR",
                    message="PacketMaster analyze tool failed unexpectedly",
                    recoverable=False,
                    suggested_action="Inspect the MCP server log.",
                    details={"exception_type": exc.__class__.__name__},
                )
            )

    @server.tool(name="get_tcp_evidence")
    async def get_tcp_evidence(request: dict[str, Any]) -> dict[str, Any]:
        try:
            parsed = EvidenceRequest.model_validate(request)
            result = await adapter.get_evidence(parsed)
            return {"ok": True, "data": result.model_dump(mode="json")}
        except ValidationError as exc:
            return _invalid_request(exc)
        except AppError as exc:
            return _error_envelope(exc)
        except Exception as exc:
            return _error_envelope(
                AppError(
                    code="MCP_INTERNAL_ERROR",
                    message="PacketMaster evidence tool failed unexpectedly",
                    recoverable=False,
                    suggested_action="Inspect the MCP server log.",
                    details={"exception_type": exc.__class__.__name__},
                )
            )

    return server


def create_default_server(settings: Settings | None = None) -> FastMCP:
    """Create the production server; tests should inject a Mock adapter."""
    runtime = settings or Settings.load()
    return create_server(
        RealAnalyzerAdapter(
            artifact_root=runtime.artifact_root,
            pipeline_script=runtime.speed_analyzer_script,
            tshark_path=runtime.tshark_path,
            evidence_timeout_seconds=runtime.evidence_timeout_seconds,
        )
    )


def main() -> None:
    create_default_server().run(transport="stdio", show_banner=False)


if __name__ == "__main__":
    main()
