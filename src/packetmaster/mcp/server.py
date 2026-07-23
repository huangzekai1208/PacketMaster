"""FastMCP server exposing only structured PacketMaster operations."""

from __future__ import annotations

import ipaddress
import json
import re
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
from packetmaster.domain import (
    AnalyzeRequest,
    AnalyzeResponse,
    EvidenceRequest,
    EvidenceResponse,
)
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
    return _safe_coverage_mapping(response.coverage_summary.model_dump(mode="json"))


def _safe_coverage_mapping(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    output: dict[str, Any] = {}
    for key in (
        "input_size_bytes",
        "total_packets_seen",
        "tcp_packets_seen",
        "speed_packets_analyzed",
        "analyzed_bytes",
        "analyzed_duration_seconds",
    ):
        number = _number(value.get(key))
        if number is not None and number >= 0:
            output[key] = number
    for key in ("complete", "truncated"):
        if isinstance(value.get(key), bool):
            output[key] = value[key]
    output["truncation_reason"] = (
        "ANALYSIS_TRUNCATED" if value.get("truncation_reason") else None
    )
    return output


def _safe_flow_id(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 512:
        return None
    if re.fullmatch(r"f-[0-9]+", value):
        return value
    parts = value.split("|")
    if len(parts) != 3 or parts[0] != "tcp":
        return None

    def valid_endpoint(endpoint: str) -> bool:
        try:
            if endpoint.startswith("["):
                closing = endpoint.find("]:")
                if closing < 0:
                    return False
                address = endpoint[1:closing]
                port = endpoint[closing + 2 :]
            else:
                address, port = endpoint.rsplit(":", 1)
            ipaddress.ip_address(address)
            return 0 <= int(port) <= 65535
        except (ValueError, TypeError):
            return False

    return value if all(valid_endpoint(item) for item in parts[1:]) else None


def _safe_evidence_id(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 1024:
        return None
    if re.fullmatch(r"ev-[0-9]+", value):
        return value
    if re.fullmatch(r"packet-(download|upload)-[0-9]+", value):
        return value
    parts = value.split(":", 3)
    if (
        len(parts) == 4
        and parts[0].isdigit()
        and parts[1]
        in {
            "retransmission",
            "fast_retransmission",
            "duplicate_ack",
            "out_of_order",
            "zero_window",
            "window_full",
        }
        and parts[2] in {"download", "upload"}
        and _safe_flow_id(parts[3]) is not None
    ):
        return value
    return None


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
                if re.fullmatch(r"[0-9]{1,10}", str(item_key))
                and (number := _number(item_value)) is not None
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
        safe_flow_id: _safe_metrics(metrics)
        for flow_id, metrics in response.flow_summary.items()
        if (safe_flow_id := _safe_flow_id(flow_id)) is not None
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


_EVIDENCE_ITEM_FIELDS = {
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
}


def _safe_evidence_scalar(field: str, value: object) -> object | None:
    if field in {"frame.number", "tcp.seq", "tcp.ack", "tcp.window_size", "tcp.len"}:
        return value if isinstance(value, int) and not isinstance(value, bool) else None
    if field in {"frame.time_relative", "tcp.analysis.ack_rtt"}:
        return _number(value)
    if field == "direction":
        return value if value in {"download", "upload", "both"} else None
    if field == "event_type":
        allowed = {
            "packet",
            "retransmission",
            "fast_retransmission",
            "duplicate_ack",
            "out_of_order",
            "zero_window",
            "window_full",
        }
        return value if value in allowed else None
    if field == "evidence_id":
        return _safe_evidence_id(value)
    if field == "flow_id":
        return _safe_flow_id(value)
    return None


def _safe_evidence_item(item: object, evidence_type: str) -> dict[str, Any]:
    if not isinstance(item, dict):
        return {}
    if evidence_type == "flow_summary":
        output = _safe_metrics(item)
        flow_id = _safe_flow_id(item.get("flow_id"))
        if flow_id is not None:
            output["flow_id"] = flow_id
        return output
    if evidence_type in {"io_timeline", "throughput_distribution"}:
        output = _safe_metrics(item, interval=True)
        interval_id = item.get("interval_id")
        if isinstance(interval_id, int) and not isinstance(interval_id, bool):
            output["interval_id"] = interval_id
        return output
    if evidence_type in {"summary", "rtt_distribution"}:
        name = item.get("name")
        if name == "coverage_summary":
            return {"name": name, **_safe_coverage_mapping(item)}
        output = _safe_metrics(item)
        if name in {"tcp_summary", "coverage_summary"}:
            output["name"] = name
        return output
    if evidence_type == "syn_options":
        output = _safe_syn_options(item)
        name = item.get("name")
        if isinstance(name, str) and len(name) <= 64:
            output["name"] = name
        return output
    output: dict[str, Any] = {}
    for field in _EVIDENCE_ITEM_FIELDS:
        if field not in item:
            continue
        value = _safe_evidence_scalar(field, item[field])
        if value is not None:
            output[field] = value
    return output


def _safe_evidence_source(source: str) -> str:
    if source == "mock":
        return "mock"
    if source.startswith("filtered:"):
        directions = [
            item
            for item in source.removeprefix("filtered:").split(",")
            if item in {"download", "upload", "none"}
        ]
        return "filtered:" + ",".join(directions)
    if source.lower().endswith(".sqlite"):
        return "sqlite"
    return "adapter"


def _safe_evidence_data(response: EvidenceResponse) -> dict[str, Any]:
    if len(response.items) > 500:
        raise AppError(
            code="INVALID_EVIDENCE_OUTPUT",
            message="Evidence response exceeds the 500-item contract limit",
            recoverable=False,
            suggested_action="Fix the evidence adapter pagination.",
        )
    coverage: dict[str, Any] = {}
    for key in ("offset", "limit"):
        value = response.coverage_range.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            coverage[key] = value
    complete = response.coverage_range.get("complete")
    if isinstance(complete, bool):
        coverage["complete"] = complete
    warnings = [
        item
        if item in {"PACKET_QUERY_TOTAL_LOWER_BOUND"}
        else "EVIDENCE_WARNING_REDACTED"
        for item in response.warnings[:20]
    ]
    data = response.model_dump(mode="json")
    data.update(
        summary={
            "returned": len(response.items),
        },
        items=[
            _safe_evidence_item(item, response.evidence_type)
            for item in response.items
        ],
        source=_safe_evidence_source(response.source),
        coverage_range=coverage,
        warnings=warnings,
    )
    if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) > 1_000_000:
        raise AppError(
            code="INVALID_EVIDENCE_OUTPUT",
            message="Sanitized MCP evidence response exceeds 1 MiB",
            recoverable=False,
            suggested_action="Reduce the evidence page size and retry.",
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
            return {"ok": True, "data": _safe_evidence_data(result)}
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
