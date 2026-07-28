"""调用本地 speed-analyze 流水线的大报文适配器，不在 Python 内存中缓冲整包。"""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import inspect
import ipaddress
import json
import math
import os
import re
import shutil
import sqlite3
import sys
import sysconfig
import threading
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from types import ModuleType
from typing import Any

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from packetmaster.analyzer.base import (
    EVENT_EVIDENCE_TYPES,
    INDEXED_EVIDENCE_TYPES,
    PACKET_EVIDENCE_TYPES,
    normalized_evidence_filters,
    validate_evidence_request,
)
from packetmaster.artifacts import ArtifactManager
from packetmaster.domain import (
    AnalysisStatus,
    AnalyzeRequest,
    AnalyzeResponse,
    CoverageSummary,
    EvidenceRequest,
    EvidenceResponse,
    Target,
)
from packetmaster.errors import AppError
from packetmaster.platform import subprocess_group_options, terminate_process

_ANALYSIS_ID = re.compile(r"^[A-Za-z0-9._-]+$")
_MAX_JSON_BYTES = 16 * 1024 * 1024
_DEFAULT_EVIDENCE_FIELDS = [
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
]
_PACKET_SUPPORT_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.len",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
]
_INTEGER_PACKET_FIELDS = {
    "frame.number",
    "tcp.seq",
    "tcp.ack",
    "tcp.window_size",
    "tcp.len",
}
_FLOAT_PACKET_FIELDS = {
    "frame.time_relative",
    "frame.time_epoch",
    "tcp.analysis.ack_rtt",
}
_EVENT_PACKET_FIELDS = {
    "tcp.analysis.fast_retransmission": "fast_retransmission",
    "tcp.analysis.retransmission": "retransmission",
    "tcp.analysis.duplicate_ack": "duplicate_ack",
    "tcp.analysis.out_of_order": "out_of_order",
    "tcp.analysis.zero_window": "zero_window",
    "tcp.analysis.window_full": "window_full",
}


def default_pipeline_script() -> Path:
    # 优先使用安装包携带的脚本；开发源码目录作为本地回退。
    installed = (
        Path(sysconfig.get_path("data"))
        / "share"
        / "packetmaster"
        / "speed-analyze"
        / "scripts"
        / "run_pipeline.py"
    )
    source_checkout = (
        Path(__file__).resolve().parents[3]
        / "speed-analyze"
        / "scripts"
        / "run_pipeline.py"
    )
    return installed if installed.is_file() else source_checkout


def _packet_scalar(field: str, value: str) -> object:
    stripped = value.strip()
    if not stripped:
        return None
    try:
        if field in _INTEGER_PACKET_FIELDS:
            return int(stripped)
        if field in _FLOAT_PACKET_FIELDS:
            return float(stripped)
    except ValueError:
        return None
    return stripped


def _packet_flow_id(row: dict[str, str]) -> str | None:
    # 对端点排序后生成稳定五元组标识，双向报文会归入同一 TCP 流。
    source = row.get("ip.src") or row.get("ipv6.src")
    destination = row.get("ip.dst") or row.get("ipv6.dst")
    try:
        source_ip = ipaddress.ip_address(source)
        destination_ip = ipaddress.ip_address(destination)
        source_port = int(row.get("tcp.srcport", ""))
        destination_port = int(row.get("tcp.dstport", ""))
    except ValueError:
        return None
    endpoints = sorted(
        ((source_ip, source_port), (destination_ip, destination_port)),
        key=lambda endpoint: (endpoint[0].packed, endpoint[1]),
    )

    def format_endpoint(endpoint: tuple[object, int]) -> str:
        address, port = endpoint
        return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"

    return f"tcp|{format_endpoint(endpoints[0])}|{format_endpoint(endpoints[1])}"


def _packet_item(
    row: dict[str, str], direction: str, epoch_baseline: float | None
) -> dict[str, object]:
    # 只保留白名单 TCP 字段，并将 epoch 时间换算为相对时间，避免泄露 Payload。
    frame_number = _packet_scalar("frame.number", row.get("frame.number", ""))
    event_type = "packet"
    for field, candidate in _EVENT_PACKET_FIELDS.items():
        if row.get(field, "").strip() not in {"", "0"}:
            event_type = candidate
            break
    item = {
        "evidence_id": f"packet-{direction}-{frame_number}",
        "event_type": event_type,
        "flow_id": _packet_flow_id(row),
        "direction": direction,
    }
    for field in _INTEGER_PACKET_FIELDS | _FLOAT_PACKET_FIELDS:
        item[field] = _packet_scalar(field, row.get(field, ""))
    epoch = item.pop("frame.time_epoch", None)
    if isinstance(epoch, int | float) and epoch_baseline is not None:
        item["frame.time_relative"] = float(epoch) - epoch_baseline
    return item


def _flow_endpoints(flow_id: str) -> tuple[tuple[str, int], tuple[str, int]] | None:
    parts = flow_id.split("|")
    if len(parts) != 3 or parts[0] != "tcp":
        return None

    def parse_endpoint(value: str) -> tuple[str, int]:
        if value.startswith("["):
            closing = value.find("]:")
            if closing < 0:
                raise ValueError
            address_text = value[1:closing]
            port_text = value[closing + 2 :]
        else:
            address_text, port_text = value.rsplit(":", 1)
        address = str(ipaddress.ip_address(address_text))
        port = int(port_text)
        if not 0 <= port <= 65535:
            raise ValueError
        return address, port

    try:
        return parse_endpoint(parts[1]), parse_endpoint(parts[2])
    except (ValueError, TypeError):
        return None


def _numeric_filter_literal(value: object) -> str | None:
    if isinstance(value, bool):
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(numeric):
        return None
    return format(numeric, ".15g")


def _flow_filter(flow_ids: list[str] | None) -> str | None:
    if not flow_ids:
        return None
    flows: list[str] = []
    for flow_id in flow_ids:
        endpoints = _flow_endpoints(flow_id)
        if endpoints is None:
            continue
        (first_address, first_port), (second_address, second_port) = endpoints
        first_field = "ipv6" if ":" in first_address else "ip"
        second_field = "ipv6" if ":" in second_address else "ip"
        forward = (
            f"({first_field}.src == {first_address} && tcp.srcport == {first_port} "
            f"&& {second_field}.dst == {second_address} "
            f"&& tcp.dstport == {second_port})"
        )
        reverse = (
            f"({second_field}.src == {second_address} && tcp.srcport == {second_port} "
            f"&& {first_field}.dst == {first_address} "
            f"&& tcp.dstport == {first_port})"
        )
        flows.append(f"({forward} || {reverse})")
    return f"({' || '.join(flows)})" if flows else "false"


def _predicate_filter(predicate: object) -> str | None:
    field, operator, expected = _predicate_values(predicate)
    if field in {"evidence_id", "flow_id", "direction"}:
        return None
    if field == "frame.time_relative":
        return None
    if field == "event_type":
        if operator not in {"eq", "in"}:
            return None
        values = (
            expected
            if operator == "in" and isinstance(expected, list)
            else [expected]
        )
        event_fields = [
            raw_field
            for raw_field, event_type in _EVENT_PACKET_FIELDS.items()
            if event_type in values
        ]
        return f"({' || '.join(event_fields)})" if event_fields else None
    if field not in _INTEGER_PACKET_FIELDS | _FLOAT_PACKET_FIELDS:
        return None
    if operator == "exists":
        return field if expected is not False else f"!{field}"
    values = expected if operator == "in" and isinstance(expected, list) else [expected]
    literals = [
        literal
        for value in values
        if (literal := _numeric_filter_literal(value)) is not None
    ]
    if not literals:
        return None
    if operator == "in":
        return f"({' || '.join(f'{field} == {value}' for value in literals)})"
    symbol = {
        "eq": "==",
        "ne": "!=",
        "gt": ">",
        "gte": ">=",
        "lt": "<",
        "lte": "<=",
    }.get(operator)
    return f"{field} {symbol} {literals[0]}" if symbol else None


def _directed_display_filter(
    filters: Any, epoch_baseline: float | None
) -> str:
    clauses = ["tcp"]
    if filters.time_start is not None and epoch_baseline is not None:
        clauses.append(
            "frame.time_epoch >= "
            + format(epoch_baseline + filters.time_start, ".15g")
        )
    if filters.time_end is not None and epoch_baseline is not None:
        clauses.append(
            "frame.time_epoch <= "
            + format(epoch_baseline + filters.time_end, ".15g")
        )
    if flow_filter := _flow_filter(filters.flow_ids):
        clauses.append(flow_filter)
    clauses.extend(
        compiled
        for predicate in filters.predicates
        if (compiled := _predicate_filter(predicate)) is not None
    )
    return " && ".join(f"({clause})" for clause in clauses)


def _packet_query_targets_indexed_events(request: EvidenceRequest) -> bool:
    if request.query is None:
        return False
    indexed_event_types = set(_EVENT_PACKET_FIELDS.values())
    for predicate in request.query.predicates:
        field, operator, expected = _predicate_values(predicate)
        if field != "event_type" or operator not in {"eq", "in"}:
            continue
        values = (
            expected
            if operator == "in" and isinstance(expected, list)
            else [expected]
        )
        if values and all(value in indexed_event_types for value in values):
            return True
    return False


def _predicate_values(predicate: object) -> tuple[str, str, object]:
    if isinstance(predicate, dict):
        field = predicate.get("field")
        operator = predicate.get("operator")
        value = predicate.get("value")
    else:
        field = getattr(predicate, "field", None)
        operator = getattr(predicate, "operator", None)
        value = getattr(predicate, "value", None)
    if hasattr(operator, "value"):
        operator = operator.value
    return str(field), str(operator), value


def _coerce_comparison(value: object, expected: object) -> object:
    if isinstance(value, bool) or value is None:
        return expected
    try:
        if isinstance(value, int):
            return int(expected)
        if isinstance(value, float):
            return float(expected)
    except (TypeError, ValueError):
        return expected
    return str(expected) if isinstance(value, str) else expected


def _matches_predicate(item: dict[str, object], predicate: object) -> bool:
    field, operator, expected = _predicate_values(predicate)
    value = item.get(field)
    if operator == "exists":
        return (value is not None) if expected is not False else (value is None)
    if operator == "in":
        return isinstance(expected, list) and any(
            value == _coerce_comparison(value, candidate) for candidate in expected
        )
    compared = _coerce_comparison(value, expected)
    if operator == "eq":
        return value == compared
    if operator == "ne":
        return value != compared
    if value is None or compared is None:
        return False
    try:
        return {
            "gt": value > compared,
            "gte": value >= compared,
            "lt": value < compared,
            "lte": value <= compared,
        }[operator]
    except (KeyError, TypeError):
        return False


class _ManifestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    analysis_id: str
    status: AnalysisStatus
    target: Target
    input_path: str
    normalized_capture_path: str | None = None
    coverage_summary: CoverageSummary
    artifact_paths: dict[str, Any]
    available_evidence: list[str]
    warnings: list[str]
    error: dict[str, Any] | None = None
    started_at: str
    completed_at: str | None = None


class _AnalysisSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    coverage_summary: CoverageSummary
    tcp_summary: dict[str, Any]
    flow_summary: dict[str, Any]
    interval_summary: list[dict[str, Any]]
    syn_options: dict[str, Any]
    timebase_epoch: float | None = None


def _sanitize_artifacts(root: Path, value: object) -> object:
    if isinstance(value, str):
        path = _artifact_path(root, value, root)
        if not path.exists():
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Manifest references a missing artifact",
                recoverable=False,
                suggested_action="Discard the task artifacts and rerun the analysis.",
                details={"path": str(path)},
            )
        return str(path)
    if isinstance(value, dict):
        return {
            str(key): _sanitize_artifacts(root, item) for key, item in value.items()
        }
    raise AppError(
        code="INVALID_ANALYSIS_OUTPUT",
        message="Manifest artifact_paths contains a non-path value",
        recoverable=False,
        suggested_action="Check the speed-analyze manifest schema.",
    )


async def _maybe_await(value: Any) -> None:
    if inspect.isawaitable(value):
        await value


def dynamic_timeout_seconds(input_size_bytes: int) -> float:
    """Allow more time for large captures while keeping a finite upper bound."""
    gib = max(0, input_size_bytes) / (1024**3)
    return min(6 * 3600.0, 300.0 + gib * 900.0)


def _read_json_object(path: Path) -> dict[str, Any]:
    try:
        if path.stat().st_size > _MAX_JSON_BYTES:
            raise ValueError("JSON artifact exceeds the compact-summary size limit")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        raise AppError(
            code="INVALID_ANALYSIS_OUTPUT",
            message=f"Invalid analysis artifact: {path.name}",
            recoverable=False,
            suggested_action="Inspect the local pipeline log and rerun the analysis.",
            details={"path": str(path)},
        ) from exc
    if not isinstance(value, dict):
        raise AppError(
            code="INVALID_ANALYSIS_OUTPUT",
            message=f"Analysis artifact is not a JSON object: {path.name}",
            recoverable=False,
            suggested_action="Inspect the local pipeline output.",
        )
    return value


def _rss_bytes(pid: int) -> int:
    try:
        process = psutil.Process(pid)
        processes = [process, *process.children(recursive=True)]
        return sum(item.memory_info().rss for item in processes if item.is_running())
    except (psutil.Error, OSError):
        return 0


def _artifact_path(root: Path, value: object, fallback: Path) -> Path:
    candidate = Path(str(value)) if value else fallback
    if not candidate.is_absolute():
        candidate = root / candidate
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root.resolve()):
        raise AppError(
            code="INVALID_ANALYSIS_OUTPUT",
            message="Manifest artifact path resolves outside the task directory",
            recoverable=False,
            suggested_action="Discard the task artifacts and rerun the analysis.",
            details={"path": str(candidate)},
        )
    return resolved


class RealAnalyzerAdapter:
    def __init__(
        self,
        *,
        artifact_root: Path,
        pipeline_script: Path | None = None,
        tshark_path: str | None = None,
        timeout_calculator: Callable[[int], float] = dynamic_timeout_seconds,
        evidence_timeout_seconds: float = 120.0,
    ) -> None:
        self.artifact_root = Path(artifact_root).expanduser().resolve()
        self.pipeline_script = (
            Path(pipeline_script).expanduser().resolve()
            if pipeline_script is not None
            else default_pipeline_script()
        )
        self.tshark_path = tshark_path
        self.timeout_calculator = timeout_calculator
        if evidence_timeout_seconds <= 0:
            raise ValueError("evidence_timeout_seconds must be positive")
        self.evidence_timeout_seconds = float(evidence_timeout_seconds)
        self._artifacts = ArtifactManager(self.artifact_root, ttl_hours=24)

    def _analysis_root(self, analysis_id: str) -> Path:
        if not _ANALYSIS_ID.fullmatch(analysis_id) or not analysis_id.strip("."):
            raise AppError(
                code="INVALID_ANALYSIS_ID",
                message="analysis_id contains unsupported path characters",
                recoverable=False,
                suggested_action="Use letters, numbers, dot, underscore, or hyphen.",
            )
        root = (self.artifact_root / analysis_id).resolve()
        if not root.is_relative_to(self.artifact_root):
            raise AppError(
                code="INVALID_ANALYSIS_ID",
                message="analysis_id resolves outside the artifact root",
                recoverable=False,
                suggested_action="Use a simple PacketMaster analysis identifier.",
            )
        return root

    async def _wait(
        self,
        process: Any,
        timeout: float,
        progress_path: Path | None = None,
        progress_callback: Callable[[float, float | None, str | None], Any]
        | None = None,
    ) -> tuple[int, int]:
        peak = _rss_bytes(process.pid)
        wait_task = asyncio.create_task(process.wait())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        progress_position = 0

        async def stop_process() -> None:
            if process.returncode is None:
                await terminate_process(process)
            if not wait_task.done():
                wait_task.cancel()
            try:
                await wait_task
            except BaseException:
                pass

        try:
            while True:
                progress_events: list[tuple[float, float | None, str]] = []
                if progress_path is not None and progress_path.is_file():
                    try:
                        with progress_path.open(encoding="utf-8") as progress_file:
                            progress_file.seek(progress_position)
                            while line := progress_file.readline():
                                progress_position = progress_file.tell()
                                try:
                                    event = json.loads(line)
                                    current = float(event.get("current", 0))
                                    total = (
                                        float(event["total"])
                                        if event.get("total") is not None
                                        else None
                                    )
                                    message = str(event.get("message", ""))
                                except (
                                    AttributeError,
                                    TypeError,
                                    ValueError,
                                    json.JSONDecodeError,
                                ):
                                    continue
                                progress_events.append((current, total, message))
                    except OSError:
                        pass
                if progress_callback is not None:
                    for current, total, message in progress_events:
                        await _maybe_await(
                            progress_callback(current, total, message)
                        )
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise TimeoutError
                try:
                    returncode = await asyncio.wait_for(
                        asyncio.shield(wait_task), timeout=min(0.25, remaining)
                    )
                    peak = max(peak, _rss_bytes(process.pid))
                    return returncode, peak
                except TimeoutError:
                    peak = max(peak, _rss_bytes(process.pid))
        except asyncio.CancelledError as exc:
            await stop_process()
            raise AppError(
                code="ANALYSIS_CANCELLED",
                message="Speed analysis was cancelled",
                recoverable=True,
                suggested_action="Rerun the analysis when ready.",
            ) from exc
        except TimeoutError as exc:
            await stop_process()
            raise AppError(
                code="ANALYSIS_TIMEOUT",
                message="Speed analysis exceeded its dynamic timeout",
                recoverable=True,
                suggested_action="Check TShark performance and available resources.",
                details={"timeout_seconds": timeout, "rss_peak_bytes": peak},
            ) from exc
        except Exception as exc:
            await stop_process()
            if isinstance(exc, AppError):
                raise
            raise AppError(
                code="ANALYSIS_PROGRESS_FAILED",
                message="Speed analysis progress forwarding failed",
                recoverable=True,
                suggested_action="Inspect the MCP connection and retry.",
                details={"exception_type": exc.__class__.__name__},
            ) from exc

    def _command(self, request: AnalyzeRequest, output: Path) -> list[str]:
        command = [
            sys.executable,
            str(self.pipeline_script),
            "--input",
            request.pcap_path,
            "--target",
            request.target.value,
            "--output",
            str(output),
            "--analysis-id",
            request.request_id,
            "--interval",
            str(request.aggregation_interval_seconds),
            (
                "--build-evidence-index"
                if request.build_evidence_index
                else "--no-build-evidence-index"
            ),
        ]
        if self.tshark_path:
            command.extend(["--tshark-path", self.tshark_path])
        return command

    @staticmethod
    def _request_fingerprint(
        request: AnalyzeRequest, input_path: Path
    ) -> dict[str, Any]:
        stat = input_path.stat()
        return {
            "request": request.model_dump(mode="json"),
            "input_size_bytes": stat.st_size,
            "input_mtime_ns": stat.st_mtime_ns,
        }

    @staticmethod
    def _write_request_fingerprint(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        try:
            temporary.write_text(
                json.dumps(value, ensure_ascii=False, separators=(",", ":")),
                encoding="utf-8",
            )
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)

    def _matches_existing_request(
        self, task_root: Path, fingerprint: dict[str, Any]
    ) -> bool:
        path = task_root / "request.json"
        try:
            existing = _read_json_object(path)
        except AppError:
            return False
        return existing == fingerprint

    @staticmethod
    def _matches_existing_content(task_root: Path, input_path: Path) -> bool:
        try:
            stats = _read_json_object(task_root / "speed_stats.json")
        except AppError:
            return False
        expected = stats.get("original_input_sha256")
        if expected is None:
            stats_input = stats.get("input_file")
            try:
                same_input = (
                    isinstance(stats_input, str)
                    and Path(stats_input).resolve() == input_path.resolve()
                )
            except OSError:
                same_input = False
            expected = stats.get("sha256") if same_input else None
        if not isinstance(expected, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", expected
        ):
            return False
        digest = hashlib.sha256()
        try:
            with input_path.open("rb") as input_file:
                while chunk := input_file.read(1024 * 1024):
                    digest.update(chunk)
        except OSError:
            return False
        return digest.hexdigest() == expected.lower()

    def _response_from_artifacts(
        self,
        request: AnalyzeRequest,
        input_path: Path,
        paths: Any,
        *,
        returncode: int,
        rss_peak: int,
        timeout: float,
        reused: bool,
    ) -> AnalyzeResponse:
        manifest_path = paths.root / "manifest.json"
        log_path = paths.logs_dir / "pipeline.log"
        if not manifest_path.is_file():
            missing_code = (
                "INVALID_ANALYSIS_OUTPUT" if returncode == 0 else "ANALYSIS_FAILED"
            )
            raise AppError(
                code=missing_code,
                message="speed-analyze did not produce manifest.json",
                recoverable=returncode != 0,
                suggested_action="Inspect the local pipeline log.",
                details={"returncode": returncode, "log_path": str(log_path)},
            )
        raw_manifest = _read_json_object(manifest_path)
        if raw_manifest.get("analysis_id") != request.request_id:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Manifest analysis_id does not match the request",
                recoverable=False,
                suggested_action="Use an isolated artifact directory and rerun.",
            )
        error = raw_manifest.get("error")
        if returncode != 0 or raw_manifest.get("status") == "failed":
            if isinstance(error, dict):
                details = error.get("details") or {}
                if not isinstance(details, dict):
                    raise AppError(
                        code="INVALID_ANALYSIS_OUTPUT",
                        message="Manifest error details must be an object",
                        recoverable=False,
                        suggested_action="Check the speed-analyze manifest schema.",
                    )
                raise AppError(
                    code=str(error.get("code", "ANALYSIS_FAILED")),
                    message=str(error.get("message", "Speed analysis failed")),
                    recoverable=bool(error.get("recoverable", True)),
                    suggested_action=str(
                        error.get("suggested_action", "Inspect the pipeline log.")
                    ),
                    details=details,
                )
            raise AppError(
                code="ANALYSIS_FAILED",
                message="speed-analyze exited unsuccessfully",
                recoverable=True,
                suggested_action="Inspect the local pipeline log.",
                details={"returncode": returncode},
            )

        try:
            manifest = _ManifestModel.model_validate(raw_manifest)
            artifacts = _sanitize_artifacts(paths.root, manifest.artifact_paths)
            if not isinstance(artifacts, dict):
                raise TypeError("artifact_paths must be an object")
        except (TypeError, ValidationError) as exc:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Manifest does not match the required schema",
                recoverable=False,
                suggested_action="Check the speed-analyze version.",
            ) from exc
        if manifest.target is not request.target:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Manifest target does not match the requested direction",
                recoverable=False,
                suggested_action="Rerun with an isolated analysis_id.",
            )
        if Path(manifest.input_path).resolve() != input_path.resolve():
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Manifest input_path does not match the requested capture",
                recoverable=False,
                suggested_action="Discard stale artifacts and use a new analysis_id.",
            )
        summary_path = _artifact_path(
            paths.root, artifacts.get("tcp_analysis"), paths.tcp_analysis_json
        )
        coverage_path = _artifact_path(
            paths.root, artifacts.get("coverage"), paths.coverage_json
        )
        try:
            summary = _AnalysisSummary.model_validate(
                _read_json_object(summary_path)
            )
            coverage = CoverageSummary.model_validate(
                _read_json_object(coverage_path)
            )
        except ValidationError as exc:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Analysis summary does not match the required schema",
                recoverable=False,
                suggested_action="Check the speed-analyze version and rerun.",
            ) from exc
        serialized = summary.model_dump_json().lower()
        if "tcp.payload" in serialized or '"payload"' in serialized:
            raise AppError(
                code="INVALID_ANALYSIS_OUTPUT",
                message="Analysis summary contains forbidden packet payload fields",
                recoverable=False,
                suggested_action="Update speed-analyze and discard this summary.",
            )
        return AnalyzeResponse(
            analysis_id=request.request_id,
            status=manifest.status,
            target=manifest.target,
            coverage_summary=coverage,
            flow_summary=summary.flow_summary,
            tcp_summary=summary.tcp_summary,
            interval_summary=summary.interval_summary,
            syn_options=summary.syn_options,
            available_evidence=manifest.available_evidence,
            resource_usage={
                "rss_peak_bytes": rss_peak,
                "timeout_seconds": timeout,
                "returncode": returncode,
                "reused": reused,
            },
            warnings=manifest.warnings,
            artifact_paths=artifacts,
        )

    async def analyze(
        self,
        request: AnalyzeRequest,
        progress_callback: Callable[[float, float | None, str | None], Any]
        | None = None,
    ) -> AnalyzeResponse:
        input_path = Path(request.pcap_path)
        if not input_path.is_file():
            raise AppError(
                code="INVALID_CAPTURE",
                message="Capture path is not a readable file",
                recoverable=True,
                suggested_action="Provide an existing absolute pcap/pcapng path.",
                details={"path": request.pcap_path},
            )
        if not self.pipeline_script.is_file():
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze pipeline entry point was not found",
                recoverable=False,
                suggested_action="Configure the speed-analyze pipeline path.",
                details={"path": str(self.pipeline_script)},
            )

        task_root = self._analysis_root(request.request_id)
        fingerprint = self._request_fingerprint(request, input_path)
        if task_root.exists():
            manifest_path = task_root / "manifest.json"
            matches = self._matches_existing_request(task_root, fingerprint)
            if matches and manifest_path.is_file():
                existing_manifest = _read_json_object(manifest_path)
                if existing_manifest.get("status") in {
                    "completed",
                    "partial",
                } and await asyncio.to_thread(
                    self._matches_existing_content, task_root, input_path
                ):
                    existing_paths = self._artifacts.create(request.request_id)
                    return self._response_from_artifacts(
                        request,
                        input_path,
                        existing_paths,
                        returncode=0,
                        rss_peak=0,
                        timeout=0,
                        reused=True,
                    )
                if existing_manifest.get("status") == "failed":
                    shutil.rmtree(task_root)
            if task_root.exists():
                raise AppError(
                    code="ANALYSIS_ID_CONFLICT",
                    message="analysis_id is active or belongs to another request",
                    recoverable=True,
                    suggested_action=(
                        "Retry the same request later or use a new analysis_id."
                    ),
                    details={"path": str(task_root)},
                )
        self._artifacts.preflight(input_path, request.target)
        try:
            task_root.mkdir(exist_ok=False)
        except FileExistsError as exc:
            raise AppError(
                code="ANALYSIS_ID_CONFLICT",
                message="analysis_id already has local artifacts",
                recoverable=True,
                suggested_action="Use a new analysis_id for this capture.",
                details={"path": str(task_root)},
            ) from exc
        paths = self._artifacts.create(request.request_id)
        self._write_request_fingerprint(paths.root / "request.json", fingerprint)
        self._artifacts.mark_active(paths)
        try:
            log_path = paths.logs_dir / "pipeline.log"
            command = self._command(request, paths.root)
            timeout = self.timeout_calculator(input_path.stat().st_size)
            if progress_callback is not None:
                await _maybe_await(
                    progress_callback(0.0, None, "Starting speed analysis")
                )
            with log_path.open("ab", buffering=0) as log_file:
                try:
                    process = await asyncio.create_subprocess_exec(
                        *command,
                        stdout=log_file,
                        stderr=log_file,
                        **subprocess_group_options(),
                    )
                except OSError as exc:
                    shutil.rmtree(paths.root, ignore_errors=True)
                    raise AppError(
                        code="DEPENDENCY_UNAVAILABLE",
                        message="Unable to start speed-analyze",
                        recoverable=True,
                        suggested_action="Check Python and speed-analyze installation.",
                        details={"log_path": str(log_path)},
                    ) from exc
                returncode, rss_peak = await self._wait(
                    process,
                    timeout,
                    paths.root / "progress.jsonl",
                    progress_callback,
                )
            if progress_callback is not None:
                await _maybe_await(
                    progress_callback(1.0, 1.0, "Speed analysis process completed")
                )
            return self._response_from_artifacts(
                request,
                input_path,
                paths,
                returncode=returncode,
                rss_peak=rss_peak,
                timeout=timeout,
                reused=False,
            )
        finally:
            self._artifacts.mark_complete(paths)

    def _load_store_module(self) -> ModuleType:
        store_path = self.pipeline_script.parent / "lib" / "store.py"
        spec = importlib.util.spec_from_file_location(
            "packetmaster_speed_analyze_store", store_path
        )
        if spec is None or spec.loader is None:
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze evidence store could not be loaded",
                recoverable=False,
                suggested_action="Check the speed-analyze installation.",
            )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze evidence store could not be loaded",
                recoverable=False,
                suggested_action="Check the speed-analyze installation.",
                details={"path": str(store_path)},
            ) from exc
        if not hasattr(module, "AnalysisStore"):
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze evidence store has no AnalysisStore",
                recoverable=False,
                suggested_action="Check the speed-analyze installation.",
            )
        return module

    def _load_tshark_module(self) -> ModuleType:
        tshark_module = self.pipeline_script.parent / "lib" / "tshark.py"
        spec = importlib.util.spec_from_file_location(
            "packetmaster_speed_analyze_tshark", tshark_module
        )
        if spec is None or spec.loader is None:
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze TShark runtime could not be loaded",
                recoverable=False,
                suggested_action="Check the speed-analyze installation.",
            )
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as exc:
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="speed-analyze TShark runtime could not be loaded",
                recoverable=False,
                suggested_action="Check the speed-analyze installation.",
                details={"path": str(tshark_module)},
            ) from exc
        return module

    def _filtered_captures(self, root: Path) -> dict[str, Path]:
        manifest = _read_json_object(root / "manifest.json")
        artifacts = manifest.get("artifact_paths")
        filtered = (
            artifacts.get("filtered_captures")
            if isinstance(artifacts, dict)
            else None
        )
        if not isinstance(filtered, dict) or not filtered:
            raise AppError(
                code="EVIDENCE_UNAVAILABLE",
                message="No filtered capture is available for packet evidence",
                recoverable=True,
                suggested_action="Rerun the complete speed analysis.",
            )
        return {
            str(direction): _artifact_path(root, value, root / "filtered")
            for direction, value in filtered.items()
        }

    def _query_packet_evidence(
        self,
        root: Path,
        request: EvidenceRequest,
        cancel_event: threading.Event | None = None,
    ) -> tuple[
        list[dict[str, object]], int, bool, int | None, str, list[str]
    ]:
        tshark = self._load_tshark_module()
        try:
            tshark_path = tshark.find_tshark(self.tshark_path)
        except RuntimeError as exc:
            raise AppError(
                code="DEPENDENCY_UNAVAILABLE",
                message="TShark is unavailable for directed packet evidence",
                recoverable=True,
                suggested_action="Configure TSHARK_PATH and retry.",
            ) from exc
        captures = self._filtered_captures(root)
        filters = normalized_evidence_filters(request)
        summary = _AnalysisSummary.model_validate(
            _read_json_object(root / "tcp_analysis.json")
        )
        epoch_baseline = summary.timebase_epoch
        if (
            filters.time_start is not None or filters.time_end is not None
        ) and epoch_baseline is None:
            raise AppError(
                code="EVIDENCE_UNAVAILABLE",
                message="Packet evidence has no shared timestamp baseline",
                recoverable=True,
                suggested_action="Rerun the analysis with the current pipeline.",
            )
        requested_fields = (
            (request.query.fields if request.query else [])
            or request.fields
            or _DEFAULT_EVIDENCE_FIELDS
        )
        output_fields = list(
            dict.fromkeys(
                [
                    "evidence_id",
                    "frame.number",
                    "frame.time_relative",
                    "flow_id",
                    "direction",
                    *requested_fields,
                ]
            )
        )
        support_fields = list(
            dict.fromkeys(
                [
                    "frame.number",
                    "frame.time_relative",
                    "frame.time_epoch",
                    "ip.src",
                    "ip.dst",
                    "ipv6.src",
                    "ipv6.dst",
                    "tcp.srcport",
                    "tcp.dstport",
                    *[
                        field
                        for field in requested_fields
                        if field in _INTEGER_PACKET_FIELDS | _FLOAT_PACKET_FIELDS
                    ],
                    *[
                        field
                        for predicate in filters.predicates
                        if (field := _predicate_values(predicate)[0])
                        in _INTEGER_PACKET_FIELDS | _FLOAT_PACKET_FIELDS
                    ],
                    *(
                        list(_EVENT_PACKET_FIELDS)
                        if "event_type" in requested_fields
                        or any(
                            _predicate_values(predicate)[0] == "event_type"
                            for predicate in filters.predicates
                        )
                        else []
                    ),
                ]
            )
        )
        display_filter = _directed_display_filter(filters, epoch_baseline)
        items: list[dict[str, object]] = []
        matched = 0
        has_more = False
        source_directions: set[str] = set()
        for direction, capture in sorted(captures.items()):
            rows = tshark.stream_tshark_fields(
                tshark_path,
                capture,
                support_fields,
                display_filter,
                timeout_seconds=self.evidence_timeout_seconds,
                cancel_event=cancel_event,
            )
            try:
                for row in rows:
                    item = _packet_item(row, direction, epoch_baseline)
                    if item["flow_id"] is None:
                        continue
                    packet_time = item.get("frame.time_relative")
                    if (
                        filters.time_start is not None
                        and (packet_time is None or packet_time < filters.time_start)
                    ):
                        continue
                    if (
                        filters.time_end is not None
                        and (packet_time is None or packet_time > filters.time_end)
                    ):
                        continue
                    if filters.flow_ids and item["flow_id"] not in filters.flow_ids:
                        continue
                    if not all(
                        _matches_predicate(item, predicate)
                        for predicate in filters.predicates
                    ):
                        continue
                    source_directions.add(direction)
                    if matched < request.offset:
                        matched += 1
                        continue
                    if len(items) >= request.limit:
                        matched += 1
                        has_more = True
                        break
                    items.append({field: item.get(field) for field in output_fields})
                    matched += 1
            finally:
                close = getattr(rows, "close", None)
                if callable(close):
                    close()
            if has_more:
                break
        next_offset = request.offset + len(items) if has_more else None
        total = matched
        warnings = ["PACKET_QUERY_TOTAL_LOWER_BOUND"] if has_more else []
        source = (
            "filtered:" + ",".join(sorted(source_directions))
            if source_directions
            else "filtered:none"
        )
        return items, total, not has_more, next_offset, source, warnings

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        root = self._analysis_root(request.analysis_id)
        validate_evidence_request(request)
        database = root / "analysis.sqlite"
        use_indexed_packet_query = (
            request.evidence_type in PACKET_EVIDENCE_TYPES
            and database.is_file()
            and _packet_query_targets_indexed_events(request)
        )
        if (
            request.evidence_type in PACKET_EVIDENCE_TYPES
            and not use_indexed_packet_query
        ):
            cancel_event = threading.Event()
            query_task = asyncio.create_task(
                asyncio.to_thread(
                    self._query_packet_evidence, root, request, cancel_event
                )
            )

            async def stop_query() -> None:
                cancel_event.set()
                with suppress(BaseException):
                    await asyncio.shield(query_task)

            try:
                items, total, total_exact, next_offset, source, warnings = (
                    await asyncio.wait_for(
                        asyncio.shield(query_task),
                        timeout=self.evidence_timeout_seconds + 1,
                    )
                )
            except asyncio.CancelledError:
                await stop_query()
                raise
            except TimeoutError as exc:
                await stop_query()
                raise AppError(
                    code="EVIDENCE_TIMEOUT",
                    message="Directed packet evidence query timed out",
                    recoverable=True,
                    suggested_action="Narrow the flow or time range and retry.",
                ) from exc
        else:
            total_exact = True
            if not database.is_file():
                raise AppError(
                    code="EVIDENCE_UNAVAILABLE",
                    message="The local evidence index does not exist",
                    recoverable=True,
                    suggested_action="Rerun analysis with evidence indexing enabled.",
                )
            module = self._load_store_module()
            try:
                with module.AnalysisStore(database) as store:
                    store.initialize()
                    if (
                        request.evidence_type in EVENT_EVIDENCE_TYPES
                        or use_indexed_packet_query
                    ):
                        filters = normalized_evidence_filters(request)
                        fields = (
                            (request.query.fields if request.query else [])
                            or request.fields
                            or _DEFAULT_EVIDENCE_FIELDS
                        )
                        page = store.query_custom_page(
                            fields=fields,
                            predicates=filters.predicates,
                            flow_ids=filters.flow_ids,
                            time_start=filters.time_start,
                            time_end=filters.time_end,
                            offset=request.offset,
                            limit=request.limit,
                        )
                    elif request.evidence_type == "flow_summary":
                        page = store.query_flows(
                            request.offset, request.limit, request.flow_id
                        )
                    elif request.evidence_type in {
                        "io_timeline",
                        "throughput_distribution",
                    }:
                        page = store.query_intervals(request.offset, request.limit)
                    elif request.evidence_type == "syn_options":
                        page = store.query_syn_options(request.offset, request.limit)
                    elif request.evidence_type == "rtt_distribution":
                        page = store.query_summary(
                            request.offset, request.limit, "tcp_summary"
                        )
                    elif request.evidence_type in INDEXED_EVIDENCE_TYPES:
                        page = store.query_summary(request.offset, request.limit)
                    else:
                        raise ValueError("unsupported evidence registry entry")
                    items = list(page["items"])
                    total = int(page["total"])
                    next_offset = page["next_offset"]
                    source = str(database.resolve())
                    warnings = []
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                raise AppError(
                    code="UNSAFE_EVIDENCE_QUERY",
                    message=str(exc),
                    recoverable=False,
                    suggested_action=(
                        "Use only supported fields, operators, and values."
                    ),
                ) from exc
            except (sqlite3.Error, OSError) as exc:
                raise AppError(
                    code="EVIDENCE_UNAVAILABLE",
                    message="The local evidence index could not be read",
                    recoverable=True,
                    suggested_action="Rebuild the evidence index and retry.",
                    details={"path": str(database)},
                ) from exc
        return EvidenceResponse(
            analysis_id=request.analysis_id,
            evidence_type=request.evidence_type,
            summary={"returned": len(items)},
            items=items,
            total=total,
            total_exact=total_exact,
            next_offset=next_offset,
            truncated=next_offset is not None,
            source=source,
            coverage_range={
                "offset": request.offset,
                "limit": request.limit,
                "complete": next_offset is None,
            },
            warnings=warnings,
        )
