"""Adapter that runs the local speed-analyze pipeline without buffering captures."""

from __future__ import annotations

import asyncio
import importlib.util
import json
import re
import sqlite3
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

import psutil
from pydantic import BaseModel, ConfigDict, ValidationError

from packetmaster.analyzer.base import (
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
    if asyncio.iscoroutine(value):
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
    ) -> None:
        self.artifact_root = Path(artifact_root).expanduser().resolve()
        self.pipeline_script = (
            Path(pipeline_script).expanduser().resolve()
            if pipeline_script is not None
            else Path(__file__).resolve().parents[3]
            / "speed-analyze"
            / "scripts"
            / "run_pipeline.py"
        )
        self.tshark_path = tshark_path
        self.timeout_calculator = timeout_calculator
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
        if task_root.exists() and any(task_root.iterdir()):
            raise AppError(
                code="ANALYSIS_ID_CONFLICT",
                message="analysis_id already has local artifacts",
                recoverable=True,
                suggested_action="Use a new analysis_id for this capture.",
                details={"path": str(task_root)},
            )
        self._artifacts.preflight(input_path, request.target)
        paths = self._artifacts.create(request.request_id)
        log_path = paths.logs_dir / "pipeline.log"
        command = self._command(request, paths.root)
        timeout = self.timeout_calculator(input_path.stat().st_size)
        if progress_callback is not None:
            await _maybe_await(progress_callback(0.0, None, "Starting speed analysis"))
        with log_path.open("ab", buffering=0) as log_file:
            try:
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=log_file,
                    stderr=log_file,
                    **subprocess_group_options(),
                )
            except OSError as exc:
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

        manifest_path = paths.root / "manifest.json"
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
            },
            warnings=manifest.warnings,
            artifact_paths=artifacts,
        )

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

    async def get_evidence(self, request: EvidenceRequest) -> EvidenceResponse:
        root = self._analysis_root(request.analysis_id)
        validate_evidence_request(request)
        database = root / "analysis.sqlite"
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
                if request.query is None:
                    event_type = (
                        None
                        if request.evidence_type == "events"
                        else request.evidence_type
                    )
                    page = store.query_events(
                        event_type=event_type,
                        flow_id=request.flow_id,
                        time_start=request.time_start,
                        time_end=request.time_end,
                        offset=request.offset,
                        limit=request.limit,
                    )
                    items = list(page["items"])
                    total = int(page["total"])
                    next_offset = page["next_offset"]
                    warnings: list[str] = []
                else:
                    query = request.query
                    filters = normalized_evidence_filters(request)
                    fields = query.fields or request.fields or _DEFAULT_EVIDENCE_FIELDS
                    items = store.query_custom(
                        fields=fields,
                        predicates=filters.predicates,
                        flow_ids=filters.flow_ids,
                        time_start=filters.time_start,
                        time_end=filters.time_end,
                        offset=request.offset,
                        limit=request.limit,
                    )
                    probe = store.query_custom(
                        fields=fields,
                        predicates=filters.predicates,
                        flow_ids=filters.flow_ids,
                        time_start=filters.time_start,
                        time_end=filters.time_end,
                        offset=request.offset + len(items),
                        limit=1,
                    )
                    has_more = bool(probe)
                    next_offset = request.offset + len(items) if has_more else None
                    total = request.offset + len(items) + (1 if has_more else 0)
                    warnings = (
                        ["Custom-query total is a lower bound while more rows exist."]
                        if has_more
                        else []
                    )
        except (TypeError, ValueError) as exc:
            raise AppError(
                code="UNSAFE_EVIDENCE_QUERY",
                message=str(exc),
                recoverable=False,
                suggested_action="Use only supported fields, operators, and values.",
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
            next_offset=next_offset,
            truncated=next_offset is not None,
            source=str(database.resolve()),
            coverage_range={
                "offset": request.offset,
                "limit": request.limit,
                "complete": next_offset is None,
            },
            warnings=warnings,
        )
