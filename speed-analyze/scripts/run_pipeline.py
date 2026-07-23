# ruff: noqa: E402
"""Run the complete, streaming speed-analyze capture pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_SRC = SCRIPT_DIR.parents[1] / "src"
for import_path in (PROJECT_SRC, SCRIPT_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from lib.aggregate import AggregationResult
from lib.progress import ProgressWriter
from lib.store import AnalysisStore
from lib.tshark import _terminate_process, find_tshark, normalize_capture
from tcp_extract import analyze_captures

from packetmaster.domain import Target

ANALYSIS_ID_PATTERN = re.compile(r"^[A-Za-z0-9._-]+$")


@dataclass
class PipelineError(Exception):
    code: str
    message: str
    recoverable: bool = False
    suggested_action: str = "Review the capture and pipeline parameters."
    details: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "recoverable": self.recoverable,
            "suggested_action": self.suggested_action,
            "details": self.details or {},
        }


@dataclass(frozen=True)
class SpeedStats:
    input_size_bytes: int
    total_packets: int
    total_tcp_packets: int
    filtered_files: dict[str, Path]
    written_counts: dict[str, int]


def _now() -> str:
    return datetime.now(UTC).isoformat()


def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def read_json_object(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8", errors="replace") as source:
            value = json.load(source)
    except (OSError, json.JSONDecodeError) as exc:
        raise PipelineError(
            "INVALID_ANALYSIS_OUTPUT",
            f"Could not read valid JSON output: {path.name}",
            details={"artifact": str(path)},
        ) from exc
    if not isinstance(value, dict):
        raise PipelineError(
            "INVALID_ANALYSIS_OUTPUT",
            f"Expected a JSON object: {path.name}",
            details={"artifact": str(path)},
        )
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _stats_error(message: str) -> PipelineError:
    return PipelineError(
        "INVALID_ANALYSIS_OUTPUT", f"Invalid speed_stats.json: {message}"
    )


def _stats_non_negative_int(stats: dict[str, Any], name: str) -> int:
    value = stats.get(name)
    if type(value) is not int or value < 0:
        raise _stats_error(f"{name} must be a non-negative integer")
    return value


def _validate_speed_stats(
    stats: dict[str, Any], normalized_capture: Path, target: Target
) -> SpeedStats:
    if stats.get("status") != "completed":
        raise _stats_error("status must be completed")
    input_file = stats.get("input_file")
    if not isinstance(input_file, str) or not input_file:
        raise _stats_error("input_file must be a path string")
    try:
        if Path(input_file).resolve() != normalized_capture.resolve():
            raise _stats_error("input_file does not match the normalized capture")
    except OSError as exc:
        raise _stats_error("input_file is invalid") from exc

    input_size_bytes = _stats_non_negative_int(stats, "input_size_bytes")
    if input_size_bytes != normalized_capture.stat().st_size:
        raise _stats_error("input_size_bytes does not match the normalized capture")
    sha256 = stats.get("sha256")
    if not isinstance(sha256, str) or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise _stats_error("sha256 must be 64 lowercase hexadecimal characters")

    total_packets = _stats_non_negative_int(stats, "total_packets")
    total_tcp_packets = _stats_non_negative_int(stats, "total_tcp_packets")
    total_flows = _stats_non_negative_int(stats, "total_flows")
    speed_flows_count = _stats_non_negative_int(stats, "speed_flows_count")
    download_flows_count = _stats_non_negative_int(stats, "download_flows_count")
    upload_flows_count = _stats_non_negative_int(stats, "upload_flows_count")
    _stats_non_negative_int(stats, "min_bytes")
    if total_tcp_packets > total_packets:
        raise _stats_error("total_tcp_packets must not exceed total_packets")
    if speed_flows_count > total_flows:
        raise _stats_error("speed_flows_count must not exceed total_flows")
    if speed_flows_count != download_flows_count + upload_flows_count:
        raise _stats_error("direction flow counts must equal speed_flows_count")

    min_ratio = stats.get("min_direction_ratio")
    if (
        isinstance(min_ratio, bool)
        or not isinstance(min_ratio, int | float)
        or not 0 <= min_ratio <= 1
    ):
        raise _stats_error("min_direction_ratio must be between 0 and 1")
    if type(stats.get("enable_strip")) is not bool:
        raise _stats_error("enable_strip must be boolean")
    if stats.get("target") != target.value:
        raise _stats_error("target does not match the pipeline target")
    speed_flows = stats.get("speed_flows")
    if not isinstance(speed_flows, list) or not all(
        isinstance(flow, dict) for flow in speed_flows
    ):
        raise _stats_error("speed_flows must be a list of objects")

    filtered_value = stats.get("filtered_files")
    written_value = stats.get("written_counts")
    if not isinstance(filtered_value, dict) or not isinstance(written_value, dict):
        raise _stats_error("filtered_files and written_counts must be objects")
    allowed = {"download", "upload"}
    if not filtered_value or set(filtered_value) - allowed:
        raise _stats_error("filtered_files has invalid direction keys")
    if set(written_value) != set(filtered_value):
        raise _stats_error("written_counts must match filtered_files directions")
    filtered_files: dict[str, Path] = {}
    written_counts: dict[str, int] = {}
    for direction, path_value in filtered_value.items():
        if not isinstance(path_value, str) or not Path(path_value).is_absolute():
            raise _stats_error(f"filtered_files.{direction} must be an absolute path")
        filtered_files[direction] = Path(path_value).resolve()
        count = written_value[direction]
        if type(count) is not int or count < 0:
            raise _stats_error(
                f"written_counts.{direction} must be a non-negative integer"
            )
        written_counts[direction] = count
    if sum(written_counts.values()) > total_tcp_packets:
        raise _stats_error("written_counts must not exceed total_tcp_packets")

    requested = {target.value} if target is not Target.BOTH else allowed
    if not set(filtered_files).issubset(requested):
        raise _stats_error("filtered_files contains an unrequested direction")
    if target is not Target.BOTH and set(filtered_files) != requested:
        raise _stats_error("filtered_files is missing the requested direction")

    return SpeedStats(
        input_size_bytes=input_size_bytes,
        total_packets=total_packets,
        total_tcp_packets=total_tcp_packets,
        filtered_files=filtered_files,
        written_counts=written_counts,
    )


def _validate_args(args: argparse.Namespace) -> tuple[Path, Path, Target]:
    input_path = Path(args.input)
    output_path = Path(args.output)
    if not input_path.is_absolute():
        raise PipelineError("INVALID_CAPTURE", "--input must be an absolute path")
    if not input_path.is_file():
        raise PipelineError("INVALID_CAPTURE", "--input must name an existing file")
    if not output_path.is_absolute():
        raise PipelineError("ANALYSIS_FAILED", "--output must be an absolute path")
    try:
        target = Target(args.target)
    except ValueError as exc:
        raise PipelineError(
            "ANALYSIS_FAILED", "--target must be download, upload, or both"
        ) from exc
    if not ANALYSIS_ID_PATTERN.fullmatch(args.analysis_id):
        raise PipelineError(
            "ANALYSIS_FAILED",
            "--analysis-id may contain only letters, digits, dot, underscore, "
            "and hyphen",
        )
    if not 1 <= args.interval <= 60:
        raise PipelineError("ANALYSIS_FAILED", "--interval must be between 1 and 60")
    if not 0 <= args.min_ratio <= 1:
        raise PipelineError("ANALYSIS_FAILED", "--min-ratio must be between 0 and 1")
    if args.min_bytes < 0:
        raise PipelineError("ANALYSIS_FAILED", "--min-bytes must be non-negative")
    return input_path.resolve(), output_path, target


def _tail(path: Path, limit: int = 8192) -> str:
    try:
        with path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            size = source.tell()
            source.seek(max(0, size - limit))
            return source.read(limit).decode("utf-8", errors="replace")
    except OSError:
        return ""


def _run_filter(
    input_path: Path,
    target: Target,
    filtered_dir: Path,
    stats_path: Path,
    progress_path: Path,
    log_path: Path,
    min_ratio: float,
    min_bytes: int,
) -> None:
    command = [
        sys.executable,
        str(SCRIPT_DIR / "speed_filter_strip.py"),
        "--input",
        str(input_path),
        "--target",
        target.value,
        "--output",
        str(filtered_dir),
        "--stats-output",
        str(stats_path),
        "--progress-path",
        str(progress_path),
        "--min-ratio",
        str(min_ratio),
        "--min-bytes",
        str(min_bytes),
    ]
    with log_path.open("w", encoding="utf-8", errors="replace") as log_file:
        try:
            process = subprocess.Popen(
                command,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise PipelineError(
                "ANALYSIS_FAILED", "Speed-flow filter could not start"
            ) from exc
        try:
            returncode = process.wait()
        except BaseException:
            _terminate_process(process)
            raise
    if returncode == 0:
        return
    log_tail = _tail(log_path)
    for code in ("NO_TCP_PACKETS", "NO_SPEED_FLOW", "INVALID_CAPTURE"):
        if code in log_tail:
            raise PipelineError(code, log_tail.strip().splitlines()[-1])
    raise PipelineError(
        "ANALYSIS_FAILED",
        f"Speed-flow filter exited with code {returncode}",
        details={"log": str(log_path)},
    )


def _merge_coverage(
    result: AggregationResult, stats: SpeedStats
) -> AggregationResult:
    coverage = result.coverage_summary.model_copy(
        update={
            "input_size_bytes": stats.input_size_bytes,
            "total_packets_seen": stats.total_packets,
            "tcp_packets_seen": stats.total_tcp_packets,
            "complete": True,
            "truncated": False,
            "truncation_reason": None,
        }
    )
    return AggregationResult(
        coverage_summary=coverage,
        tcp_summary=result.tcp_summary,
        flows=result.flows,
        intervals=result.intervals,
        events=result.events,
        syn_options=result.syn_options,
        timebase_epoch=result.timebase_epoch,
    )


def _artifact_paths(output: Path) -> dict[str, Any]:
    return {
        "manifest": str((output / "manifest.json").resolve()),
        "coverage": str((output / "coverage.json").resolve()),
        "speed_stats": str((output / "speed_stats.json").resolve()),
        "tcp_analysis": str((output / "tcp_analysis.json").resolve()),
        "progress": str((output / "progress.jsonl").resolve()),
        "logs": {"filter": str((output / "logs" / "filter.log").resolve())},
        "filtered_captures": {},
    }


def run(args: argparse.Namespace) -> int:
    started_at = _now()
    output = Path(args.output)
    manifest_path = (
        output / "manifest.json"
        if output.is_absolute()
        else output.resolve() / "manifest.json"
    )
    manifest: dict[str, Any] = {
        "analysis_id": args.analysis_id,
        "status": "failed",
        "target": args.target,
        "input_path": args.input,
        "normalized_capture_path": None,
        "coverage_summary": {},
        "artifact_paths": _artifact_paths(manifest_path.parent),
        "available_evidence": [],
        "warnings": [],
        "error": None,
        "started_at": started_at,
        "completed_at": None,
    }
    try:
        input_path, output, target = _validate_args(args)
        output.mkdir(parents=True, exist_ok=True)
        filtered_dir = output / "filtered"
        logs_dir = output / "logs"
        normalized_dir = output / "normalized"
        filtered_dir.mkdir(exist_ok=True)
        logs_dir.mkdir(exist_ok=True)
        manifest_path = output / "manifest.json"
        manifest["artifact_paths"] = _artifact_paths(output)
        manifest["input_path"] = str(input_path)
        manifest["target"] = target.value

        progress_path = output / "progress.jsonl"
        progress = ProgressWriter(progress_path)
        progress.emit("validate", 1, 1, "Inputs validated")
        try:
            tshark_path = find_tshark(args.tshark_path)
        except RuntimeError as exc:
            raise PipelineError(
                "DEPENDENCY_UNAVAILABLE",
                "TShark executable was not found",
                recoverable=True,
                suggested_action="Install Wireshark/TShark or pass --tshark-path.",
            ) from exc
        progress.emit("normalize", 0, 1, "Normalizing capture")
        try:
            normalized = normalize_capture(input_path, normalized_dir, tshark_path)
        except RuntimeError as exc:
            code = (
                "INVALID_CAPTURE"
                if str(exc).startswith("INVALID_CAPTURE")
                else "ANALYSIS_FAILED"
            )
            raise PipelineError(code, str(exc).split(":", 1)[-1].strip()) from exc
        manifest["normalized_capture_path"] = str(normalized)
        progress.emit("normalize", 1, 1, "Capture normalized")

        stats_path = output / "speed_stats.json"
        filter_log = logs_dir / "filter.log"
        _run_filter(
            normalized,
            target,
            filtered_dir,
            stats_path,
            progress_path,
            filter_log,
            args.min_ratio,
            args.min_bytes,
        )
        raw_stats = read_json_object(stats_path)
        stats = _validate_speed_stats(raw_stats, normalized, target)
        raw_stats["original_input_sha256"] = (
            raw_stats["sha256"]
            if normalized.resolve() == input_path.resolve()
            else _sha256_file(input_path)
        )
        atomic_write_json(stats_path, raw_stats)
        captures: dict[str, Path] = {}
        for direction, capture in stats.filtered_files.items():
            if not capture.is_file():
                raise PipelineError(
                    "INVALID_ANALYSIS_OUTPUT",
                    f"Filtered capture is missing: {direction}",
                )
            captures[direction] = capture.resolve()
        requested = (
            {target.value} if target is not Target.BOTH else {"download", "upload"}
        )
        if not captures or not set(captures).issubset(requested):
            raise PipelineError(
                "NO_SPEED_FLOW", "No requested speed-flow capture exists"
            )
        if target is not Target.BOTH and set(captures) != requested:
            raise PipelineError("NO_SPEED_FLOW", f"No {target.value} speed flow exists")
        status = "completed"
        if target is Target.BOTH and set(captures) != requested:
            missing = sorted(requested - set(captures))
            status = "partial"
            manifest["warnings"].append(
                f"No matching {'/'.join(missing)} speed flow was found."
            )

        database_path = (
            output / "analysis.sqlite" if args.build_evidence_index else None
        )
        result = analyze_captures(
            captures,
            target,
            args.interval,
            database_path,
            tshark_path,
            stats.input_size_bytes,
            progress,
        )
        result = _merge_coverage(result, stats)
        timing = result.tcp_summary.get("timing", {})
        timing_available = timing.get("available") is True
        timing_complete = timing.get("complete") is True
        if not timing_complete:
            status = "partial"
            manifest["warnings"].append(
                "Packet timestamps are unavailable for some or all analyzed packets; "
                "temporal duration, intervals, and time-based throughput are "
                "incomplete."
            )
        if database_path is not None:
            with AnalysisStore(database_path) as store:
                store.initialize()
                store.write_result(result)

        summary = result.to_summary_dict()
        coverage = result.coverage_summary.model_dump(mode="json")
        private_field_markers = (
            "tcp." + "payload",
            "per_packet" + "_fields",
            "Pay" + "load",
        )
        if any(marker in json.dumps(summary) for marker in private_field_markers):
            raise PipelineError(
                "INVALID_ANALYSIS_OUTPUT", "TCP summary contains packet payload fields"
            )
        atomic_write_json(output / "tcp_analysis.json", summary)
        atomic_write_json(output / "coverage.json", coverage)

        artifacts = manifest["artifact_paths"]
        artifacts["filtered_captures"] = {
            direction: str(path) for direction, path in captures.items()
        }
        if database_path is not None:
            artifacts["analysis_db"] = str(database_path.resolve())
        manifest["status"] = status
        manifest["coverage_summary"] = coverage
        manifest["available_evidence"] = ["summary", "flows"]
        if timing_available:
            manifest["available_evidence"].append("intervals")
        if database_path is not None:
            manifest["available_evidence"].append("events")
        manifest["error"] = None
        progress.emit("complete", 1, 1, f"Analysis {status}")
        return_code = 0
    except PipelineError as exc:
        manifest["error"] = exc.to_dict()
        return_code = 1
    except Exception as exc:
        manifest["error"] = PipelineError(
            "ANALYSIS_FAILED", str(exc) or exc.__class__.__name__
        ).to_dict()
        return_code = 1
    finally:
        manifest["completed_at"] = _now()
        try:
            atomic_write_json(manifest_path, manifest)
        except OSError:
            return_code = 1
    return return_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run full streaming speed analysis")
    parser.add_argument(
        "--input", required=True, help="Absolute pcap/pcapng input path"
    )
    parser.add_argument(
        "--target", default="download", help="download, upload, or both"
    )
    parser.add_argument(
        "--output", required=True, help="Absolute analysis output directory"
    )
    parser.add_argument(
        "--analysis-id", required=True, help="Stable analysis identifier"
    )
    parser.add_argument(
        "--interval", type=int, default=1, help="Interval seconds (1..60)"
    )
    parser.add_argument(
        "--build-evidence-index",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Build analysis.sqlite evidence index (default: enabled)",
    )
    parser.add_argument("--tshark-path", help="Optional explicit TShark executable")
    parser.add_argument("--min-ratio", type=float, default=0.70)
    parser.add_argument("--min-bytes", type=int, default=100 * 1024)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
