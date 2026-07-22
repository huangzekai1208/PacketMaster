# ruff: noqa: E402
"""Stream filtered captures into TCP aggregates and optional SQLite evidence."""

from __future__ import annotations

import sys
from decimal import Decimal, InvalidOperation
from itertools import chain
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_SRC = SCRIPT_DIR.parents[1] / "src"
for import_path in (PROJECT_SRC, SCRIPT_DIR):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

from lib.aggregate import AggregationResult, TcpAccumulator
from lib.store import AnalysisStore
from lib.tshark import stream_tshark_fields

from packetmaster.domain import Target

EXTRACT_FIELDS = [
    "frame.time_epoch",
    "frame.time_relative",
    "frame.number",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq",
    "tcp.ack",
    "tcp.hdr_len",
    "tcp.len",
    "tcp.window_size_value",
    "tcp.window_size",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
    "tcp.flags.push",
    "tcp.flags.urg",
    "tcp.flags.ece",
    "tcp.flags.cwr",
    "tcp.options.mss_val",
    "tcp.options.wscale.shift",
    "tcp.options.sack_perm",
    "tcp.options.timestamp.tsval",
    "tcp.options.timestamp.tsecr",
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
]


def _packet_epoch(row: dict[str, str]) -> Decimal:
    value = row.get("frame.time_epoch", "").strip()
    try:
        epoch = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"invalid frame.time_epoch: {value}") from exc
    if not epoch.is_finite():
        raise ValueError(f"invalid frame.time_epoch: {value}")
    return epoch


def _validated_captures(captures: dict[str, Path], target: Target) -> dict[str, Path]:
    if not captures:
        raise ValueError("captures must include at least one requested direction")
    invalid = set(captures) - {Target.DOWNLOAD.value, Target.UPLOAD.value}
    if invalid:
        raise ValueError(f"unsupported capture directions: {sorted(invalid)}")
    if target is not Target.BOTH and set(captures) != {target.value}:
        raise ValueError(f"captures must contain only the {target.value} direction")

    validated: dict[str, Path] = {}
    for direction, capture in captures.items():
        path = Path(capture)
        if not path.is_file():
            raise ValueError(f"capture does not exist: {path}")
        validated[direction] = path.resolve()
    return validated


def _with_input_size(
    result: AggregationResult, input_size_bytes: int
) -> AggregationResult:
    coverage = result.coverage_summary.model_copy(
        update={"input_size_bytes": input_size_bytes}
    )
    return AggregationResult(
        coverage_summary=coverage,
        tcp_summary=result.tcp_summary,
        flows=result.flows,
        intervals=result.intervals,
        events=result.events,
        syn_options=result.syn_options,
    )


def analyze_captures(
    captures: dict[str, Path],
    target: Target | str,
    interval_seconds: int,
    database_path: Path | None,
    tshark_path: Path,
    input_size_bytes: int,
    progress_writer=None,
) -> AggregationResult:
    """Analyze every TCP row from each requested filtered capture."""
    parsed_target = Target(target)
    validated = _validated_captures(captures, parsed_target)
    if input_size_bytes < 0:
        raise ValueError("input_size_bytes must be non-negative")

    store = AnalysisStore(Path(database_path)) if database_path is not None else None
    event_sink = store.append_event if store is not None else lambda event: None
    accumulator = TcpAccumulator(
        interval_seconds=interval_seconds,
        target=parsed_target,
        event_sink=event_sink,
    )

    try:
        if store is not None:
            store.initialize()
        streams: dict[str, tuple[dict[str, str], object]] = {}
        close_streams = []
        first_epochs: list[Decimal] = []
        for direction, capture in validated.items():
            if progress_writer is not None:
                progress_writer.emit(
                    "tcp_extract", 0, None, f"Extracting all {direction} TCP packets"
                )
            iterator = iter(
                stream_tshark_fields(
                    Path(tshark_path), capture, EXTRACT_FIELDS, display_filter="tcp"
                )
            )
            close = getattr(iterator, "close", None)
            if close is not None:
                close_streams.append(close)
            first_row = next(iterator, None)
            if first_row is not None:
                streams[direction] = (first_row, iterator)
                first_epochs.append(_packet_epoch(first_row))

        baseline = min(first_epochs) if first_epochs else Decimal(0)
        for direction, (first_row, iterator) in streams.items():
            count = 0
            for row in chain((first_row,), iterator):
                normalized_row = dict(row)
                normalized_row["frame.time_relative"] = str(
                    _packet_epoch(row) - baseline
                )
                accumulator.observe(normalized_row, direction)
                count += 1
                if progress_writer is not None and count % 100_000 == 0:
                    progress_writer.emit(
                        "tcp_extract",
                        count,
                        None,
                        f"Extracted {count} {direction} TCP packets",
                    )
            if progress_writer is not None:
                progress_writer.emit(
                    "tcp_extract",
                    count,
                    count,
                    f"Completed {direction} TCP extraction",
                )

        result = _with_input_size(accumulator.finalize(), input_size_bytes)
        if store is not None:
            store.write_result(result)
        return result
    finally:
        for close in locals().get("close_streams", []):
            close()
        if store is not None:
            store.close()
