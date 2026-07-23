from __future__ import annotations

import asyncio
import hashlib
import io
import json
import sqlite3
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.domain import (
    CustomEvidenceQuery,
    EvidenceOperator,
    EvidencePredicate,
    EvidenceRequest,
)
from tests.helpers import load_script_module

ROOT = Path(__file__).resolve().parents[2]
RUN_PIPELINE = ROOT / "speed-analyze" / "scripts" / "run_pipeline.py"
FILTER_SCRIPT = ROOT / "speed-analyze" / "scripts" / "speed_filter_strip.py"
CAPTURE_GENERATOR = ROOT / "scripts" / "generate_test_capture.py"


def run_pipeline(
    capture: Path | str,
    output: Path,
    *,
    tshark_path: Path,
    analysis_id: str = "integration-test",
    target: str | None = "download",
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(RUN_PIPELINE),
        "--input",
        str(capture),
        "--output",
        str(output),
        "--analysis-id",
        analysis_id,
        "--tshark-path",
        str(tshark_path),
        "--min-bytes",
        "1",
        "--min-ratio",
        "0.65",
    ]
    if target is not None:
        command.extend(["--target", target])
    return subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def read_json(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as json_file:
        value = json.load(json_file)
    assert isinstance(value, dict)
    return value


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def generate_capture(output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CAPTURE_GENERATOR),
            "--output",
            str(output),
            "--flows",
            "2",
            "--data-packets-per-flow",
            "2500",
            "--anomaly-after",
            "5000",
            "--zero-window",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )


def run_filter(capture: Path, output: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(FILTER_SCRIPT),
            "--input",
            str(capture),
            "--output",
            str(output / "filtered"),
            "--target",
            "download",
            "--stats-output",
            str(output / "speed_stats.json"),
            "--progress-path",
            str(output / "progress.jsonl"),
            "--min-bytes",
            "1",
            "--min-ratio",
            "0.65",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )


def test_spb_filter_does_not_copy_non_target_packets(
    tmp_path: Path, spb_capture: Path, tshark_path: Path
) -> None:
    output = tmp_path / "spb output"

    result = run_filter(spb_capture, output)

    assert result.returncode == 0, result.stdout + result.stderr
    stats = read_json(output / "speed_stats.json")
    filtered_capture = stats["filtered_files"]["download"]
    tshark_result = subprocess.run(
        [
            str(tshark_path),
            "-r",
            filtered_capture,
            "-T",
            "fields",
            "-e",
            "tcp.srcport",
            "-e",
            "tcp.dstport",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert tshark_result.returncode == 0, tshark_result.stderr
    assert "41000" in tshark_result.stdout
    assert "42000" not in tshark_result.stdout
    assert "5202" not in tshark_result.stdout


def test_fingerprint_completes_during_first_scan_before_filter_write(
    tmp_path: Path, spb_capture: Path
) -> None:
    output = tmp_path / "fingerprint output"

    result = run_filter(spb_capture, output)

    assert result.returncode == 0, result.stdout + result.stderr
    events = [
        json.loads(line)
        for line in (output / "progress.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    fingerprint_complete = next(
        index
        for index, event in enumerate(events)
        if event["stage"] == "fingerprint" and event["current"] == event["total"]
    )
    filter_write_start = next(
        index
        for index, event in enumerate(events)
        if event["stage"] == "filter_write" and event["current"] == 0
    )
    assert fingerprint_complete < filter_write_start


def test_real_spb_pipeline_keeps_non_temporal_metrics_and_warns_about_time(
    tmp_path: Path, spb_capture: Path, tshark_path: Path
) -> None:
    output = (tmp_path / "spb full pipeline").resolve()

    result = run_pipeline(spb_capture, output, tshark_path=tshark_path)

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = read_json(output / "manifest.json")
    stats = read_json(output / "speed_stats.json")
    coverage = read_json(output / "coverage.json")
    analysis = read_json(output / "tcp_analysis.json")
    assert manifest["status"] == "partial"
    assert any("timestamp" in warning.lower() for warning in manifest["warnings"])
    assert coverage["complete"] is True
    assert coverage["truncated"] is False
    assert coverage["speed_packets_analyzed"] == stats["written_counts"]["download"]
    assert analysis["tcp_summary"]["packet_count"] > 0
    assert analysis["tcp_summary"]["payload_bytes"] > 0
    assert analysis["tcp_summary"]["timing"] == {
        "available": False,
        "complete": False,
        "timed_packets": 0,
        "untimed_packets": coverage["speed_packets_analyzed"],
    }
    assert analysis["interval_summary"] == []
    assert "intervals" not in manifest["available_evidence"]


class GuardedBlockReader(io.BytesIO):
    def __init__(self, value: bytes, max_read: int = 64) -> None:
        super().__init__(value)
        self.max_read = max_read
        self.read_sizes: list[int] = []

    def read(self, size: int = -1) -> bytes:
        self.read_sizes.append(size)
        assert 0 <= size <= self.max_read, f"unsafe declared-length read: {size}"
        return super().read(size)

    def __enter__(self):
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


@pytest.mark.parametrize("declared_length", [4, 0xFFFFFFFC])
def test_read_blocks_rejects_unsafe_lengths_before_declared_size_read(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    declared_length: int,
) -> None:
    module = load_script_module(
        "speed_filter_strip.py", f"task5_filter_length_{declared_length}"
    )
    capture = tmp_path / "malformed.pcapng"
    capture.write_bytes(struct.pack("<II", 1, declared_length))
    reader = GuardedBlockReader(capture.read_bytes())
    original_open = module.Path.open

    def guarded_open(path: Path, *args: object, **kwargs: object):
        if path == capture:
            return reader
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(module.Path, "open", guarded_open)

    with pytest.raises(RuntimeError, match=r"^INVALID_CAPTURE"):
        next(module._read_blocks(capture))

    assert max(reader.read_sizes) <= 64


@pytest.mark.parametrize(
    "block",
    [
        struct.pack("<III", 1, 14, 14) + b"xx",
        struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 16),
    ],
    ids=["misaligned", "trailer-mismatch"],
)
def test_read_blocks_rejects_misaligned_and_mismatched_trailer(
    tmp_path: Path, block: bytes
) -> None:
    module = load_script_module("speed_filter_strip.py", "task5_filter_structure")
    capture = tmp_path / "malformed.pcapng"
    capture.write_bytes(block)

    with pytest.raises(RuntimeError, match=r"^INVALID_CAPTURE"):
        next(module._read_blocks(capture))


def test_run_pipeline_help_has_full_streaming_contract() -> None:
    result = subprocess.run(
        [sys.executable, str(RUN_PIPELINE), "--help"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
    )

    assert result.returncode == 0
    for option in (
        "--analysis-id",
        "--interval",
        "--build-evidence-index",
        "--no-build-evidence-index",
        "--tshark-path",
    ):
        assert option in result.stdout
    assert "--max-packets" not in result.stdout


def test_real_download_pipeline_writes_complete_private_artifacts(
    tmp_path: Path, sample_capture: Path, tshark_path: Path
) -> None:
    unicode_capture = tmp_path / "输入 报文" / "测速 样本.pcapng"
    unicode_capture.parent.mkdir()
    unicode_capture.write_bytes(sample_capture.read_bytes())
    output = (tmp_path / "分析 output" / "任务 一").resolve()

    result = run_pipeline(unicode_capture.resolve(), output, tshark_path=tshark_path)

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = read_json(output / "manifest.json")
    coverage = read_json(output / "coverage.json")
    stats = read_json(output / "speed_stats.json")
    analysis = read_json(output / "tcp_analysis.json")
    assert manifest["status"] == "completed"
    assert manifest["target"] == "download"
    assert coverage["complete"] is True
    assert coverage["truncated"] is False
    assert coverage["total_packets_seen"] == stats["total_packets"]
    assert coverage["tcp_packets_seen"] == stats["total_tcp_packets"]
    assert coverage["speed_packets_analyzed"] > 0
    assert stats["input_size_bytes"] == unicode_capture.stat().st_size
    assert stats["sha256"] == hashlib.sha256(unicode_capture.read_bytes()).hexdigest()
    assert set(stats["filtered_files"]) == {"download"}
    for name in (
        "manifest.json",
        "coverage.json",
        "speed_stats.json",
        "tcp_analysis.json",
        "progress.jsonl",
        "analysis.sqlite",
    ):
        assert (output / name).is_file()
    serialized = json.dumps(
        {
            "manifest": manifest,
            "coverage": coverage,
            "stats": stats,
            "analysis": analysis,
        }
    )
    for forbidden in ("per_packet_fields", "Payload", "tcp.payload"):
        assert forbidden not in serialized
    with sqlite3.connect(output / "analysis.sqlite") as connection:
        schema = " ".join(
            row[0]
            for row in connection.execute(
                "SELECT sql FROM sqlite_master WHERE sql IS NOT NULL"
            )
        )
    assert "payload" not in schema.lower()


@pytest.mark.parametrize(
    ("target", "expected"),
    [(None, {"download"}), ("upload", {"upload"}), ("both", {"download", "upload"})],
)
def test_real_pipeline_keeps_requested_direction(
    tmp_path: Path,
    sample_capture: Path,
    tshark_path: Path,
    target: str | None,
    expected: set[str],
) -> None:
    output = (tmp_path / f"route-{target or 'default'}").resolve()

    result = run_pipeline(
        sample_capture, output, tshark_path=tshark_path, target=target
    )

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = read_json(output / "manifest.json")
    stats = read_json(output / "speed_stats.json")
    assert manifest["target"] == (target or "download")
    assert set(stats["filtered_files"]) == expected
    filtered = manifest["artifact_paths"]["filtered_captures"]
    assert set(filtered) == expected
    assert len(set(filtered.values())) == len(expected)


def test_generated_multiflow_capture_indexes_evidence_after_packet_5000(
    tmp_path: Path, tshark_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    api_key = "sk-release-gate-secret"
    monkeypatch.setenv("MODEL_API_KEY", api_key)
    capture = (tmp_path / "generated" / "多流 后段异常.pcapng").resolve()
    generated = generate_capture(capture)
    assert generated.returncode == 0, generated.stdout + generated.stderr
    metadata = json.loads(generated.stdout)
    assert metadata["anomaly_start_frame"] > 5000
    duplicate = (tmp_path / "generated" / "deterministic-copy.pcapng").resolve()
    duplicate_result = generate_capture(duplicate)
    assert duplicate_result.returncode == 0
    assert sha256_file(capture) == sha256_file(duplicate)

    output = (tmp_path / "generated-analysis").resolve()
    result = run_pipeline(capture, output, tshark_path=tshark_path)

    assert result.returncode == 0, result.stdout + result.stderr
    coverage = read_json(output / "coverage.json")
    analysis = read_json(output / "tcp_analysis.json")
    assert coverage["speed_packets_analyzed"] > 5000
    assert coverage["complete"] is True
    assert coverage["truncated"] is False
    assert len(analysis["flow_summary"]) >= 2
    with sqlite3.connect(output / "analysis.sqlite") as connection:
        late_events = connection.execute(
            "SELECT frame_number, event_type FROM events "
            "WHERE frame_number > 5000 ORDER BY frame_number"
        ).fetchall()
    assert late_events
    assert {event_type for _, event_type in late_events} >= {
        "retransmission",
        "duplicate_ack",
        "zero_window",
    }
    text_artifacts = result.stdout + result.stderr
    for path in output.rglob("*"):
        if path.suffix in {".json", ".jsonl"}:
            text_artifacts += path.read_text(encoding="utf-8")
    assert api_key not in text_artifacts


def test_real_adapter_queries_indexed_summary_and_normal_packet_fields(
    tmp_path: Path, sample_capture: Path, tshark_path: Path
) -> None:
    artifact_root = (tmp_path / "query-artifacts").resolve()
    analysis_id = "evidence-query"
    output = artifact_root / analysis_id
    result = run_pipeline(
        sample_capture,
        output,
        tshark_path=tshark_path,
        analysis_id=analysis_id,
        target="both",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    adapter = RealAnalyzerAdapter(
        artifact_root=artifact_root,
        tshark_path=str(tshark_path),
    )

    flow_page = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id=analysis_id,
                evidence_type="flow_summary",
                limit=10,
            )
        )
    )
    packet_page = asyncio.run(
        adapter.get_evidence(
            EvidenceRequest(
                analysis_id=analysis_id,
                evidence_type="custom_packet_query",
                query=CustomEvidenceQuery(
                    fields=["frame.number", "flow_id", "tcp.len"],
                    predicates=[
                        EvidencePredicate(
                            field="tcp.len",
                            operator=EvidenceOperator.GT,
                            value=0,
                        )
                    ],
                ),
                limit=2,
            )
        )
    )

    assert flow_page.total >= 2
    assert all("flow_id" in item for item in flow_page.items)
    assert packet_page.total >= 2
    assert len(packet_page.items) == 2
    assert all(
        item["frame.number"] > 0 and item["flow_id"] and item["tcp.len"] > 0
        for item in packet_page.items
    )
    assert packet_page.source == "filtered:download"
    assert packet_page.total_exact is False
    assert packet_page.warnings == ["PACKET_QUERY_TOTAL_LOWER_BOUND"]


def test_analyze_captures_streams_past_5000_and_indexes_final_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract")
    capture = tmp_path / "filtered.pcapng"
    capture.write_bytes(b"fixture")

    def rows(*args: object, **kwargs: object):
        for number in range(1, 5002):
            yield {
                "frame.number": str(number),
                "frame.time_relative": str((number - 1) / 1000),
                "frame.time_epoch": str(100 + (number - 1) / 1000),
                "ip.src": "198.51.100.20",
                "ip.dst": "192.0.2.10",
                "ipv6.src": "",
                "ipv6.dst": "",
                "tcp.srcport": "5201",
                "tcp.dstport": "41000",
                "tcp.seq": str(number),
                "tcp.ack": "2",
                "tcp.len": "100",
                "tcp.window_size": "65535",
                "tcp.flags.syn": "1" if number == 1 else "",
                "tcp.options.mss_val": "1460" if number == 1 else "",
                "tcp.options.wscale.shift": "7" if number == 1 else "",
                "tcp.options.sack_perm": "1" if number == 1 else "",
                "tcp.analysis.zero_window": "1" if number == 5001 else "",
            }

    monkeypatch.setattr(module, "stream_tshark_fields", rows)
    database = tmp_path / "analysis.sqlite"

    result = module.analyze_captures(
        {"download": capture},
        "download",
        1,
        database,
        Path("tshark"),
        capture.stat().st_size,
    )

    assert result.coverage_summary.speed_packets_analyzed == 5001
    assert result.coverage_summary.truncated is False
    assert result.events == []
    with sqlite3.connect(database) as connection:
        final_event = connection.execute(
            "SELECT frame_number, event_type FROM events WHERE frame_number = 5001"
        ).fetchone()
    assert final_event == (5001, "zero_window")


def test_no_evidence_index_discards_events(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_no_db")
    capture = tmp_path / "filtered.pcapng"
    capture.write_bytes(b"fixture")
    row = {
        "frame.number": "1",
        "frame.time_relative": "0",
        "frame.time_epoch": "100",
        "ip.src": "198.51.100.20",
        "ip.dst": "192.0.2.10",
        "ipv6.src": "",
        "ipv6.dst": "",
        "tcp.srcport": "5201",
        "tcp.dstport": "41000",
        "tcp.len": "1",
        "tcp.analysis.retransmission": "1",
    }
    monkeypatch.setattr(
        module, "stream_tshark_fields", lambda *args, **kwargs: iter([row])
    )

    result = module.analyze_captures(
        {"download": capture}, "download", 1, None, Path("tshark"), 1
    )

    assert result.events == []


def test_both_captures_use_one_epoch_timebase_without_overlapping_intervals(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_epoch")
    download_capture = tmp_path / "download.pcapng"
    upload_capture = tmp_path / "upload.pcapng"
    download_capture.write_bytes(b"download")
    upload_capture.write_bytes(b"upload")

    def row(number: int, epoch: float, direction: str) -> dict[str, str]:
        download = direction == "download"
        return {
            "frame.number": str(number),
            "frame.time_relative": str(epoch % 10),
            "frame.time_epoch": str(epoch),
            "ip.src": "198.51.100.20" if download else "192.0.2.10",
            "ip.dst": "192.0.2.10" if download else "198.51.100.20",
            "ipv6.src": "",
            "ipv6.dst": "",
            "tcp.srcport": "5201" if download else "41000",
            "tcp.dstport": "41000" if download else "5201",
            "tcp.len": "100",
        }

    def rows(
        tshark_path: Path,
        capture: Path,
        fields: list[str],
        display_filter: str,
    ):
        assert "frame.time_epoch" in fields
        direction = "download" if capture == download_capture else "upload"
        start = 100.0 if direction == "download" else 110.0
        yield row(1, start, direction)
        yield row(2, start + 0.2, direction)

    monkeypatch.setattr(module, "stream_tshark_fields", rows)

    result = module.analyze_captures(
        {"download": download_capture, "upload": upload_capture},
        "both",
        1,
        None,
        Path("tshark"),
        16,
    )

    interval_starts = {
        interval["direction"]: interval["interval_start"]
        for interval in result.intervals
    }
    assert interval_starts == {"download": 0.0, "upload": 10.0}
    assert result.coverage_summary.analyzed_duration_seconds == pytest.approx(10.2)
    assert result.timebase_epoch == 100.0


def _timing_row(
    number: int,
    epoch: float | None,
    direction: str,
    *,
    retransmission: bool = False,
) -> dict[str, str]:
    download = direction == "download"
    return {
        "frame.number": str(number),
        "frame.time_relative": "",
        "frame.time_epoch": "" if epoch is None else str(epoch),
        "ip.src": "198.51.100.20" if download else "192.0.2.10",
        "ip.dst": "192.0.2.10" if download else "198.51.100.20",
        "ipv6.src": "",
        "ipv6.dst": "",
        "tcp.srcport": "5201" if download else "41000",
        "tcp.dstport": "41000" if download else "5201",
        "tcp.len": "100",
        "tcp.analysis.retransmission": "1" if retransmission else "",
    }


def test_single_capture_recovers_timing_after_leading_untimed_packet(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_late_epoch")
    capture = tmp_path / "download.pcapng"
    capture.write_bytes(b"download")
    rows = iter(
        [
            _timing_row(1, None, "download", retransmission=True),
            _timing_row(2, 100.0, "download"),
            _timing_row(3, 101.0, "download"),
        ]
    )
    monkeypatch.setattr(
        module, "stream_tshark_fields", lambda *args, **kwargs: rows
    )

    class ProgressRecorder:
        def __init__(self) -> None:
            self.events: list[tuple[str, int, int | None, str]] = []

        def emit(
            self, stage: str, current: int, total: int | None, message: str
        ) -> None:
            self.events.append((stage, current, total, message))

    progress = ProgressRecorder()
    database = tmp_path / "analysis.sqlite"

    result = module.analyze_captures(
        {"download": capture},
        "download",
        1,
        database,
        Path("tshark"),
        8,
        progress,
    )

    assert result.tcp_summary["timing"] == {
        "available": True,
        "complete": False,
        "timed_packets": 2,
        "untimed_packets": 1,
    }
    assert [interval["interval_start"] for interval in result.intervals] == [0.0, 1.0]
    assert progress.events[-1][1:3] == (3, 3)
    with sqlite3.connect(database) as connection:
        event = connection.execute(
            "SELECT frame_number, time_relative FROM events"
        ).fetchone()
    assert event == (1, None)


def test_both_uses_first_timed_epoch_after_leading_untimed_packets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_both_late_epoch")
    download_capture = tmp_path / "download.pcapng"
    upload_capture = tmp_path / "upload.pcapng"
    download_capture.write_bytes(b"download")
    upload_capture.write_bytes(b"upload")
    capture_rows = {
        download_capture: [
            _timing_row(1, None, "download"),
            _timing_row(2, 90.0, "download"),
            _timing_row(3, 91.0, "download"),
        ],
        upload_capture: [
            _timing_row(1, 100.0, "upload"),
            _timing_row(2, 101.0, "upload"),
        ],
    }

    def rows(
        tshark_path: Path,
        capture: Path,
        fields: list[str],
        display_filter: str,
    ):
        yield from capture_rows[capture]

    monkeypatch.setattr(module, "stream_tshark_fields", rows)

    result = module.analyze_captures(
        {"download": download_capture, "upload": upload_capture},
        "both",
        1,
        None,
        Path("tshark"),
        16,
    )

    intervals = [
        (interval["direction"], interval["interval_start"])
        for interval in result.intervals
    ]
    assert intervals == [
        ("download", 0.0),
        ("download", 1.0),
        ("upload", 10.0),
        ("upload", 11.0),
    ]
    assert result.tcp_summary["timing"] == {
        "available": True,
        "complete": False,
        "timed_packets": 4,
        "untimed_packets": 1,
    }


class ClosingIterator:
    def __init__(
        self, rows: list[dict[str, str]], *, close_error: BaseException | None = None
    ) -> None:
        self._rows = iter(rows)
        self.close_error = close_error
        self.closed = False

    def __iter__(self):
        return self

    def __next__(self) -> dict[str, str]:
        return next(self._rows)

    def close(self) -> None:
        self.closed = True
        if self.close_error is not None:
            raise self.close_error


class RecordingStore:
    def __init__(self) -> None:
        self.closed = False

    def initialize(self) -> None:
        return None

    def append_event(self, event: dict[str, object]) -> None:
        return None

    def write_result(self, result: object) -> None:
        return None

    def close(self) -> None:
        self.closed = True


def test_cleanup_closes_all_iterators_and_store_after_close_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_cleanup")
    download_capture = tmp_path / "download.pcapng"
    upload_capture = tmp_path / "upload.pcapng"
    download_capture.write_bytes(b"download")
    upload_capture.write_bytes(b"upload")
    download_rows = ClosingIterator(
        [_timing_row(1, 100.0, "download")],
        close_error=RuntimeError("download close failed"),
    )
    upload_rows = ClosingIterator([_timing_row(1, 101.0, "upload")])
    iterators = {download_capture: download_rows, upload_capture: upload_rows}
    store = RecordingStore()

    monkeypatch.setattr(
        module,
        "stream_tshark_fields",
        lambda tshark_path, capture, fields, display_filter: iterators[capture],
    )
    monkeypatch.setattr(module, "AnalysisStore", lambda path: store)

    with pytest.raises(RuntimeError, match="download close failed"):
        module.analyze_captures(
            {"download": download_capture, "upload": upload_capture},
            "both",
            1,
            tmp_path / "analysis.sqlite",
            Path("tshark"),
            16,
        )

    assert download_rows.closed is True
    assert upload_rows.closed is True
    assert store.closed is True


def test_cleanup_error_does_not_mask_original_analysis_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_cleanup_error")
    capture = tmp_path / "download.pcapng"
    capture.write_bytes(b"download")
    invalid_row = _timing_row(1, 100.0, "download")
    invalid_row["tcp.srcport"] = "invalid"
    rows = ClosingIterator(
        [invalid_row], close_error=RuntimeError("iterator close failed")
    )
    store = RecordingStore()

    monkeypatch.setattr(
        module, "stream_tshark_fields", lambda *args, **kwargs: rows
    )
    monkeypatch.setattr(module, "AnalysisStore", lambda path: store)

    with pytest.raises(ValueError, match="invalid TCP src port"):
        module.analyze_captures(
            {"download": capture},
            "download",
            1,
            tmp_path / "analysis.sqlite",
            Path("tshark"),
            8,
        )

    assert rows.closed is True
    assert store.closed is True


def test_cleanup_error_propagates_inside_callers_exception_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("tcp_extract.py", "task5_tcp_extract_outer_error")
    capture = tmp_path / "download.pcapng"
    capture.write_bytes(b"download")
    rows = ClosingIterator(
        [_timing_row(1, 100.0, "download")],
        close_error=RuntimeError("iterator close failed"),
    )
    store = RecordingStore()

    monkeypatch.setattr(
        module, "stream_tshark_fields", lambda *args, **kwargs: rows
    )
    monkeypatch.setattr(module, "AnalysisStore", lambda path: store)

    try:
        1 / 0
    except ZeroDivisionError:
        with pytest.raises(RuntimeError, match="iterator close failed"):
            module.analyze_captures(
                {"download": capture},
                "download",
                1,
                tmp_path / "analysis.sqlite",
                Path("tshark"),
                8,
            )

    assert rows.closed is True
    assert store.closed is True


@pytest.mark.parametrize(
    ("capture", "analysis_id", "target", "error_code"),
    [
        ("relative.pcapng", "relative", "download", "INVALID_CAPTURE"),
        (None, "bad/id", "download", "ANALYSIS_FAILED"),
        (None, "bad-target", "sideways", "ANALYSIS_FAILED"),
    ],
)
def test_invalid_requests_write_failed_manifest(
    tmp_path: Path,
    sample_capture: Path,
    capture: str | None,
    analysis_id: str,
    target: str,
    error_code: str,
    tshark_path: Path,
) -> None:
    output = (tmp_path / analysis_id.replace("/", "-")).resolve()
    selected_capture = capture if capture is not None else sample_capture

    result = run_pipeline(
        selected_capture,
        output,
        tshark_path=tshark_path,
        analysis_id=analysis_id,
        target=target,
    )

    assert result.returncode != 0
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["error"]["code"] == error_code
    assert "traceback" not in json.dumps(manifest).lower()


def test_no_tcp_capture_writes_specific_failed_manifest(
    tmp_path: Path, no_tcp_capture: Path, tshark_path: Path
) -> None:
    output = (tmp_path / "no-tcp").resolve()

    result = run_pipeline(no_tcp_capture, output, tshark_path=tshark_path)

    assert result.returncode != 0
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["error"]["code"] == "NO_TCP_PACKETS"


def test_tcp_without_directional_speed_flow_writes_specific_failed_manifest(
    tmp_path: Path, no_speed_flow_capture: Path, tshark_path: Path
) -> None:
    output = (tmp_path / "no-speed-flow").resolve()

    result = run_pipeline(no_speed_flow_capture, output, tshark_path=tshark_path)

    assert result.returncode != 0
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["error"]["code"] == "NO_SPEED_FLOW"


def test_invalid_json_output_maps_to_invalid_analysis_output(tmp_path: Path) -> None:
    module = load_script_module("run_pipeline.py", "task5_run_pipeline")
    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]", encoding="utf-8")

    with pytest.raises(module.PipelineError) as exc_info:
        module.read_json_object(invalid)

    assert exc_info.value.code == "INVALID_ANALYSIS_OUTPUT"


@pytest.mark.parametrize(
    "corruption",
    [
        "missing_input_size",
        "string_input_size",
        "negative_input_size",
        "negative_total_packets",
        "tcp_exceeds_total",
        "invalid_sha256",
        "negative_written_count",
        "filtered_files_not_object",
    ],
)
def test_invalid_speed_stats_contract_writes_invalid_output_manifest(
    tmp_path: Path,
    sample_capture: Path,
    monkeypatch: pytest.MonkeyPatch,
    corruption: str,
) -> None:
    module = load_script_module(
        "run_pipeline.py", f"task5_run_pipeline_bad_stats_{corruption}"
    )
    output = (tmp_path / corruption).resolve()
    filtered_capture = (output / "filtered" / "download.pcapng").resolve()
    stats: dict[str, object] = {
        "status": "completed",
        "input_file": str(sample_capture),
        "input_size_bytes": sample_capture.stat().st_size,
        "sha256": "a" * 64,
        "total_packets": 10,
        "total_tcp_packets": 8,
        "total_flows": 1,
        "speed_flows_count": 1,
        "download_flows_count": 1,
        "upload_flows_count": 0,
        "min_bytes": 1,
        "min_direction_ratio": 0.65,
        "enable_strip": False,
        "target": "download",
        "speed_flows": [],
        "written_counts": {"download": 8},
        "filtered_files": {"download": str(filtered_capture)},
    }
    if corruption == "missing_input_size":
        stats.pop("input_size_bytes")
    elif corruption == "string_input_size":
        stats["input_size_bytes"] = "100"
    elif corruption == "negative_input_size":
        stats["input_size_bytes"] = -1
    elif corruption == "negative_total_packets":
        stats["total_packets"] = -1
    elif corruption == "tcp_exceeds_total":
        stats["total_tcp_packets"] = 11
    elif corruption == "invalid_sha256":
        stats["sha256"] = "not-a-sha256"
    elif corruption == "negative_written_count":
        stats["written_counts"] = {"download": -1}
    elif corruption == "filtered_files_not_object":
        stats["filtered_files"] = []

    def fake_filter(*args: object, **kwargs: object) -> None:
        filtered_capture.parent.mkdir(parents=True, exist_ok=True)
        filtered_capture.write_bytes(b"filtered")
        stats_path = Path(args[3])
        stats_path.write_text(json.dumps(stats), encoding="utf-8")

    monkeypatch.setattr(module, "find_tshark", lambda configured: Path("tshark"))
    monkeypatch.setattr(
        module,
        "normalize_capture",
        lambda input_path, output_dir, tshark_path: sample_capture,
    )
    monkeypatch.setattr(module, "_run_filter", fake_filter)
    monkeypatch.setattr(
        module,
        "analyze_captures",
        lambda *args, **kwargs: pytest.fail("invalid stats reached analysis"),
    )
    args = module.build_parser().parse_args(
        [
            "--input",
            str(sample_capture),
            "--output",
            str(output),
            "--analysis-id",
            f"bad-stats-{corruption}",
        ]
    )

    assert module.run(args) == 1
    manifest = read_json(output / "manifest.json")
    assert manifest["error"]["code"] == "INVALID_ANALYSIS_OUTPUT"


def test_filter_subprocess_is_terminated_when_pipeline_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_script_module("run_pipeline.py", "task5_run_pipeline_cancel")

    class InterruptingProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.wait_calls = 0
            self.terminate_calls = 0
            self.kill_calls = 0

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.wait_calls += 1
            if self.wait_calls == 1:
                raise KeyboardInterrupt
            self.returncode = -15
            return self.returncode

        def terminate(self) -> None:
            self.terminate_calls += 1

        def kill(self) -> None:
            self.kill_calls += 1

    process = InterruptingProcess()
    monkeypatch.setattr(module.subprocess, "Popen", lambda *args, **kwargs: process)
    monkeypatch.setattr(
        module.subprocess,
        "run",
        lambda *args, **kwargs: (_ for _ in ()).throw(KeyboardInterrupt),
    )
    log_path = tmp_path / "logs" / "filter.log"
    log_path.parent.mkdir()

    with pytest.raises(KeyboardInterrupt):
        module._run_filter(
            tmp_path / "capture.pcapng",
            module.Target.DOWNLOAD,
            tmp_path / "filtered",
            tmp_path / "speed_stats.json",
            tmp_path / "progress.jsonl",
            log_path,
            0.7,
            1,
        )

    assert process.terminate_calls == 1
    assert process.wait_calls == 2
    assert process.kill_calls == 0
