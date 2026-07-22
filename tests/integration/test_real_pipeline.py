from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from tests.helpers import load_script_module

ROOT = Path(__file__).resolve().parents[2]
RUN_PIPELINE = ROOT / "speed-analyze" / "scripts" / "run_pipeline.py"
TSHARK = Path("/opt/homebrew/bin/tshark")


def run_pipeline(
    capture: Path | str,
    output: Path,
    *,
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
        str(TSHARK),
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
    tmp_path: Path, sample_capture: Path
) -> None:
    if not TSHARK.is_file():
        pytest.skip("tshark not installed")
    unicode_capture = tmp_path / "输入 报文" / "测速 样本.pcapng"
    unicode_capture.parent.mkdir()
    unicode_capture.write_bytes(sample_capture.read_bytes())
    output = (tmp_path / "分析 output" / "任务 一").resolve()

    result = run_pipeline(unicode_capture.resolve(), output)

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
    target: str | None,
    expected: set[str],
) -> None:
    if not TSHARK.is_file():
        pytest.skip("tshark not installed")
    output = (tmp_path / f"route-{target or 'default'}").resolve()

    result = run_pipeline(sample_capture, output, target=target)

    assert result.returncode == 0, result.stdout + result.stderr
    manifest = read_json(output / "manifest.json")
    stats = read_json(output / "speed_stats.json")
    assert manifest["target"] == (target or "download")
    assert set(stats["filtered_files"]) == expected
    filtered = manifest["artifact_paths"]["filtered_captures"]
    assert set(filtered) == expected
    assert len(set(filtered.values())) == len(expected)


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
        TSHARK,
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
        {"download": capture}, "download", 1, None, TSHARK, 1
    )

    assert result.events == []


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
) -> None:
    output = (tmp_path / analysis_id.replace("/", "-")).resolve()
    selected_capture = capture if capture is not None else sample_capture

    result = run_pipeline(
        selected_capture,
        output,
        analysis_id=analysis_id,
        target=target,
    )

    assert result.returncode != 0
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["error"]["code"] == error_code
    assert "traceback" not in json.dumps(manifest).lower()


def test_no_tcp_capture_writes_specific_failed_manifest(
    tmp_path: Path, no_tcp_capture: Path
) -> None:
    if not TSHARK.is_file():
        pytest.skip("tshark not installed")
    output = (tmp_path / "no-tcp").resolve()

    result = run_pipeline(no_tcp_capture, output)

    assert result.returncode != 0
    manifest = read_json(output / "manifest.json")
    assert manifest["status"] == "failed"
    assert manifest["error"]["code"] == "NO_TCP_PACKETS"


def test_tcp_without_directional_speed_flow_writes_specific_failed_manifest(
    tmp_path: Path, no_speed_flow_capture: Path
) -> None:
    if not TSHARK.is_file():
        pytest.skip("tshark not installed")
    output = (tmp_path / "no-speed-flow").resolve()

    result = run_pipeline(no_speed_flow_capture, output)

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
