from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from packetmaster.analyzer.real import RealAnalyzerAdapter
from packetmaster.domain import AnalyzeRequest, Target

pytestmark = pytest.mark.performance

_DEFAULT_MIN_CAPTURE_BYTES = 1536 * 1024**2
_DEFAULT_MAX_RSS_BYTES = 1024 * 1024**2


def _performance_capture() -> Path:
    configured = os.environ.get("PERF_PCAP_PATH")
    if not configured:
        pytest.skip("PERF_PCAP_PATH is not configured")
    capture = Path(configured).expanduser().resolve()
    if not capture.is_file():
        pytest.fail(f"PERF_PCAP_PATH is not a file: {capture}")
    minimum = int(
        os.environ.get("PERF_MIN_CAPTURE_BYTES", _DEFAULT_MIN_CAPTURE_BYTES)
    )
    if capture.stat().st_size < minimum:
        pytest.fail(
            f"performance capture is smaller than {minimum} bytes: {capture}"
        )
    return capture


def _expected_coverage(capture: Path) -> dict[str, int]:
    configured = os.environ.get("PERF_METADATA_PATH")
    metadata_path = (
        Path(configured).expanduser().resolve()
        if configured
        else capture.with_name(f"{capture.name}.metadata.json")
    )
    if not metadata_path.is_file():
        pytest.fail(f"performance metadata is not a file: {metadata_path}")
    try:
        value = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        pytest.fail(f"invalid performance metadata: {exc}")
    required = (
        "input_size_bytes",
        "total_packets_seen",
        "tcp_packets_seen",
        "speed_packets_analyzed",
    )
    if not isinstance(value, dict) or any(
        not isinstance(value.get(field), int) or value[field] <= 0
        for field in required
    ):
        pytest.fail(f"performance metadata needs positive integers: {required}")
    return {field: value[field] for field in required}


def test_large_capture_is_complete_and_stays_within_rss_budget(
    tmp_path: Path,
) -> None:
    capture = _performance_capture()
    expected = _expected_coverage(capture)
    adapter = RealAnalyzerAdapter(artifact_root=tmp_path / "artifacts")

    response = asyncio.run(
        adapter.analyze(
            AnalyzeRequest(
                request_id="large-capture-release-gate",
                pcap_path=str(capture),
                target=Target.DOWNLOAD,
            )
        )
    )

    coverage = response.coverage_summary
    assert capture.stat().st_size == expected["input_size_bytes"]
    assert coverage.input_size_bytes == expected["input_size_bytes"]
    assert coverage.total_packets_seen == expected["total_packets_seen"]
    assert coverage.tcp_packets_seen == expected["tcp_packets_seen"]
    assert coverage.speed_packets_analyzed == expected["speed_packets_analyzed"]
    assert coverage.complete is True
    assert coverage.truncated is False
    rss_budget = int(os.environ.get("PERF_MAX_RSS_BYTES", _DEFAULT_MAX_RSS_BYTES))
    sampled_rss_peak = response.resource_usage["rss_peak_bytes"]
    assert sampled_rss_peak > 0
    assert sampled_rss_peak <= rss_budget
