from __future__ import annotations

import asyncio
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


def test_large_capture_is_complete_and_stays_within_rss_budget(
    tmp_path: Path,
) -> None:
    capture = _performance_capture()
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
    assert coverage.input_size_bytes == capture.stat().st_size
    assert coverage.speed_packets_analyzed > 0
    assert coverage.complete is True
    assert coverage.truncated is False
    rss_budget = int(os.environ.get("PERF_MAX_RSS_BYTES", _DEFAULT_MAX_RSS_BYTES))
    assert response.resource_usage["rss_peak_bytes"] <= rss_budget
