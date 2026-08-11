import asyncio
import json

from packetmaster.application.stall import StallDiagnosisService
from packetmaster.application.stall_protocol import extract_protocol_summary
from packetmaster.config import Settings


def test_protocol_extractor_reads_real_capture(sample_capture, tshark_path) -> None:
    summary = extract_protocol_summary(sample_capture, tshark_path=tshark_path)

    assert summary["capture_summary"]["packet_count"] > 0
    assert summary["endpoint_summary"]
    assert summary["capture_summary"]["protocol_counts"]
    assert set(summary["keyword_summary"]) == {
        "timeout",
        "error",
        "buffering",
        "stall",
        "retry",
        "unavailable",
    }


def test_protocol_extractor_supports_udp_only_capture(
    no_tcp_capture, tshark_path
) -> None:
    summary = extract_protocol_summary(no_tcp_capture, tshark_path=tshark_path)

    assert summary["udp_summary"]["packet_count"] == 1
    assert summary["udp_summary"]["flow_count"] == 1


def test_stall_service_generates_report_for_udp_only_capture(
    tmp_path, no_tcp_capture, tshark_path
) -> None:
    service = StallDiagnosisService(
        Settings(artifact_root=tmp_path / "artifacts", tshark_path=str(tshark_path))
    )

    outcome = asyncio.run(
        service.run(pcap_path=str(no_tcp_capture), request_id="stall-udp")
    )
    report = json.loads(outcome.report_path.read_text(encoding="utf-8"))

    assert outcome.partial is True
    assert report["mode"] == "stall"
    assert report["udp_summary"]["packet_count"] == 1
    assert report["analysis_metadata"]["analyzer"] == "generic-multiprotocol-v1"
