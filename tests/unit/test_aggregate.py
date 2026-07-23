from __future__ import annotations

import json
from pathlib import Path

import pytest

from packetmaster.domain import Target
from tests.helpers import load_script_module

aggregate = load_script_module("lib/aggregate.py", "speed_analyze_aggregate")


def packet_row(number: int, **overrides: str) -> dict[str, str]:
    row = {
        "frame.number": str(number),
        "frame.time_relative": f"{number / 1000:.3f}",
        "ip.src": "192.0.2.10",
        "ip.dst": "198.51.100.20",
        "tcp.srcport": "50000",
        "tcp.dstport": "443",
        "tcp.len": "1000",
        "tcp.seq": str(number * 1000),
        "tcp.ack": "1",
        "tcp.window_size": "65535",
    }
    row.update(overrides)
    return row


def test_late_anomaly_is_counted_across_all_6000_packets() -> None:
    accumulator = aggregate.TcpAccumulator(target=Target.DOWNLOAD)

    for number in range(1, 6001):
        overrides = {"tcp.analysis.retransmission": "1"} if number == 5501 else {}
        accumulator.observe(packet_row(number, **overrides), Target.DOWNLOAD)

    result = accumulator.finalize()

    assert result.coverage_summary.total_packets_seen == 6000
    assert result.coverage_summary.tcp_packets_seen == 6000
    assert result.coverage_summary.speed_packets_analyzed == 6000
    assert result.tcp_summary["retransmission_count"] == 1
    assert result.events[0]["frame.number"] == 5501
    assert result.coverage_summary.complete is True
    assert result.coverage_summary.truncated is False


def test_event_sink_streams_10000_events_without_retaining_them() -> None:
    seen: list[str] = []
    accumulator = aggregate.TcpAccumulator(
        target="download", event_sink=lambda event: seen.append(event["evidence_id"])
    )

    for number in range(1, 10001):
        accumulator.observe(
            packet_row(number, **{"tcp.analysis.duplicate_ack": "1"}),
            "download",
        )

    result = accumulator.finalize()

    assert len(seen) == 10000
    assert len(set(seen)) == 10000
    assert result.events == []
    assert result.tcp_summary["duplicate_ack_count"] == 10000


def test_target_filters_analyzed_packets_but_not_coverage() -> None:
    accumulator = aggregate.TcpAccumulator(target="upload")
    accumulator.observe(packet_row(1), "download")
    accumulator.observe(packet_row(2, **{"tcp.len": "250"}), "upload")
    accumulator.observe({"frame.number": "3"}, "download")

    result = accumulator.finalize()

    assert result.coverage_summary.total_packets_seen == 3
    assert result.coverage_summary.tcp_packets_seen == 2
    assert result.coverage_summary.speed_packets_analyzed == 1
    assert result.coverage_summary.analyzed_bytes == 250
    assert result.tcp_summary["payload_bytes_by_direction"] == {
        "download": 0,
        "upload": 250,
    }


def test_both_target_accepts_both_packet_directions() -> None:
    accumulator = aggregate.TcpAccumulator(target="both")
    accumulator.observe(packet_row(1), "download")
    accumulator.observe(packet_row(2), "upload")

    result = accumulator.finalize()

    assert result.coverage_summary.speed_packets_analyzed == 2
    assert result.tcp_summary["payload_bytes_by_direction"] == {
        "download": 1000,
        "upload": 1000,
    }


def test_normalized_flow_id_is_bidirectional_and_supports_ipv6() -> None:
    forward = packet_row(1)
    reverse = packet_row(
        2,
        **{
            "ip.src": forward["ip.dst"],
            "ip.dst": forward["ip.src"],
            "tcp.srcport": forward["tcp.dstport"],
            "tcp.dstport": forward["tcp.srcport"],
        },
    )
    ipv6 = packet_row(
        3,
        **{
            "ip.src": "",
            "ip.dst": "",
            "ipv6.src": "2001:db8::1",
            "ipv6.dst": "2001:db8::2",
        },
    )

    assert aggregate.normalized_flow_id(forward) == aggregate.normalized_flow_id(
        reverse
    )
    assert "[2001:db8::1]" in aggregate.normalized_flow_id(ipv6)


@pytest.mark.parametrize(
    ("row", "message"),
    [
        ({"tcp.srcport": "1", "tcp.dstport": "2"}, "address"),
        ({"ip.src": "192.0.2.1", "ip.dst": "192.0.2.2"}, "port"),
    ],
)
def test_normalized_flow_id_rejects_incomplete_rows(
    row: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        aggregate.normalized_flow_id(row)


def test_intervals_use_configured_boundaries_and_throughput() -> None:
    accumulator = aggregate.TcpAccumulator(interval_seconds=2, target="download")
    accumulator.observe(
        packet_row(1, **{"frame.time_relative": "1.999", "tcp.len": "1000000"}),
        "download",
    )
    accumulator.observe(
        packet_row(2, **{"frame.time_relative": "2.000", "tcp.len": "500000"}),
        "download",
    )

    intervals = accumulator.finalize().intervals

    assert [(item["interval_start"], item["interval_end"]) for item in intervals] == [
        (0.0, 2.0),
        (2.0, 4.0),
    ]
    assert [item["throughput_mbps"] for item in intervals] == [4.0, 2.0]


def test_rtt_uses_fixed_histogram_without_samples() -> None:
    accumulator = aggregate.TcpAccumulator(target="download")
    for number, seconds in enumerate(
        [0.0005, 0.001, 0.005, 0.0101, 0.5, 1.5], start=1
    ):
        accumulator.observe(
            packet_row(number, **{"tcp.analysis.ack_rtt": str(seconds)}),
            "download",
        )

    histogram = accumulator.finalize().tcp_summary["rtt_histogram"]

    assert histogram == [
        {"upper_bound_ms": 1, "count": 2},
        {"upper_bound_ms": 5, "count": 1},
        {"upper_bound_ms": 10, "count": 0},
        {"upper_bound_ms": 20, "count": 1},
        {"upper_bound_ms": 50, "count": 0},
        {"upper_bound_ms": 100, "count": 0},
        {"upper_bound_ms": 200, "count": 0},
        {"upper_bound_ms": 500, "count": 1},
        {"upper_bound_ms": 1000, "count": 0},
        {"upper_bound_ms": "inf", "count": 1},
    ]
    assert "rtt_samples" not in accumulator.finalize().tcp_summary


def test_per_flow_summary_contains_direction_throughput_time_and_rtt() -> None:
    accumulator = aggregate.TcpAccumulator(target="both")
    accumulator.observe(
        packet_row(
            1,
            **{
                "frame.time_relative": "1.0",
                "tcp.len": "1000000",
                "tcp.analysis.ack_rtt": "0.005",
            },
        ),
        "upload",
    )
    accumulator.observe(
        packet_row(
            2,
            **{
                "frame.time_relative": "3.0",
                "tcp.len": "1000000",
                "tcp.analysis.ack_rtt": "0.010",
            },
        ),
        "upload",
    )

    flow = next(iter(accumulator.finalize().flows.values()))

    assert flow["direction"] == "upload"
    assert flow["time_start"] == 1.0
    assert flow["time_end"] == 3.0
    assert flow["duration_seconds"] == 2.0
    assert flow["throughput_mbps"] == 8.0
    assert sum(bucket["count"] for bucket in flow["rtt_histogram"]) == 2


def test_syn_options_and_event_evidence_are_aggregated_from_fixture() -> None:
    fixture = Path(__file__).parents[1] / "fixtures" / "packet_rows.jsonl"
    rows = [
        json.loads(line)
        for line in fixture.read_text(encoding="utf-8").splitlines()
    ]
    accumulator = aggregate.TcpAccumulator(target="both")
    for index, row in enumerate(rows):
        accumulator.observe(row, "download" if index != 1 else "upload")

    result = accumulator.finalize()

    assert result.syn_options == {
        "syn_packet_count": 1,
        "mss_values": {"1460": 1},
        "window_scale_shifts": {"7": 1},
        "sack_permitted_count": 1,
    }
    assert {event["event_type"] for event in result.events} == {
        "duplicate_ack",
        "zero_window",
    }
    assert result.events[0].keys() >= {
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


def test_all_event_types_and_per_flow_counters_are_recorded() -> None:
    accumulator = aggregate.TcpAccumulator(target="download")
    row = packet_row(
        1,
        **{
            "tcp.analysis.retransmission": "1",
            "tcp.analysis.fast_retransmission": "1",
            "tcp.analysis.duplicate_ack": "1",
            "tcp.analysis.out_of_order": "1",
            "tcp.analysis.zero_window": "1",
            "tcp.analysis.window_full": "1",
        },
    )
    accumulator.observe(row, "download")

    result = accumulator.finalize()
    flow = next(iter(result.flows.values()))

    assert {event["event_type"] for event in result.events} == {
        "retransmission",
        "fast_retransmission",
        "duplicate_ack",
        "out_of_order",
        "zero_window",
        "window_full",
    }
    assert flow["packet_count"] == 1
    assert flow["retransmission_count"] == 1
    assert flow["duplicate_ack_count"] == 1
    assert flow["window_min"] == 65535
    assert flow["window_max"] == 65535


@pytest.mark.parametrize("frame_number", [None, "", "not-a-number", "0", "-1"])
def test_event_record_rejects_missing_or_invalid_exception_frame_number(
    frame_number: str | None,
) -> None:
    row = packet_row(1, **{"tcp.analysis.retransmission": "1"})
    if frame_number is None:
        row.pop("frame.number")
    else:
        row["frame.number"] = frame_number

    with pytest.raises(ValueError, match="frame.number"):
        aggregate.event_record(row, "retransmission", "flow-id", "download")


@pytest.mark.parametrize("target", ["", "DOWNLOAD", "invalid", None])
def test_invalid_target_is_rejected(target: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        aggregate.TcpAccumulator(target=target)


@pytest.mark.parametrize("interval", [0, 61, 1.5, "1"])
def test_invalid_interval_is_rejected(interval: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        aggregate.TcpAccumulator(interval_seconds=interval)


@pytest.mark.parametrize("direction", ["both", "invalid", "", None])
def test_invalid_direction_is_rejected_after_counting(direction: object) -> None:
    accumulator = aggregate.TcpAccumulator(target="both")

    with pytest.raises((TypeError, ValueError)):
        accumulator.observe(packet_row(1), direction)

    assert accumulator.finalize().coverage_summary.total_packets_seen == 1
