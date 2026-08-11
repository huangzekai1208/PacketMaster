from packetmaster.application.stall import build_stall_report


def test_build_stall_report_attributes_tcp_retransmission_without_bandwidth() -> None:
    report = build_stall_report(
        "stall-1",
        {
            "coverage_summary": {"complete": True, "tcp_packets_seen": 100},
            "tcp_summary": {
                "packet_count": 100,
                "retransmission_count": 5,
                "zero_window_count": 0,
                "window_full_count": 0,
            },
            "flow_summary": {
                "tcp|192.0.2.1:443|198.51.100.1:50000": {
                    "direction": "download"
                }
            },
            "interval_summary": [],
        },
        {"status": "completed"},
    )

    assert report.mode == "stall"
    assert report.primary_cause == "TCP 丢包或重传导致有效数据交付中断"
    assert report.protocol_summary["retransmission_count"] == 5
    assert report.coverage_summary.complete is True
    assert "bandwidth" not in report.model_dump(mode="json")
