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
                "tcp|192.0.2.1:443|198.51.100.1:50000": {"direction": "download"}
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


def test_build_stall_report_attributes_protocol_failures_without_tcp() -> None:
    report = build_stall_report(
        "stall-udp",
        {},
        {"status": "partial"},
        {
            "capture_summary": {"packet_count": 20, "protocol_counts": {"DNS": 4}},
            "dns_summary": {
                "failure_count": 1,
                "unanswered_count": 2,
                "latency_ms": {"p95": 800},
            },
            "tls_summary": {"alert_count": 0},
            "http_summary": {"error_response_count": 0},
            "udp_summary": {"packet_count": 20},
            "keyword_summary": {},
        },
    )

    assert report.primary_cause == "DNS 解析失败或请求未获得响应"
    assert report.dns_summary["failure_count"] == 1
    assert report.protocol_summary["packet_count"] == 20
    assert report.analysis_metadata["analyzer"] == "generic-multiprotocol-v1"


def test_user_description_changes_stall_priority_and_troubleshooting() -> None:
    summary = {
        "coverage_summary": {"complete": True},
        "tcp_summary": {"packet_count": 100, "retransmission_count": 5},
        "interval_summary": [
            {
                "direction": "download",
                "interval_start": 0,
                "interval_end": 1,
                "throughput_mbps": 10,
            },
            {
                "direction": "download",
                "interval_start": 1,
                "interval_end": 2,
                "throughput_mbps": 0.1,
            },
        ],
    }

    generic = build_stall_report("generic", summary, {"status": "completed"})
    video = build_stall_report(
        "video",
        summary,
        {"status": "completed"},
        symptom_context="观看视频时在 12 秒左右频繁转圈卡顿",
    )

    assert generic.user_context["specificity"] == "generic"
    assert video.user_context["tags"] == ["video", "buffering"]
    assert video.user_context["time_offset_seconds"] == 12
    assert video.user_context["summary"] == "视频、缓冲卡顿、约 12 秒"
    assert video.troubleshooting_steps[0].startswith("优先检查抓包开始后约 12 秒")
    assert video.candidate_causes[0].confidence > generic.candidate_causes[0].confidence


def test_automatic_generic_prompt_is_not_treated_as_user_context() -> None:
    report = build_stall_report(
        "generic",
        {"coverage_summary": {}},
        {"status": "completed"},
        symptom_context="请对所选报文进行通用卡顿分析",
    )

    assert report.user_context["provided"] is False
    assert report.user_context["tags"] == []


def test_user_host_is_correlated_without_copying_full_description() -> None:
    report = build_stall_report(
        "web",
        {"coverage_summary": {}},
        {"status": "completed"},
        {
            "endpoint_summary": [
                {
                    "ip": "198.51.100.20",
                    "domains": ["video.example.com"],
                    "sni": ["video.example.com"],
                    "protocols": ["TLSv1.3"],
                }
            ]
        },
        symptom_context="访问 https://video.example.com/private/path 时加载很慢",
    )

    assert report.user_context["requested_hosts"] == ["video.example.com"]
    assert report.user_context["matched_endpoints"][0]["ip"] == "198.51.100.20"
    assert "/private/path" not in report.user_context["summary"]
