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


def test_ps5_login_description_targets_playstation_dns_failure() -> None:
    report = build_stall_report(
        "ps5-login",
        {"coverage_summary": {"complete": True}},
        {"status": "completed"},
        {
            "dns_summary": {
                "domains": [
                    {
                        "name": "auth.api.playstation.com",
                        "query_count": 2,
                        "response_count": 1,
                        "rcodes": {"2": 1},
                        "answer_ips": [],
                    }
                ]
            },
            "tls_summary": {"sni": []},
            "http_summary": {"hosts": {}},
            "endpoint_summary": [],
        },
        symptom_context="用户反馈 PS5 游戏机无法登录",
    )

    business = report.business_analysis
    assert business["profile"] == "playstation"
    assert business["action"] == "login"
    assert business["coverage"] == "observed"
    assert business["stages"][0]["status"] == "failed"
    assert (
        report.primary_cause == "PlayStation Network 登录链路异常集中在“域名解析”阶段"
    )
    assert (
        report.candidate_causes[0].cause == "PlayStation Network 登录链路的域名解析异常"
    )


def test_ps5_login_reports_encrypted_authentication_boundary() -> None:
    report = build_stall_report(
        "ps5-login-ok-network",
        {"coverage_summary": {"complete": True}},
        {"status": "completed"},
        {
            "dns_summary": {
                "domains": [
                    {
                        "name": "auth.api.playstation.com",
                        "query_count": 1,
                        "response_count": 1,
                        "rcodes": {"0": 1},
                        "answer_ips": ["198.51.100.20"],
                    }
                ]
            },
            "tls_summary": {
                "sni": [
                    {
                        "name": "auth.api.playstation.com",
                        "client_hello_count": 1,
                        "server_hello_count": 1,
                        "alert_count": 0,
                        "endpoint_ips": ["198.51.100.20"],
                    }
                ]
            },
            "http_summary": {"hosts": {}},
            "endpoint_summary": [
                {
                    "ip": "198.51.100.20",
                    "tcp_syn": 1,
                    "tcp_syn_ack": 1,
                    "tcp_resets": 0,
                    "tcp_retransmissions": 0,
                }
            ],
        },
        symptom_context="PS5 无法登录 PSN",
    )

    assert "未发现明确的解析、连接或 TLS 失败" in report.primary_cause
    assert report.business_analysis["stages"][-1]["status"] == "encrypted"


def test_ps5_login_reports_when_capture_does_not_cover_psn() -> None:
    report = build_stall_report(
        "ps5-missing",
        {"coverage_summary": {"complete": True}},
        {"status": "completed"},
        {"dns_summary": {"domains": []}, "tls_summary": {"sni": []}},
        symptom_context="PS5 游戏机无法登录",
    )

    assert report.business_analysis["coverage"] == "not_observed"
    assert "当前抓包可能未覆盖登录过程" in report.primary_cause
    assert report.troubleshooting_steps[0].startswith(
        "重新抓取包含 PlayStation Network"
    )
