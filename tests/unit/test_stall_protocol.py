from packetmaster.application.stall_protocol import aggregate_protocol_rows


def _row(**values: str) -> dict[str, str]:
    return values


def test_protocol_aggregation_associates_dns_sni_http_and_endpoints() -> None:
    summary = aggregate_protocol_rows(
        [
            _row(
                **{
                    "frame.time_relative": "0.0",
                    "frame.len": "80",
                    "_ws.col.Protocol": "DNS",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "8.8.8.8",
                    "udp.srcport": "53000",
                    "udp.dstport": "53",
                    "udp.length": "60",
                    "dns.id": "1",
                    "dns.flags.response": "0",
                    "dns.qry.name": "video.example.com",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "0.8",
                    "frame.len": "120",
                    "_ws.col.Protocol": "DNS",
                    "ip.src": "8.8.8.8",
                    "ip.dst": "192.0.2.10",
                    "udp.srcport": "53",
                    "udp.dstport": "53000",
                    "udp.length": "100",
                    "dns.id": "1",
                    "dns.flags.response": "1",
                    "dns.flags.rcode": "0",
                    "dns.qry.name": "video.example.com",
                    "dns.a": "198.51.100.20",
                    "dns.time": "0.8",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "1.0",
                    "frame.len": "100",
                    "_ws.col.Protocol": "TLSv1.3",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "198.51.100.20",
                    "tcp.srcport": "50000",
                    "tcp.dstport": "443",
                    "tcp.stream": "1",
                    "tls.handshake.type": "1",
                    "tls.handshake.extensions_server_name": "video.example.com",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "1.1",
                    "frame.len": "100",
                    "_ws.col.Protocol": "TLSv1.3",
                    "ip.src": "198.51.100.20",
                    "ip.dst": "192.0.2.10",
                    "tcp.srcport": "443",
                    "tcp.dstport": "50000",
                    "tcp.stream": "1",
                    "tls.handshake.type": "2",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "2.5",
                    "frame.len": "150",
                    "_ws.col.Protocol": "HTTP",
                    "ip.src": "198.51.100.20",
                    "ip.dst": "192.0.2.10",
                    "http.response.code": "503",
                    "http.time": "1.5",
                    "http.content_type": "video/mp4",
                }
            ),
        ]
    )

    assert summary["dns_summary"]["latency_ms"]["p95"] == 800
    assert summary["dns_summary"]["unanswered_count"] == 0
    assert summary["tls_summary"]["sni"][0]["name"] == "video.example.com"
    assert summary["tls_summary"]["sni"][0]["server_hello_count"] == 1
    assert summary["http_summary"]["error_response_count"] == 1
    endpoint = next(
        item for item in summary["endpoint_summary"] if item["ip"] == "198.51.100.20"
    )
    assert endpoint["domains"] == ["video.example.com"]
    assert endpoint["sni"] == ["video.example.com"]


def test_protocol_aggregation_detects_dns_failure_and_quic_gap() -> None:
    summary = aggregate_protocol_rows(
        [
            _row(
                **{
                    "frame.time_relative": "0",
                    "_ws.col.Protocol": "DNS",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "8.8.8.8",
                    "udp.srcport": "53000",
                    "udp.dstport": "53",
                    "dns.id": "2",
                    "dns.flags.response": "0",
                    "dns.qry.name": "missing.example",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "1",
                    "_ws.col.Protocol": "QUIC",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "198.51.100.20",
                    "udp.srcport": "50000",
                    "udp.dstport": "443",
                    "udp.length": "1200",
                }
            ),
            _row(
                **{
                    "frame.time_relative": "4.5",
                    "_ws.col.Protocol": "QUIC",
                    "ip.src": "198.51.100.20",
                    "ip.dst": "192.0.2.10",
                    "udp.srcport": "443",
                    "udp.dstport": "50000",
                    "udp.length": "1200",
                }
            ),
        ]
    )

    assert summary["dns_summary"]["unanswered_count"] == 1
    assert summary["udp_summary"]["quic_packet_count"] == 2
    assert summary["udp_summary"]["long_gap_flow_count"] == 1
    evidence = summary["evidence_index"]
    assert {item["evidence_type"] for item in evidence} >= {"dns", "udp_gap"}
    assert all("payload" not in item for item in evidence)


def test_protocol_aggregation_matches_cname_response_without_query_name() -> None:
    summary = aggregate_protocol_rows(
        [
            _row(
                **{
                    "frame.number": "1",
                    "frame.time_relative": "0",
                    "_ws.col.Protocol": "DNS",
                    "ip.src": "192.0.2.10",
                    "ip.dst": "8.8.8.8",
                    "dns.id": "100",
                    "dns.flags.response": "0",
                    "dns.qry.name": "login.console.example.com",
                }
            ),
            _row(
                **{
                    "frame.number": "2",
                    "frame.time_relative": "0.05",
                    "_ws.col.Protocol": "DNS",
                    "ip.src": "8.8.8.8",
                    "ip.dst": "192.0.2.10",
                    "dns.id": "100",
                    "dns.flags.response": "1",
                    "dns.flags.rcode": "0",
                    "dns.qry.name": "",
                    "dns.cname": "auth.edge.example.net,global.edge.example.net",
                    "dns.time": "0.05",
                }
            ),
        ]
    )

    assert summary["dns_summary"]["unanswered_count"] == 0
    domain = summary["dns_summary"]["domains"][0]
    assert domain["name"] == "login.console.example.com"
    assert domain["response_count"] == 1
    assert domain["cname_targets"] == [
        "auth.edge.example.net",
        "global.edge.example.net",
    ]
    response = next(
        item for item in summary["evidence_index"] if item["frame.number"] == "2"
    )
    assert response["domain"] == "login.console.example.com"
    assert response["cname_targets"] == domain["cname_targets"]
