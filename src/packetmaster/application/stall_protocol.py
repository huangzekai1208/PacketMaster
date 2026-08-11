"""Privacy-bounded multi-protocol metadata extraction for stall diagnosis."""

from __future__ import annotations

import ipaddress
import math
import shutil
import subprocess
import tempfile
import threading
from collections import Counter, defaultdict
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from packetmaster.errors import AppError

FIELDS = [
    "frame.number",
    "frame.time_relative",
    "frame.len",
    "_ws.col.Protocol",
    "ip.src",
    "ipv6.src",
    "ip.dst",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "udp.length",
    "dns.id",
    "dns.flags.response",
    "dns.flags.rcode",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "dns.time",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "tls.alert_message.desc",
    "http.request.method",
    "http.host",
    "http.response.code",
    "http.time",
    "http.content_type",
]
KEYWORDS = ("timeout", "error", "buffering", "stall", "retry", "unavailable")


def find_tshark(configured: str | None) -> Path:
    candidates = [Path(configured).expanduser()] if configured else []
    discovered = shutil.which("tshark")
    if discovered:
        candidates.append(Path(discovered))
    candidates.extend(
        [
            Path("/Applications/Wireshark.app/Contents/MacOS/tshark"),
            Path("/opt/homebrew/bin/tshark"),
            Path("/usr/local/bin/tshark"),
            Path(r"C:\Program Files\Wireshark\tshark.exe"),
        ]
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    raise AppError(
        code="DEPENDENCY_UNAVAILABLE",
        message="未找到 TShark，无法执行多协议卡顿分析",
        recoverable=True,
        suggested_action="请安装 Wireshark/TShark 或配置 TSHARK_PATH。",
    )


def extract_protocol_summary(
    capture: Path,
    *,
    tshark_path: Path,
    timeout_seconds: float = 300.0,
) -> dict[str, Any]:
    command = [str(tshark_path), "-r", str(capture), "-T", "fields"]
    for field in FIELDS:
        command.extend(["-e", field])
    command.extend(["-E", "occurrence=f"])
    with tempfile.TemporaryFile(
        mode="w+", encoding="utf-8", errors="replace"
    ) as stderr:
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=stderr,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise _protocol_error(
                "PROTOCOL_ANALYZER_UNAVAILABLE", "无法启动 TShark"
            ) from exc
        timed_out = threading.Event()

        def terminate_on_timeout() -> None:
            timed_out.set()
            process.kill()

        timer = threading.Timer(timeout_seconds, terminate_on_timeout)
        timer.daemon = True
        timer.start()
        try:
            assert process.stdout is not None
            rows = (
                dict(zip(FIELDS, _split_fields(line), strict=True))
                for line in process.stdout
                if line.strip()
            )
            result = aggregate_protocol_rows(rows)
            returncode = process.wait()
        finally:
            timer.cancel()
            if process.poll() is None:
                process.kill()
                process.wait()
        if timed_out.is_set():
            raise _protocol_error("PROTOCOL_ANALYSIS_TIMEOUT", "多协议元数据提取超时")
        if returncode:
            stderr.seek(0)
            raise _protocol_error(
                "PROTOCOL_ANALYSIS_FAILED",
                f"多协议元数据提取失败：{stderr.read(300).strip()}",
            )
    result["keyword_summary"] = _keyword_counts(
        capture, tshark_path=tshark_path, timeout_seconds=timeout_seconds
    )
    return result


def aggregate_protocol_rows(rows: Iterable[dict[str, str]]) -> dict[str, Any]:
    protocols: Counter[str] = Counter()
    endpoints: dict[str, dict[str, Any]] = defaultdict(_endpoint)
    dns_queries: dict[tuple[str, str, str], float] = {}
    dns_answered: set[tuple[str, str, str]] = set()
    dns_domains: dict[str, dict[str, Any]] = defaultdict(_domain)
    dns_latencies: list[float] = []
    dns_responses = dns_failures = 0
    sni: dict[str, dict[str, Any]] = defaultdict(_sni)
    tls_client_hellos = tls_server_hellos = tls_alerts = 0
    http_hosts: Counter[str] = Counter()
    http_requests = http_responses = http_errors = 0
    http_latencies: list[float] = []
    content_types: Counter[str] = Counter()
    udp_packets = udp_bytes = quic_packets = 0
    udp_flows: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    first_time: float | None = None
    last_time = 0.0
    packet_count = 0

    for row in rows:
        packet_count += 1
        timestamp = _float(row.get("frame.time_relative"))
        first_time = timestamp if first_time is None else min(first_time, timestamp)
        last_time = max(last_time, timestamp)
        protocol = _bounded(row.get("_ws.col.Protocol"), 32).upper() or "UNKNOWN"
        protocols[protocol] += 1
        src = row.get("ip.src") or row.get("ipv6.src") or ""
        dst = row.get("ip.dst") or row.get("ipv6.dst") or ""
        size = _int(row.get("frame.len"))
        _observe_endpoint(endpoints, src, protocol, sent=size)
        _observe_endpoint(endpoints, dst, protocol, received=size)

        query_name = _hostname(row.get("dns.qry.name"))
        dns_id = _bounded(row.get("dns.id"), 32)
        is_response = row.get("dns.flags.response") == "1"
        if query_name and not is_response:
            dns_queries[(dns_id, src, query_name)] = timestamp
            dns_domains[query_name]["query_count"] += 1
        if is_response:
            dns_responses += 1
            dns_answered.add((dns_id, dst, query_name))
            rcode = _int(row.get("dns.flags.rcode"))
            if rcode:
                dns_failures += 1
            if query_name:
                domain = dns_domains[query_name]
                domain["response_count"] += 1
                domain["rcodes"][str(rcode)] += 1
                answers = _answer_ips(row)
                domain["answer_ips"].update(answers)
                for address in answers:
                    endpoints[address]["domains"].add(query_name)
            latency = _float(row.get("dns.time"))
            if latency > 0:
                dns_latencies.append(latency * 1000)

        handshake_types = set(_csv(row.get("tls.handshake.type")))
        hostname = _hostname(row.get("tls.handshake.extensions_server_name"))
        if "1" in handshake_types:
            tls_client_hellos += 1
        if "2" in handshake_types:
            tls_server_hellos += 1
        if hostname:
            sni[hostname]["count"] += 1
            if dst:
                sni[hostname]["endpoint_ips"].add(dst)
                endpoints[dst]["sni"].add(hostname)
        if row.get("tls.alert_message.desc"):
            tls_alerts += 1

        method = _bounded(row.get("http.request.method"), 16)
        host = _hostname(row.get("http.host"))
        status = _int(row.get("http.response.code"))
        if method:
            http_requests += 1
        if host:
            http_hosts[host] += 1
            if dst:
                endpoints[dst]["domains"].add(host)
        if status:
            http_responses += 1
            if status >= 400:
                http_errors += 1
        http_time = _float(row.get("http.time"))
        if http_time > 0:
            http_latencies.append(http_time * 1000)
        content_type = _bounded(row.get("http.content_type"), 96)
        if content_type:
            content_types[content_type] += 1

        src_port = row.get("udp.srcport") or ""
        dst_port = row.get("udp.dstport") or ""
        if src_port or dst_port:
            udp_packets += 1
            udp_bytes += _int(row.get("udp.length"))
            if protocol == "QUIC" or src_port == "443" or dst_port == "443":
                quic_packets += 1
            key = _flow_key(src, src_port, dst, dst_port)
            flow = udp_flows.setdefault(
                key,
                {
                    "packet_count": 0,
                    "bytes": 0,
                    "first": timestamp,
                    "last": timestamp,
                    "max_gap": 0.0,
                },
            )
            flow["packet_count"] += 1
            flow["bytes"] += _int(row.get("udp.length"))
            flow["max_gap"] = max(flow["max_gap"], timestamp - flow["last"])
            flow["last"] = timestamp

    return {
        "capture_summary": {
            "packet_count": packet_count,
            "duration_seconds": round(max(0.0, last_time - (first_time or 0.0)), 6),
            "protocol_counts": dict(protocols.most_common(32)),
        },
        "endpoint_summary": _serialize_endpoints(endpoints),
        "dns_summary": {
            "query_count": len(dns_queries),
            "response_count": dns_responses,
            "failure_count": dns_failures,
            "unanswered_count": len(set(dns_queries) - dns_answered),
            "latency_ms": _latency(dns_latencies),
            "domains": _serialize_domains(dns_domains),
        },
        "tls_summary": {
            "client_hello_count": tls_client_hellos,
            "server_hello_count": tls_server_hellos,
            "alert_count": tls_alerts,
            "sni": _serialize_sni(sni),
        },
        "http_summary": {
            "request_count": http_requests,
            "response_count": http_responses,
            "error_response_count": http_errors,
            "latency_ms": _latency(http_latencies),
            "hosts": dict(http_hosts.most_common(64)),
            "content_types": dict(content_types.most_common(32)),
        },
        "udp_summary": {
            "packet_count": udp_packets,
            "bytes": udp_bytes,
            "flow_count": len(udp_flows),
            "quic_packet_count": quic_packets,
            "long_gap_flow_count": sum(
                1 for flow in udp_flows.values() if flow["max_gap"] > 2
            ),
        },
    }


def _keyword_counts(
    capture: Path, *, tshark_path: Path, timeout_seconds: float
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for keyword in KEYWORDS:
        command = [
            str(tshark_path),
            "-r",
            str(capture),
            "-Y",
            f'(tcp || udp) && frame contains "{keyword}"',
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=max(5.0, timeout_seconds / len(KEYWORDS)),
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            counts[keyword] = 0
            continue
        counts[keyword] = min(10_000, len(result.stdout.splitlines()))
    return counts


def _serialize_endpoints(values: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for address, value in sorted(
        values.items(), key=lambda item: item[1]["packets"], reverse=True
    )[:128]:
        output.append(
            {
                "ip": address,
                "scope": _ip_scope(address),
                "packets": value["packets"],
                "sent_bytes": value["sent_bytes"],
                "received_bytes": value["received_bytes"],
                "protocols": sorted(value["protocols"])[:16],
                "domains": sorted(value["domains"])[:32],
                "sni": sorted(value["sni"])[:32],
            }
        )
    return output


def _serialize_domains(values: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "query_count": value["query_count"],
            "response_count": value["response_count"],
            "rcodes": dict(value["rcodes"]),
            "answer_ips": sorted(value["answer_ips"])[:32],
        }
        for name, value in sorted(
            values.items(), key=lambda item: item[1]["query_count"], reverse=True
        )[:128]
    ]


def _serialize_sni(values: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        {
            "name": name,
            "count": value["count"],
            "endpoint_ips": sorted(value["endpoint_ips"])[:32],
        }
        for name, value in sorted(
            values.items(), key=lambda item: item[1]["count"], reverse=True
        )[:128]
    ]


def _endpoint() -> dict[str, Any]:
    return {
        "packets": 0,
        "sent_bytes": 0,
        "received_bytes": 0,
        "protocols": set(),
        "domains": set(),
        "sni": set(),
    }


def _domain() -> dict[str, Any]:
    return {
        "query_count": 0,
        "response_count": 0,
        "rcodes": Counter(),
        "answer_ips": set(),
    }


def _sni() -> dict[str, Any]:
    return {"count": 0, "endpoint_ips": set()}


def _observe_endpoint(
    endpoints: dict[str, dict[str, Any]],
    address: str,
    protocol: str,
    *,
    sent: int = 0,
    received: int = 0,
) -> None:
    if not address:
        return
    value = endpoints[address]
    value["packets"] += 1
    value["sent_bytes"] += sent
    value["received_bytes"] += received
    value["protocols"].add(protocol)


def _answer_ips(row: dict[str, str]) -> set[str]:
    values = set(_csv(row.get("dns.a"))) | set(_csv(row.get("dns.aaaa")))
    return {value for value in values if _is_ip(value)}


def _flow_key(src: str, sport: str, dst: str, dport: str) -> tuple[str, str, str, str]:
    left = (src, sport)
    right = (dst, dport)
    first, second = sorted((left, right))
    return first[0], first[1], second[0], second[1]


def _latency(values: list[float]) -> dict[str, float]:
    if not values:
        return {"count": 0, "average": 0.0, "p95": 0.0, "max": 0.0}
    ordered = sorted(values)
    index = min(len(ordered) - 1, math.ceil(len(ordered) * 0.95) - 1)
    return {
        "count": len(ordered),
        "average": round(sum(ordered) / len(ordered), 3),
        "p95": round(ordered[index], 3),
        "max": round(ordered[-1], 3),
    }


def _split_fields(line: str) -> list[str]:
    values = line.rstrip("\r\n").split("\t")
    values.extend([""] * max(0, len(FIELDS) - len(values)))
    return values[: len(FIELDS)]


def _csv(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _hostname(value: str | None) -> str:
    candidate = _bounded(value, 253).lower().rstrip(".")
    if not candidate or any(
        char not in "abcdefghijklmnopqrstuvwxyz0123456789.-_" for char in candidate
    ):
        return ""
    return candidate


def _bounded(value: str | None, limit: int) -> str:
    return (value or "").strip()[:limit]


def _int(value: str | None) -> int:
    try:
        return max(0, int(value or 0))
    except ValueError:
        return 0


def _float(value: str | None) -> float:
    try:
        return max(0.0, float(value or 0))
    except ValueError:
        return 0.0


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _ip_scope(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return "unknown"
    if address.is_loopback:
        return "loopback"
    if address.is_private:
        return "private"
    if address.is_multicast:
        return "multicast"
    if address.is_link_local:
        return "link_local"
    return "public"


def _protocol_error(code: str, message: str) -> AppError:
    return AppError(
        code=code,
        message=message,
        recoverable=True,
        suggested_action="请检查报文完整性和 TShark 配置后重试。",
    )
