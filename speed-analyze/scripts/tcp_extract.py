"""
TCP 字段提取脚本 - tshark CLI

从筛选后的 pcapng 中提取 TCP 关键指标（覆盖 tcp_head.md 1-5 类），
计算 Category 6 统计指标，输出 {stem}_tcp_analysis.json。

工作流程：
  1. tshark CLI 提取逐包字段、会话统计、I/O 时序
  2. 解析原始数据 + 计算 Category 6 统计指标
  3. 输出完整 JSON

用法：
  python tcp_extract.py --input <filtered.pcapng> --port <测速端口> --output output
  python tcp_extract.py --input <filtered.pcapng> --port <测速端口> --output output --max-packets 3000
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime
from statistics import mean, stdev

# Windows 下强制 stdout/stderr 使用 UTF-8，避免中文路径/日志的 GBK 编码错误
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ============================================================
# 常量
# ============================================================

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# tcp_head.md Category 1-5 提取字段列表
EXTRACT_FIELDS = [
    # Category 5: IP Layer
    "frame.time_relative", "frame.number",
    "ip.src", "ip.dst", "ip.ttl", "ip.len", "ip.id", "ip.dsfield",
    # Category 1: TCP Basic
    "tcp.srcport", "tcp.dstport", "tcp.seq", "tcp.ack",
    "tcp.hdr_len", "tcp.len",
    "tcp.window_size_value", "tcp.window_size",
    "tcp.flags",
    # Category 2: TCP Flags
    "tcp.flags.syn", "tcp.flags.ack", "tcp.flags.fin",
    "tcp.flags.reset", "tcp.flags.push", "tcp.flags.urg",
    "tcp.flags.ece", "tcp.flags.cwr",
    # Category 3: TCP Options
    "tcp.options.mss_val", "tcp.options.wscale.shift",
    "tcp.options.sack_perm",
    "tcp.options.timestamp.tsval", "tcp.options.timestamp.tsecr",
    # Category 4: Wireshark TCP Analysis
    "tcp.analysis.ack_rtt",
    "tcp.analysis.retransmission", "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack", "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment", "tcp.analysis.ack_lost_segment",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.zero_window", "tcp.analysis.window_full",
    "tcp.analysis.keep_alive", "tcp.analysis.keep_alive_ack",
]

# Label 类型字段（tshark 输出为文本标签或空值，需转布尔）
LABEL_FIELDS = {
    "tcp.analysis.retransmission",
    "tcp.analysis.fast_retransmission",
    "tcp.analysis.duplicate_ack",
    "tcp.analysis.out_of_order",
    "tcp.analysis.lost_segment",
    "tcp.analysis.ack_lost_segment",
    "tcp.analysis.spurious_retransmission",
    "tcp.analysis.zero_window",
    "tcp.analysis.window_full",
    "tcp.analysis.keep_alive",
    "tcp.analysis.keep_alive_ack",
}

# ============================================================
# 日志
# ============================================================

def setup_logger(output_dir):
    log_dir = os.path.join(output_dir, "log")
    os.makedirs(log_dir, exist_ok=True)
    _log_tmp = os.path.join(log_dir, "_running_tcp_extract.tmp")

    logger = logging.getLogger("tcp_extract")
    logger.setLevel(logging.INFO)
    fmt = logging.Formatter("%(message)s")

    sh = logging.StreamHandler(
        open(sys.stdout.fileno(), mode='w', encoding='utf-8', errors='replace', closefd=False)
    )
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(_log_tmp, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger, _log_tmp


def close_logger(logger, log_tmp_path):
    log_dir = os.path.dirname(log_tmp_path)
    for h in logger.handlers[:]:
        h.close()
        logger.removeHandler(h)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_path = os.path.join(log_dir, f"{ts}_tcp_extract.log")
    if os.path.exists(log_tmp_path):
        try:
            os.rename(log_tmp_path, final_path)
        except OSError:
            pass


# ============================================================
# tshark CLI 提取
# ============================================================

def run_tshark(args, logger, timeout=300):
    """运行 tshark 命令，返回 stdout 文本。"""
    cmd = [TSHARK_PATH] + args
    logger.info(f"  tshark: {' '.join(cmd[:6])}...")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        if result.returncode != 0:
            logger.error(f"  tshark 返回码 {result.returncode}: {result.stderr[:200]}")
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        logger.error(f"  tshark 超时 ({timeout}s)")
        return None
    except FileNotFoundError:
        logger.error(f"  tshark 未找到: {TSHARK_PATH}")
        return None


def tshark_extract_fields(pcapng_path, port, max_packets, logger):
    """用 tshark CLI 提取逐包 TCP 字段。"""
    args = ["-r", pcapng_path, "-T", "fields"]
    for f in EXTRACT_FIELDS:
        args += ["-e", f]
    args += ["-Y", f"tcp.port == {port}", "-c", str(max_packets)]

    output = run_tshark(args, logger)
    if output is None:
        return None

    # 解析 tab 分隔的行
    packets = []
    for line in output.strip().split("\n"):
        if not line.strip():
            continue
        values = line.split("\t")
        if len(values) < len(EXTRACT_FIELDS):
            # 补齐短行
            values += [""] * (len(EXTRACT_FIELDS) - len(values))
        pkt = {}
        for i, field in enumerate(EXTRACT_FIELDS):
            val = values[i].strip() if i < len(values) else ""
            if field in LABEL_FIELDS:
                pkt[field] = val != ""
            else:
                pkt[field] = val
        packets.append(pkt)

    logger.info(f"  tshark 提取 {len(packets)} 个报文字段")
    return packets


def tshark_conversation_stats(pcapng_path, logger):
    """用 tshark CLI 提取 TCP 会话统计。"""
    args = ["-r", pcapng_path, "-q", "-z", "conv,tcp"]
    output = run_tshark(args, logger)
    if output is None:
        return None
    return output


def tshark_io_stat(pcapng_path, port, logger):
    """用 tshark CLI 提取时序吞吐量。"""
    args = ["-r", pcapng_path, "-q", "-z", f"io,stat,1,tcp.port=={port}"]
    output = run_tshark(args, logger)
    if output is None:
        return None
    return output


# ============================================================
# I/O 统计解析
# ============================================================

def parse_io_stat_text(text):
    """解析 tshark -z io,stat 输出文本为结构化数据。"""
    intervals = []
    if text is None:
        return intervals
    # 匹配行如: | 0 <> 1 | 9641 | 752354 |
    pattern = re.compile(r'\|\s*(\d+)\s*<>\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|')
    for line in text.split("\n"):
        m = pattern.search(line)
        if m:
            intervals.append({
                "interval_start": int(m.group(1)),
                "interval_end": int(m.group(2)),
                "frames": int(m.group(3)),
                "bytes": int(m.group(4)),
            })
    return intervals


# ============================================================
# Category 6: 计算统计指标
# ============================================================

def compute_stats(packets, io_intervals, server_ip, client_ip):
    """从逐包字段和 IO 统计计算 Category 6 指标。"""

    if not packets:
        return {}

    # 时间范围
    times = []
    for pkt in packets:
        t = pkt.get("frame.time_relative", "")
        if t:
            try:
                times.append(float(t))
            except ValueError:
                pass

    duration = (max(times) - min(times)) if len(times) >= 2 else 0

    # 分离上下行数据（tcp.len > 0 的包才有 payload）
    def _pkt_has_data(p):
        v = p.get("tcp.len", "")
        try:
            return int(v) > 0
        except (ValueError, TypeError):
            return False

    data_pkts = [p for p in packets if _pkt_has_data(p)]
    server_data = [p for p in data_pkts if p.get("ip.src") == server_ip]
    client_data = [p for p in data_pkts if p.get("ip.src") == client_ip]

    # Total Bytes - 以下行方向为主
    total_bytes_server = 0
    for p in server_data:
        try:
            total_bytes_server += int(p.get("tcp.len", "0"))
        except ValueError:
            pass

    total_bytes_client = 0
    for p in client_data:
        try:
            total_bytes_client += int(p.get("tcp.len", "0"))
        except ValueError:
            pass

    total_packets = len(packets)

    # Avg Throughput (server → client, Mbps)
    avg_throughput_mbps = (total_bytes_server * 8 / duration / 1e6) if duration > 0 else 0

    # Peak Throughput from io_stat
    peak_throughput_mbps = 0
    if io_intervals:
        for iv in io_intervals:
            bps = iv["bytes"] * 8 / 1e6  # 1秒间隔
            if bps > peak_throughput_mbps:
                peak_throughput_mbps = bps

    # RTT stats
    rtt_values = []
    for p in packets:
        rtt = p.get("tcp.analysis.ack_rtt", "")
        if rtt:
            try:
                rtt_values.append(float(rtt))
            except ValueError:
                pass

    avg_rtt = mean(rtt_values) * 1000 if rtt_values else 0  # 转毫秒
    max_rtt = max(rtt_values) * 1000 if rtt_values else 0
    std_rtt = stdev(rtt_values) * 1000 if len(rtt_values) > 1 else 0

    # 异常事件计数
    retrans_count = sum(1 for p in packets if p.get("tcp.analysis.retransmission") is True)
    fast_retrans_count = sum(1 for p in packets if p.get("tcp.analysis.fast_retransmission") is True)
    dup_ack_count = sum(1 for p in packets if p.get("tcp.analysis.duplicate_ack") is True)
    out_of_order_count = sum(1 for p in packets if p.get("tcp.analysis.out_of_order") is True)
    lost_segment_count = sum(1 for p in packets if p.get("tcp.analysis.lost_segment") is True)
    ack_lost_segment_count = sum(1 for p in packets if p.get("tcp.analysis.ack_lost_segment") is True)
    spurious_retrans_count = sum(1 for p in packets if p.get("tcp.analysis.spurious_retransmission") is True)
    zero_window_count = sum(1 for p in packets if p.get("tcp.analysis.zero_window") is True)
    window_full_count = sum(1 for p in packets if p.get("tcp.analysis.window_full") is True)

    # Retransmission Rate
    data_pkt_count = len(data_pkts) if data_pkts else 1
    retrans_rate = (retrans_count / data_pkt_count * 100) if data_pkt_count > 0 else 0

    # Window stats (client → server ACK 方向的窗口，即接收窗口)
    client_windows = []
    for p in packets:
        if p.get("ip.src") == client_ip:
            ws = p.get("tcp.window_size", "")
            if ws:
                try:
                    client_windows.append(int(ws))
                except ValueError:
                    pass

    server_windows = []
    for p in packets:
        if p.get("ip.src") == server_ip:
            ws = p.get("tcp.window_size", "")
            if ws:
                try:
                    server_windows.append(int(ws))
                except ValueError:
                    pass

    return {
        "duration_s": round(duration, 3),
        "total_bytes_server_to_client": total_bytes_server,
        "total_bytes_client_to_server": total_bytes_client,
        "total_packets": total_packets,
        "avg_throughput_mbps": round(avg_throughput_mbps, 2),
        "peak_throughput_mbps": round(peak_throughput_mbps, 2),
        "avg_rtt_ms": round(avg_rtt, 3),
        "max_rtt_ms": round(max_rtt, 3),
        "std_rtt_ms": round(std_rtt, 3),
        "retransmission_count": retrans_count,
        "fast_retransmission_count": fast_retrans_count,
        "retransmission_rate_pct": round(retrans_rate, 2),
        "duplicate_ack_count": dup_ack_count,
        "out_of_order_count": out_of_order_count,
        "lost_segment_count": lost_segment_count,
        "ack_lost_segment_count": ack_lost_segment_count,
        "spurious_retransmission_count": spurious_retrans_count,
        "zero_window_count": zero_window_count,
        "window_full_count": window_full_count,
        "avg_client_window": round(mean(client_windows)) if client_windows else 0,
        "max_client_window": max(client_windows) if client_windows else 0,
        "avg_server_window": round(mean(server_windows)) if server_windows else 0,
        "max_server_window": max(server_windows) if server_windows else 0,
        "rtt_sample_count": len(rtt_values),
        "client_window_sample_count": len(client_windows),
    }


# ============================================================
# SYN 选项提取
# ============================================================

def _is_true(val):
    """判断 tshark 输出值是否为真。支持 "1"、"True"、"true" 等。"""
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("1", "true", "yes")
    return False


def extract_syn_options(packets):
    """从 SYN/SYN-ACK 报文中提取 TCP 选项。"""
    syn_info = {}
    for pkt in packets:
        try:
            syn_val = pkt.get("tcp.flags.syn", "")
            ack_val = pkt.get("tcp.flags.ack", "")
            is_syn = _is_true(syn_val)
            is_ack = _is_true(ack_val)
            if is_syn and not is_ack:
                # 客户端 SYN
                syn_info["client_syn"] = {
                    "ip.src": pkt.get("ip.src", ""),
                    "mss": pkt.get("tcp.options.mss_val", ""),
                    "wscale": pkt.get("tcp.options.wscale.shift", ""),
                    "sack_perm": pkt.get("tcp.options.sack_perm", ""),
                    "window_size_value": pkt.get("tcp.window_size_value", ""),
                }
            elif is_syn and is_ack:
                # 服务端 SYN-ACK
                syn_info["server_syn_ack"] = {
                    "ip.src": pkt.get("ip.src", ""),
                    "mss": pkt.get("tcp.options.mss_val", ""),
                    "wscale": pkt.get("tcp.options.wscale.shift", ""),
                    "sack_perm": pkt.get("tcp.options.sack_perm", ""),
                    "window_size_value": pkt.get("tcp.window_size_value", ""),
                }
        except (ValueError, TypeError):
            pass
    return syn_info


# ============================================================
# 主流程
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="TCP 字段提取 - tshark CLI")
    parser.add_argument("--input", required=True, help="筛选后的 pcapng 文件路径")
    parser.add_argument("--port", required=True, type=int, help="测速服务端口")
    parser.add_argument("--output", default="output", help="输出目录（默认: output）")
    parser.add_argument("--max-packets", type=int, default=5000, help="最大提取报文数（默认: 5000）")
    parser.add_argument("--stats", default="", help="speed_stats.json 路径（可选，用于获取服务端 IP）")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    logger, log_tmp = setup_logger(args.output)

    input_stem = os.path.splitext(os.path.basename(args.input))[0]
    output_json = os.path.join(args.output, f"{input_stem}_tcp_analysis.json")

    logger.info(f"输入: {args.input}")
    logger.info(f"端口: {args.port}")
    logger.info(f"最大报文数: {args.max_packets}")

    # 读取 speed_stats.json 获取服务端/客户端 IP
    server_ip = ""
    client_ip = ""
    if args.stats and os.path.exists(args.stats):
        with open(args.stats, "r", encoding="utf-8") as f:
            stats = json.load(f)
        for flow in stats.get("speed_flows", []):
            if flow.get("category") == "download":
                server_ip = flow.get("dst", "")
                client_ip = flow.get("src", "")
            elif flow.get("category") == "upload":
                server_ip = flow.get("src", "")
                client_ip = flow.get("dst", "")
            if server_ip:
                break

    # 如果没从 stats 获取到，尝试从报文中推断
    if not server_ip or not client_ip:
        logger.info("未从 stats 获取到 IP，将从报文推断")

    # ============================================================
    # 1. 逐包字段提取
    # ============================================================
    logger.info("\n[1/3] 提取逐包 TCP 字段 (tshark CLI)...")

    packets = tshark_extract_fields(args.input, args.port, args.max_packets, logger)
    if packets is None:
        logger.error("  逐包字段提取失败!")
        packets = []

    # 推断 server/client IP
    if packets and (not server_ip or not client_ip):
        ip_counts = defaultdict(int)
        for p in packets:
            src = p.get("ip.src", "")
            if src:
                ip_counts[src] += 1
        if len(ip_counts) >= 2:
            # 数据量大的方向为服务端（下载场景）
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            server_ip = sorted_ips[0][0]
            client_ip = sorted_ips[1][0] if len(sorted_ips) > 1 else ""

    # ============================================================
    # 2. 会话统计
    # ============================================================
    logger.info("\n[2/3] 提取 TCP 会话统计...")

    conv_text = tshark_conversation_stats(args.input, logger)
    if conv_text is None:
        conv_text = ""

    # ============================================================
    # 3. I/O 时序统计
    # ============================================================
    logger.info("\n[3/3] 提取 I/O 时序吞吐量...")

    io_text = tshark_io_stat(args.input, args.port, logger)
    if io_text is None:
        io_text = ""

    io_intervals = parse_io_stat_text(io_text)

    # ============================================================
    # 4. 计算统计指标 + 组装输出
    # ============================================================
    logger.info("\n[4/4] 计算 Category 6 统计指标...")

    computed = compute_stats(packets, io_intervals, server_ip, client_ip)
    syn_options = extract_syn_options(packets)

    logger.info(f"  持续时间: {computed.get('duration_s', 0):.2f}s")
    logger.info(f"  服务端→客户端: {computed.get('total_bytes_server_to_client', 0)} bytes")
    logger.info(f"  平均吞吐: {computed.get('avg_throughput_mbps', 0):.2f} Mbps")
    logger.info(f"  峰值吞吐: {computed.get('peak_throughput_mbps', 0):.2f} Mbps")
    logger.info(f"  重传数: {computed.get('retransmission_count', 0)}")
    logger.info(f"  重复ACK: {computed.get('duplicate_ack_count', 0)}")
    logger.info(f"  丢失段: {computed.get('lost_segment_count', 0)}")
    logger.info(f"  零窗口: {computed.get('zero_window_count', 0)}")

    # 组装最终输出
    result = {
        "metadata": {
            "input_file": args.input,
            "port": args.port,
            "max_packets": args.max_packets,
            "server_ip": server_ip,
            "client_ip": client_ip,
            "extraction_timestamp": datetime.now().isoformat(),
        },
        "syn_options": syn_options,
        "computed_stats": computed,
        "conversation_stats_raw": conv_text,
        "io_stats_intervals": io_intervals,
        "per_packet_count": len(packets),
        "per_packet_fields": packets,
    }

    with open(output_json, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"\n输出: {output_json}")
    logger.info(f"  逐包报文数: {len(packets)}")
    logger.info(f"  I/O 区间数: {len(io_intervals)}")

    close_logger(logger, log_tmp)


if __name__ == "__main__":
    main()
