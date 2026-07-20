"""
测速报文筛选 + TCP payload 剥离脚本
从原始 pcapng 文件中筛选出测速 TCP 流，并剥离 TCP payload，输出轻量 pcapng。

流程：
  第一遍扫描：统计各 TCP 流流量 → 筛选测速流 → 分类上行/下载
  第二遍扫描：根据配置筛选 + 剥离 payload → 输出结果文件

关键：
  - 直接读写原始报文字节，Scapy 仅用于解析五元组和 TCP dataofs
  - 只修改 IP total_length / IP checksum，TCP checksum 不动
  - 支持 VLAN / PPPoE 等多种 L2 封装
"""

import json
import logging
import os
import struct
import sys
from collections import defaultdict
from datetime import datetime
import argparse

# Windows 下强制 stdout/stderr 使用 UTF-8，避免中文路径/日志的 GBK 编码错误
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from scapy.all import Ether, IP, IPv6, RawPcapReader, TCP
from scapy.error import Scapy_Exception


# ============================================================
# 默认配置（可通过 CLI 参数覆盖）
# ============================================================

PCAP_INPUT = ""                   # 输入 pcapng 路径（CLI 必需）
OUTPUT_DIR = "output"             # 输出目录
MIN_DIRECTION_RATIO = 0.70        # 单向流量占比 >= 70% 才认为是测速流
MIN_BYTES = 100 * 1024            # 至少 100KB 流量，过滤噪声流
ENABLE_STRIP = False              # True=开启剥离，False=仅筛选不剥离
STRIP_TARGET = "download"         # 剥离/导出目标: "upload" | "download" | "both"

# ============================================================

# 自动生成输出文件名（以输入文件名为前缀）
_INPUT_STEM = os.path.splitext(os.path.basename(PCAP_INPUT))[0]

_SUFFIX = "_stripped" if ENABLE_STRIP else ""

# 根据 ENABLE_STRIP 和 STRIP_TARGET 决定输出哪些文件
if not ENABLE_STRIP:
    # 仅筛选：按 STRIP_TARGET 决定导出哪些流（不剥离）
    if STRIP_TARGET == "download":
        OUTPUT_FILES = {
            "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download.pcapng"),
        }
    elif STRIP_TARGET == "upload":
        OUTPUT_FILES = {
            "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload.pcapng"),
        }
    else:  # "both"
        OUTPUT_FILES = {
            "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload.pcapng"),
            "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download.pcapng"),
        }
elif STRIP_TARGET == "download":
    OUTPUT_FILES = {
        "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download{_SUFFIX}.pcapng"),
    }
elif STRIP_TARGET == "upload":
    OUTPUT_FILES = {
        "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload{_SUFFIX}.pcapng"),
    }
else:  # "both"
    OUTPUT_FILES = {
        "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload{_SUFFIX}.pcapng"),
        "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download{_SUFFIX}.pcapng"),
    }

STATS_JSON = os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_speed_stats.json")

# pcapng 块类型常量
EPB_TYPE = 0x00000006
SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001


# ============================================================
# 工具函数
# ============================================================

def read_block(f):
    """从 pcapng 文件读取一个完整块，返回 (block_type, raw_block_bytes) 或 None(EOF)。"""
    header = f.read(8)
    if len(header) < 8:
        return None
    block_type = struct.unpack('<I', header[:4])[0]
    block_len = struct.unpack('<I', header[4:8])[0]
    remaining = f.read(block_len - 8)
    if len(remaining) < block_len - 8:
        return None
    return block_type, header + remaining


def setup_logger():
    """配置日志：同时输出到终端和 output/log 目录下的日志文件。"""
    log_dir = os.path.join(OUTPUT_DIR, "log")
    os.makedirs(log_dir, exist_ok=True)

    _log_tmp = os.path.join(log_dir, "_running_filter_strip.tmp")

    logger = logging.getLogger("speed_filter_strip")
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

    return logger


def close_logger(logger):
    """关闭日志并将临时文件重命名为运行结束时间。"""
    log_dir = os.path.join(OUTPUT_DIR, "log")
    _log_tmp = os.path.join(log_dir, "_running_filter_strip.tmp")

    for h in logger.handlers[:]:
        h.close()
        logger.removeHandler(h)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    final_path = os.path.join(log_dir, f"{ts}_filter_strip.log")
    if os.path.exists(_log_tmp):
        try:
            os.rename(_log_tmp, final_path)
        except OSError:
            pass


# ============================================================
# 第一遍：筛选相关函数
# ============================================================

def get_flow_key(pkt):
    """从 TCP 报文中提取五元组 key（双向归一化）。"""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    tcp = pkt.getlayer(TCP)
    if tcp is None:
        return None
    a = (ip.src, tcp.sport, ip.dst, tcp.dport)
    b = (ip.dst, tcp.dport, ip.src, tcp.sport)
    return a if a < b else b


def get_direction(pkt):
    """返回报文方向 (src_ip, src_port, dst_ip, dst_port)。"""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    tcp = pkt.getlayer(TCP)
    if tcp is None:
        return None
    return (ip.src, tcp.sport, ip.dst, tcp.dport)


def parse_raw_packet(raw_bytes):
    """从原始报文字节解析出 Scapy 报文（仅用于提取五元组）。"""
    try:
        return Ether(raw_bytes)
    except Exception:
        return None


# ============================================================
# 第二遍：剥离相关函数
# ============================================================

def _calc_l2_len(pkt_data):
    """
    从原始报文字节逐层解析 L2 封装，返回 IP 头的起始偏移。
    支持：普通 Ethernet(14)、802.1Q VLAN(18)、PPPoE over VLAN(~26) 等。
    """
    offset = 0
    while offset + 14 <= len(pkt_data):
        ether_type = struct.unpack('>H', pkt_data[offset + 12:offset + 14])[0]

        if ether_type == 0x8100:
            offset += 4
            continue

        if ether_type in (0x0800, 0x86DD):
            offset += 14
            return offset

        if ether_type in (0x8863, 0x8864):
            offset += 14
            offset += 6  # PPPoE 头
            offset += 2  # PPP 头
            return offset

        offset += 14
        return offset

    return 14


def _should_strip(fkey, upload_flows, download_flows):
    """判断某条流是否需要剥离 payload，基于 STRIP_TARGET 配置。"""
    if STRIP_TARGET == "both":
        return fkey in upload_flows or fkey in download_flows
    elif STRIP_TARGET == "upload":
        return fkey in upload_flows
    elif STRIP_TARGET == "download":
        return fkey in download_flows
    return False


def is_tcp_and_get_header_end(pkt_data, caplen):
    """
    判断报文是否为 TCP，并返回 (header_end, l2_len)。
    非 TCP 返回 None。
    """
    try:
        pkt = Ether(pkt_data)
    except Exception:
        return None

    tcp_layer = pkt.getlayer(TCP)
    if tcp_layer is None:
        return None

    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip_layer is None:
        return None

    l2_len = _calc_l2_len(pkt_data)

    if isinstance(ip_layer, IP):
        ip_hdr_len = ip_layer.ihl * 4
    else:
        ip_hdr_len = 40

    tcp_hdr_len = tcp_layer.dataofs * 4

    header_end = l2_len + ip_hdr_len + tcp_hdr_len
    header_end = min(header_end, caplen)

    return header_end, l2_len


def ipv4_checksum(header_bytes):
    """计算 IPv4 头部 checksum（反码求和算法）。"""
    if len(header_bytes) % 2:
        header_bytes += b'\x00'
    s = 0
    for i in range(0, len(header_bytes), 2):
        s += (header_bytes[i] << 8) + header_bytes[i + 1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def fix_ip_header(pkt_data, header_end, l2_len):
    """
    修正 IP 头部字段并截断报文到 header_end。
    IPv4：更新 total_length + 重算 checksum
    IPv6：更新 payload_len
    """
    result = bytearray(pkt_data[:header_end])

    ip_version = (result[l2_len] >> 4) & 0x0F
    ip_offset = l2_len

    if ip_version == 4:
        new_total_length = header_end - l2_len
        struct.pack_into('>H', result, ip_offset + 2, new_total_length)
        struct.pack_into('>H', result, ip_offset + 10, 0)
        ip_header = bytes(result[ip_offset:ip_offset + new_total_length])
        chksum = ipv4_checksum(ip_header)
        struct.pack_into('>H', result, ip_offset + 10, chksum)

    elif ip_version == 6:
        ipv6_hdr_len = 40
        new_payload_len = header_end - l2_len - ipv6_hdr_len
        struct.pack_into('>H', result, ip_offset + 4, new_payload_len)

    return bytes(result)


def rebuild_epb(block_data, new_pkt_data):
    """用新的报文数据重建 EPB 块。"""
    epb_head = block_data[:20]

    new_caplen = len(new_pkt_data)
    new_origlen = new_caplen

    padding_len = (4 - (new_caplen % 4)) % 4
    padded_pkt = new_pkt_data + b'\x00' * padding_len

    block_total_length = 20 + 4 + 4 + new_caplen + padding_len + 4

    new_block = bytearray()
    new_block += epb_head
    new_block += struct.pack('<I', new_caplen)
    new_block += struct.pack('<I', new_origlen)
    new_block += padded_pkt
    new_block += struct.pack('<I', block_total_length)

    struct.pack_into('<I', new_block, 4, block_total_length)

    return bytes(new_block)


# ============================================================
# 主流程
# ============================================================

def filter_and_strip():
    """主流程：筛选测速流 + 剥离 TCP payload，输出结果。"""
    log = setup_logger()

    log.info(f"输入: {PCAP_INPUT}")
    strip_info = f"{STRIP_TARGET}" if ENABLE_STRIP else "关闭（仅筛选）"
    log.info(f"剥离: {strip_info}")
    log.info(f"筛选参数: MIN_DIRECTION_RATIO={MIN_DIRECTION_RATIO}, MIN_BYTES={MIN_BYTES/1024:.0f}KB")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # ---- 第一遍扫描：统计各流流量 + 记录 SYN 客户端方向 ----
    log.info(f"\n[1/3] 扫描报文: {PCAP_INPUT}")
    flow_bytes = defaultdict(lambda: [0, 0])
    flow_dirs = {}
    flow_client = {}
    packet_count = 0
    tcp_count = 0

    try:
        with RawPcapReader(PCAP_INPUT) as reader:
            for raw_bytes, meta in reader:
                packet_count += 1
                if packet_count % 100000 == 0:
                    log.info(f"  已扫描 {packet_count} 个报文...")

                pkt = parse_raw_packet(raw_bytes)
                if pkt is None:
                    continue

                fkey = get_flow_key(pkt)
                if fkey is None:
                    continue
                tcp_count += 1
                direction = get_direction(pkt)
                if direction is None:
                    continue

                pkt_len = meta.wirelen

                if fkey not in flow_dirs:
                    flow_dirs[fkey] = [direction, None]
                dirs = flow_dirs[fkey]
                if direction == dirs[0]:
                    flow_bytes[fkey][0] += pkt_len
                elif dirs[1] is None:
                    dirs[1] = direction
                    flow_bytes[fkey][1] += pkt_len
                elif direction == dirs[1]:
                    flow_bytes[fkey][1] += pkt_len
                else:
                    flow_bytes[fkey][0] += pkt_len

                tcp = pkt.getlayer(TCP)
                if tcp.flags & 0x02 and not (tcp.flags & 0x10):
                    if fkey not in flow_client:
                        flow_client[fkey] = direction
    except Scapy_Exception as e:
        log.error(f"错误: 无法读取 pcapng 文件: {e}")
        sys.exit(1)

    log.info(f"  总报文: {packet_count}, TCP报文: {tcp_count}, TCP流数: {len(flow_bytes)}")

    # ---- 调试：输出所有流统计 ----
    log.info("\n[DEBUG] 所有流统计（按总流量降序）：")
    debug_list = []
    for fkey, sizes in flow_bytes.items():
        total = sizes[0] + sizes[1]
        max_dir_ratio = max(sizes[0], sizes[1]) / total if total > 0 else 0
        debug_list.append({"fkey": fkey, "total": total,
                           "dir_a": sizes[0], "dir_b": sizes[1], "ratio": max_dir_ratio})
    debug_list.sort(key=lambda x: x["total"], reverse=True)
    for i, d in enumerate(debug_list):
        log.info(f"  {i+1}. total={d['total']/1024:.1f}KB "
                 f"dir_a={d['dir_a']/1024:.1f}KB dir_b={d['dir_b']/1024:.1f}KB "
                 f"ratio={d['ratio']:.3f}")

    over_min_bytes = [d for d in debug_list if d["total"] >= MIN_BYTES]
    log.info(f"\n[DEBUG] 超过MIN_BYTES({MIN_BYTES/1024:.0f}KB)的流: {len(over_min_bytes)}条")
    passed = [d for d in over_min_bytes if d["ratio"] >= MIN_DIRECTION_RATIO]
    failed_ratio = [d for d in over_min_bytes if d["ratio"] < MIN_DIRECTION_RATIO]
    log.info(f"[DEBUG] 通过单向占比筛选: {len(passed)}条")
    log.info(f"[DEBUG] 未通过单向占比筛选: {len(failed_ratio)}条")
    if failed_ratio:
        log.info(f"[DEBUG] 未通过流的单向占比: {[round(d['ratio'],3) for d in failed_ratio[:10]]}")

    # ---- 筛选测速流 + 分类上行/下载 ----
    log.info("\n[2/3] 筛选测速流...")

    speed_flows = set()
    upload_flows = set()
    download_flows = set()
    stats_list = []

    for fkey, sizes in flow_bytes.items():
        total = sizes[0] + sizes[1]
        if total < MIN_BYTES:
            continue
        max_dir_ratio = max(sizes[0], sizes[1]) / total if total > 0 else 0

        if max_dir_ratio >= MIN_DIRECTION_RATIO:
            speed_flows.add(fkey)
            dirs = flow_dirs[fkey]
            client_dir = flow_client.get(fkey)

            category = "unknown"
            if client_dir is not None:
                if client_dir == dirs[0]:
                    client_idx, server_idx = 0, 1
                elif dirs[1] is not None and client_dir == dirs[1]:
                    client_idx, server_idx = 1, 0
                else:
                    client_idx, server_idx = None, None

                if client_idx is not None:
                    if sizes[client_idx] > sizes[server_idx]:
                        category = "upload"
                        upload_flows.add(fkey)
                    else:
                        category = "download"
                        download_flows.add(fkey)

            stats_list.append({
                "src": dirs[0][0], "sport": dirs[0][1],
                "dst": dirs[0][2], "dport": dirs[0][3],
                "total_bytes": total,
                "total_mb": round(total / (1024 * 1024), 2),
                "dir_a_bytes": sizes[0], "dir_b_bytes": sizes[1],
                "max_direction_ratio": round(max_dir_ratio, 3),
                "category": category,
                "client": client_dir[0] + ":" + str(client_dir[1]) if client_dir else None,
            })

    stats_list.sort(key=lambda x: x["total_bytes"], reverse=True)
    log.info(f"  测速流数量: {len(speed_flows)} / {len(flow_bytes)}")
    log.info(f"  上行测速: {len(upload_flows)} 条, 下载测速: {len(download_flows)} 条")

    # ---- 写 JSON 统计 ----
    summary = {
        "input_file": PCAP_INPUT,
        "total_packets": packet_count,
        "total_tcp_packets": tcp_count,
        "total_flows": len(flow_bytes),
        "speed_flows_count": len(speed_flows),
        "upload_flows_count": len(upload_flows),
        "download_flows_count": len(download_flows),
        "min_bytes": MIN_BYTES,
        "min_direction_ratio": MIN_DIRECTION_RATIO,
        "enable_strip": ENABLE_STRIP,
        "strip_target": STRIP_TARGET if ENABLE_STRIP else None,
        "speed_flows": stats_list,
    }
    with open(STATS_JSON, "w", encoding="utf-8") as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    log.info(f"  统计摘要: {STATS_JSON}")

    # ---- 第二遍：筛选 + 剥离 + 输出 ----
    log.info(f"\n[3/3] 输出结果（剥离: {strip_info}）...")

    written_counts = {key: 0 for key in OUTPUT_FILES}
    stripped_count = 0

    try:
        open_files = {key: open(path, 'wb') for key, path in OUTPUT_FILES.items()}
        all_dst = list(open_files.values())

        with open(PCAP_INPUT, 'rb') as src:
            for key, dst in open_files.items():
                # context manager 不嵌套，手动管理
                pass

            while True:
                result = read_block(src)
                if result is None:
                    break
                block_type, block_data = result

                if block_type in (SHB_TYPE, IDB_TYPE):
                    for dst in all_dst:
                        dst.write(block_data)
                    continue

                if block_type == EPB_TYPE:
                    caplen = struct.unpack('<I', block_data[20:24])[0]
                    pkt_data = block_data[28: 28 + caplen]

                    pkt = parse_raw_packet(pkt_data)
                    if pkt is None:
                        continue

                    fkey = get_flow_key(pkt)
                    if fkey is None or fkey not in speed_flows:
                        continue

                    # 判断该流属于哪个分类
                    is_upload = fkey in upload_flows
                    is_download = fkey in download_flows

                    # 确定写入哪些输出文件
                    targets = []
                    if "speed" in open_files:
                        targets.append(("speed", open_files["speed"]))
                    if is_upload and "upload" in open_files:
                        targets.append(("upload", open_files["upload"]))
                    if is_download and "download" in open_files:
                        targets.append(("download", open_files["download"]))

                    if not targets:
                        continue

                    # 判断该流是否需要剥离 payload
                    need_strip = ENABLE_STRIP and _should_strip(fkey, upload_flows, download_flows)

                    if need_strip:
                        strip_result = is_tcp_and_get_header_end(pkt_data, caplen)
                        if strip_result is not None:
                            header_end, l2_len = strip_result
                            if header_end < caplen:
                                new_pkt_data = fix_ip_header(pkt_data, header_end, l2_len)
                                new_block = rebuild_epb(block_data, new_pkt_data)
                                for cat, dst in targets:
                                    dst.write(new_block)
                                    written_counts[cat] += 1
                                stripped_count += 1
                                continue

                    # 不需要剥离 或 无 payload 可剥离 → 原样写入
                    for cat, dst in targets:
                        dst.write(block_data)
                        written_counts[cat] += 1

                    total_written = sum(written_counts.values())
                    if total_written % 100000 == 0 and total_written > 0:
                        log.info(f"  已写出 {total_written} 个报文（剥离 {stripped_count}）...")

                    continue

                # 其他块类型写入所有输出文件
                for dst in all_dst:
                    dst.write(block_data)

        # 关闭所有输出文件
        for dst in all_dst:
            dst.close()

    except Exception as e:
        log.error(f"错误: {e}")
        sys.exit(1)

    # 统计输出
    input_size = 0
    try:
        input_size = os.path.getsize(PCAP_INPUT)
    except OSError:
        pass

    log.info("")
    log.info("=" * 50)
    log.info("处理完成！统计信息：")
    log.info(f"  总报文数:      {packet_count}")
    total_written = sum(written_counts.values())
    log.info(f"  测速流报文:    {total_written}")
    for cat, count in written_counts.items():
        log.info(f"    {cat}: {count}")
    log.info(f"  剥离 payload:  {stripped_count}")
    log.info(f"  原始大小:      {input_size / (1024*1024):.1f} MB")
    for cat, path in OUTPUT_FILES.items():
        try:
            sz = os.path.getsize(path)
            log.info(f"  {cat} 输出:     {path} ({sz / (1024*1024):.1f} MB)")
        except OSError:
            log.info(f"  {cat} 输出:     {path}")
    log.info("=" * 50)

    close_logger(log)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="测速报文筛选 + TCP payload 剥离")
    parser.add_argument("--input", required=True, help="输入 pcapng 文件路径")
    parser.add_argument("--output", default="output", help="输出目录（默认: output）")
    parser.add_argument("--target", default="download",
                        choices=["upload", "download", "both"],
                        help="导出/剥离方向（默认: download）")
    parser.add_argument("--strip", action="store_true",
                        help="启用 TCP payload 剥离（默认: 仅筛选不剥离）")
    parser.add_argument("--min-ratio", type=float, default=0.70,
                        help="单向流量占比阈值（默认: 0.70）")
    parser.add_argument("--min-bytes", type=int, default=102400,
                        help="最小流量字节数（默认: 102400）")
    args = parser.parse_args()

    # 用 CLI 参数覆盖全局配置
    PCAP_INPUT = args.input
    OUTPUT_DIR = args.output
    STRIP_TARGET = args.target
    ENABLE_STRIP = args.strip
    MIN_DIRECTION_RATIO = args.min_ratio
    MIN_BYTES = args.min_bytes

    # 重新计算依赖配置的变量
    _INPUT_STEM = os.path.splitext(os.path.basename(PCAP_INPUT))[0]
    _SUFFIX = "_stripped" if ENABLE_STRIP else ""
    if not ENABLE_STRIP:
        if STRIP_TARGET == "download":
            OUTPUT_FILES = {"download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download.pcapng")}
        elif STRIP_TARGET == "upload":
            OUTPUT_FILES = {"upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload.pcapng")}
        else:
            OUTPUT_FILES = {
                "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload.pcapng"),
                "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download.pcapng"),
            }
    elif STRIP_TARGET == "download":
        OUTPUT_FILES = {"download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download{_SUFFIX}.pcapng")}
    elif STRIP_TARGET == "upload":
        OUTPUT_FILES = {"upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload{_SUFFIX}.pcapng")}
    else:
        OUTPUT_FILES = {
            "upload": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_upload{_SUFFIX}.pcapng"),
            "download": os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_download{_SUFFIX}.pcapng"),
        }
    STATS_JSON = os.path.join(OUTPUT_DIR, f"{_INPUT_STEM}_speed_stats.json")

    # 注入到模块全局命名空间（供 filter_and_strip 内部引用）
    globals().update(locals())

    filter_and_strip()
