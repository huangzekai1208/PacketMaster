# ruff: noqa: E402
"""识别测速方向的 TCP 流，并筛选为最小化 pcapng 报文。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
from collections import defaultdict
from contextlib import ExitStack
from pathlib import Path

from scapy.all import IP, TCP, Ether, IPv6

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from lib.progress import ProgressWriter

EPB_TYPE = 0x00000006
SHB_TYPE = 0x0A0D0D0A
IDB_TYPE = 0x00000001
PACKET_BLOCK_TYPE = 0x00000002
SPB_TYPE = 0x00000003
MAX_PCAPNG_BLOCK_SIZE = 64 * 1024 * 1024
MIN_BLOCK_LENGTHS = {
    SHB_TYPE: 28,
    IDB_TYPE: 20,
    EPB_TYPE: 32,
    PACKET_BLOCK_TYPE: 32,
    SPB_TYPE: 16,
}


def parse_packet(raw_bytes: bytes):
    try:
        return Ether(raw_bytes)
    except Exception:
        return None


def flow_key(packet) -> tuple[object, ...] | None:
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    tcp = packet.getlayer(TCP)
    if ip is None or tcp is None:
        return None
    forward = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
    reverse = (ip.dst, int(tcp.dport), ip.src, int(tcp.sport))
    return min(forward, reverse)


def packet_direction(packet) -> tuple[object, ...] | None:
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    tcp = packet.getlayer(TCP)
    if ip is None or tcp is None:
        return None
    return (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))


def _scan_capture(
    capture: Path, progress: ProgressWriter
) -> tuple[
    int,
    int,
    dict[tuple[object, ...], list[int]],
    dict[tuple[object, ...], list[tuple[object, ...] | None]],
    dict[tuple[object, ...], tuple[object, ...]],
    int,
    str,
]:
    total_packets = 0
    total_tcp_packets = 0
    flow_bytes: dict[tuple[object, ...], list[int]] = defaultdict(lambda: [0, 0])
    flow_directions: dict[tuple[object, ...], list[tuple[object, ...] | None]] = {}
    flow_clients: dict[tuple[object, ...], tuple[object, ...]] = {}
    input_size = 0
    digest = hashlib.sha256()
    progress.emit("fingerprint", 0, capture.stat().st_size, "Fingerprinting capture")
    progress.emit("filter_scan", 0, None, "Scanning capture flows")
    try:
        for endian, block_type, block in _read_blocks(capture):
            digest.update(block)
            input_size += len(block)
            if block_type not in {EPB_TYPE, PACKET_BLOCK_TYPE, SPB_TYPE}:
                continue
            raw_bytes, _, wire_length = _packet_block_data(
                block_type, block, endian
            )
            total_packets += 1
            packet = parse_packet(raw_bytes)
            key = flow_key(packet) if packet is not None else None
            direction = packet_direction(packet) if packet is not None else None
            if key is None or direction is None:
                continue
            total_tcp_packets += 1
            directions = flow_directions.setdefault(key, [direction, None])
            if direction == directions[0]:
                index = 0
            elif directions[1] is None:
                directions[1] = direction
                index = 1
            elif direction == directions[1]:
                index = 1
            else:
                index = 0
            flow_bytes[key][index] += wire_length
            tcp = packet.getlayer(TCP)
            if tcp.flags & 0x02 and not tcp.flags & 0x10:
                flow_clients.setdefault(key, direction)
            if total_packets % 100_000 == 0:
                progress.emit(
                    "filter_scan",
                    total_packets,
                    None,
                    f"Scanned {total_packets} packets",
                )
    except OSError as exc:
        raise RuntimeError(f"INVALID_CAPTURE: unable to read capture: {exc}") from exc
    progress.emit("fingerprint", input_size, input_size, "Fingerprint completed")
    progress.emit("filter_scan", total_packets, total_packets, "Capture scan completed")
    return (
        total_packets,
        total_tcp_packets,
        flow_bytes,
        flow_directions,
        flow_clients,
        input_size,
        digest.hexdigest(),
    )


def _classify_flows(
    flow_bytes: dict[tuple[object, ...], list[int]],
    flow_directions: dict[tuple[object, ...], list[tuple[object, ...] | None]],
    flow_clients: dict[tuple[object, ...], tuple[object, ...]],
    min_bytes: int,
    min_ratio: float,
) -> tuple[dict[str, set[tuple[object, ...]]], list[dict[str, object]]]:
    classified = {"download": set(), "upload": set()}
    statistics: list[dict[str, object]] = []
    for key, sizes in flow_bytes.items():
        total = sum(sizes)
        ratio = max(sizes) / total if total else 0.0
        if total < min_bytes or ratio < min_ratio:
            continue
        directions = flow_directions[key]
        client_direction = flow_clients.get(key)
        category = "unknown"
        if client_direction in directions:
            client_index = directions.index(client_direction)
            server_index = 1 - client_index
            category = (
                "upload" if sizes[client_index] > sizes[server_index] else "download"
            )
            classified[category].add(key)
        first_direction = directions[0]
        assert first_direction is not None
        statistics.append(
            {
                "src": first_direction[0],
                "sport": first_direction[1],
                "dst": first_direction[2],
                "dport": first_direction[3],
                "total_bytes": total,
                "direction_bytes": sizes,
                "max_direction_ratio": round(ratio, 6),
                "category": category,
                "client": (
                    f"{client_direction[0]}:{client_direction[1]}"
                    if client_direction is not None
                    else None
                ),
            }
        )
    statistics.sort(key=lambda item: int(item["total_bytes"]), reverse=True)
    return classified, statistics


def _read_blocks(capture: Path):
    endian = "<"
    capture_size = capture.stat().st_size
    with capture.open("rb") as source:
        while True:
            block_start = source.tell()
            header = source.read(8)
            if not header:
                return
            if len(header) != 8:
                raise RuntimeError("INVALID_CAPTURE: truncated pcapng block header")
            raw_type = header[:4]
            if raw_type == struct.pack("<I", SHB_TYPE):
                byte_order_magic = source.read(4)
                if len(byte_order_magic) != 4:
                    raise RuntimeError("INVALID_CAPTURE: truncated section header")
                if byte_order_magic == b"\x4d\x3c\x2b\x1a":
                    endian = "<"
                elif byte_order_magic == b"\x1a\x2b\x3c\x4d":
                    endian = ">"
                else:
                    raise RuntimeError("INVALID_CAPTURE: bad pcapng byte-order magic")
                block_length = struct.unpack(f"{endian}I", header[4:8])[0]
                block_type = SHB_TYPE
                prefix = header + byte_order_magic
            else:
                block_length = struct.unpack(f"{endian}I", header[4:8])[0]
                block_type = struct.unpack(f"{endian}I", raw_type)[0]
                prefix = header

            minimum_length = MIN_BLOCK_LENGTHS.get(block_type, 12)
            if block_length < minimum_length:
                raise RuntimeError("INVALID_CAPTURE: pcapng block is too short")
            if block_length % 4 != 0:
                raise RuntimeError(
                    "INVALID_CAPTURE: pcapng block length is not aligned"
                )
            if block_length > MAX_PCAPNG_BLOCK_SIZE:
                raise RuntimeError(
                    "INVALID_CAPTURE: pcapng block exceeds the 64 MiB safety limit"
                )
            file_remaining = capture_size - block_start
            if block_length > file_remaining:
                raise RuntimeError(
                    "INVALID_CAPTURE: pcapng block length exceeds remaining file size"
                )

            remainder = source.read(block_length - len(prefix))
            block = prefix + remainder
            if len(block) != block_length:
                raise RuntimeError("INVALID_CAPTURE: truncated or invalid pcapng block")
            trailing_length = struct.unpack(f"{endian}I", block[-4:])[0]
            if trailing_length != block_length:
                raise RuntimeError(
                    "INVALID_CAPTURE: pcapng block length trailer does not match"
                )
            yield endian, block_type, block


def _packet_from_epb(block: bytes, endian: str) -> tuple[bytes, int]:
    if len(block) < 32:
        raise RuntimeError("INVALID_CAPTURE: invalid enhanced packet block")
    captured_length = struct.unpack(f"{endian}I", block[20:24])[0]
    end = 28 + captured_length
    if end > len(block) - 4:
        raise RuntimeError("INVALID_CAPTURE: invalid enhanced packet length")
    return block[28:end], captured_length


def _packet_from_spb(block: bytes, endian: str) -> tuple[bytes, int, int]:
    if len(block) < 16:
        raise RuntimeError("INVALID_CAPTURE: invalid simple packet block")
    original_length = struct.unpack(f"{endian}I", block[8:12])[0]
    available_length = len(block) - 16
    captured_length = min(original_length, available_length)
    return block[12 : 12 + captured_length], captured_length, original_length


def _packet_block_data(
    block_type: int, block: bytes, endian: str
) -> tuple[bytes, int, int]:
    if block_type == SPB_TYPE:
        return _packet_from_spb(block, endian)
    packet_data, captured_length = _packet_from_epb(block, endian)
    original_length = struct.unpack(f"{endian}I", block[24:28])[0]
    return packet_data, captured_length, original_length


def _strip_payload(
    block: bytes, packet_data: bytes, captured_length: int, endian: str
) -> bytes:
    packet = parse_packet(packet_data)
    if packet is None or packet.getlayer(TCP) is None:
        return block
    tcp = packet.getlayer(TCP)
    ip = packet.getlayer(IP) or packet.getlayer(IPv6)
    if ip is None or tcp.dataofs is None:
        return block
    l2_length = len(packet_data) - len(bytes(ip))
    ip_header_length = int(ip.ihl) * 4 if isinstance(ip, IP) else 40
    header_end = min(
        l2_length + ip_header_length + int(tcp.dataofs) * 4, captured_length
    )
    if header_end >= captured_length:
        return block

    stripped = bytearray(packet_data[:header_end])
    if isinstance(ip, IP):
        struct.pack_into(">H", stripped, l2_length + 2, header_end - l2_length)
        struct.pack_into(">H", stripped, l2_length + 10, 0)
    else:
        struct.pack_into(">H", stripped, l2_length + 4, header_end - l2_length - 40)
    padding = b"\x00" * ((4 - header_end % 4) % 4)
    new_length = 28 + header_end + len(padding) + 4
    rebuilt = bytearray(block[:20])
    rebuilt.extend(struct.pack(f"{endian}I", header_end))
    rebuilt.extend(struct.pack(f"{endian}I", header_end))
    rebuilt.extend(stripped)
    rebuilt.extend(padding)
    rebuilt.extend(struct.pack(f"{endian}I", new_length))
    struct.pack_into(f"{endian}I", rebuilt, 4, new_length)
    return bytes(rebuilt)


def _strip_spb_payload(
    block: bytes, packet_data: bytes, captured_length: int, endian: str
) -> bytes:
    stripped_epb = _strip_payload(
        b"\x06\x00\x00\x00"
        + struct.pack(f"{endian}I", 32 + captured_length)
        + (b"\x00" * 12)
        + struct.pack(f"{endian}II", captured_length, captured_length)
        + packet_data
        + (b"\x00" * ((4 - captured_length % 4) % 4))
        + struct.pack(
            f"{endian}I", 32 + captured_length + ((4 - captured_length % 4) % 4)
        ),
        packet_data,
        captured_length,
        endian,
    )
    new_captured_length = struct.unpack(f"{endian}I", stripped_epb[20:24])[0]
    new_packet = stripped_epb[28 : 28 + new_captured_length]
    padding = b"\x00" * ((4 - new_captured_length % 4) % 4)
    new_block_length = 16 + new_captured_length + len(padding)
    return (
        struct.pack(f"{endian}III", SPB_TYPE, new_block_length, new_captured_length)
        + new_packet
        + padding
        + struct.pack(f"{endian}I", new_block_length)
    )


def _write_filtered(
    capture: Path,
    output_files: dict[str, Path],
    classified: dict[str, set[tuple[object, ...]]],
    strip_payload: bool,
    progress: ProgressWriter,
) -> dict[str, int]:
    counts = {direction: 0 for direction in output_files}
    progress.emit("filter_write", 0, None, "Writing filtered captures")
    with ExitStack() as stack:
        destinations = {
            direction: stack.enter_context(path.open("wb"))
            for direction, path in output_files.items()
        }
        for endian, block_type, block in _read_blocks(capture):
            if block_type in {SHB_TYPE, IDB_TYPE}:
                for destination in destinations.values():
                    destination.write(block)
                continue
            if block_type in {EPB_TYPE, PACKET_BLOCK_TYPE, SPB_TYPE}:
                packet_data, captured_length, _ = _packet_block_data(
                    block_type, block, endian
                )
                packet = parse_packet(packet_data)
                key = flow_key(packet) if packet is not None else None
                if key is None:
                    continue
                for direction, destination in destinations.items():
                    if key not in classified[direction]:
                        continue
                    filtered_block = block
                    if strip_payload:
                        filtered_block = (
                            _strip_spb_payload(
                                block, packet_data, captured_length, endian
                            )
                            if block_type == SPB_TYPE
                            else _strip_payload(
                                block, packet_data, captured_length, endian
                            )
                        )
                    destination.write(filtered_block)
                    counts[direction] += 1
                continue
            for destination in destinations.values():
                destination.write(block)
    progress.emit(
        "filter_write",
        sum(counts.values()),
        sum(counts.values()),
        "Filtering completed",
    )
    return counts


def _atomic_write_json(path: Path, value: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("w", encoding="utf-8") as output:
            json.dump(value, output, ensure_ascii=False, indent=2)
            output.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def filter_capture(args: argparse.Namespace) -> dict[str, object]:
    capture = Path(args.input).resolve()
    output_directory = Path(args.output).resolve()
    stats_output = Path(args.stats_output).resolve()
    progress = ProgressWriter(Path(args.progress_path).resolve())
    output_directory.mkdir(parents=True, exist_ok=True)

    (
        total_packets,
        total_tcp_packets,
        flow_bytes,
        flow_directions,
        flow_clients,
        input_size,
        sha256,
    ) = _scan_capture(capture, progress)
    if total_tcp_packets == 0:
        raise RuntimeError("NO_TCP_PACKETS: capture contains no TCP packets")
    classified, speed_flows = _classify_flows(
        flow_bytes,
        flow_directions,
        flow_clients,
        args.min_bytes,
        args.min_ratio,
    )
    requested = ["download", "upload"] if args.target == "both" else [args.target]
    available = [direction for direction in requested if classified[direction]]
    if not available:
        raise RuntimeError(
            f"NO_SPEED_FLOW: no {args.target} speed-test flow matched thresholds"
        )
    output_files = {
        direction: (output_directory / f"{capture.stem}_{direction}.pcapng").resolve()
        for direction in available
    }
    written_counts = _write_filtered(
        capture, output_files, classified, args.strip, progress
    )
    summary: dict[str, object] = {
        "status": "completed",
        "input_file": str(capture),
        "input_size_bytes": input_size,
        "sha256": sha256,
        "total_packets": total_packets,
        "total_tcp_packets": total_tcp_packets,
        "total_flows": len(flow_bytes),
        "speed_flows_count": sum(len(flows) for flows in classified.values()),
        "download_flows_count": len(classified["download"]),
        "upload_flows_count": len(classified["upload"]),
        "min_bytes": args.min_bytes,
        "min_direction_ratio": args.min_ratio,
        "enable_strip": args.strip,
        "target": args.target,
        "speed_flows": speed_flows,
        "written_counts": written_counts,
        "filtered_files": {
            direction: str(path) for direction, path in output_files.items()
        },
    }
    _atomic_write_json(stats_output, summary)
    return summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Filter directional speed-test TCP flows"
    )
    parser.add_argument("--input", required=True, help="Input pcapng path")
    parser.add_argument("--output", default="output", help="Filtered capture directory")
    parser.add_argument(
        "--target",
        default="download",
        choices=["download", "upload", "both"],
        help="Requested speed-test direction (default: download)",
    )
    parser.add_argument("--stats-output", help="Explicit speed_stats.json path")
    parser.add_argument("--progress-path", help="Progress JSON Lines path")
    parser.add_argument("--strip", action="store_true", help="Strip TCP payload")
    parser.add_argument("--min-ratio", type=float, default=0.70)
    parser.add_argument("--min-bytes", type=int, default=100 * 1024)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    output = Path(args.output)
    stem = Path(args.input).stem
    args.stats_output = args.stats_output or str(output / f"{stem}_speed_stats.json")
    args.progress_path = args.progress_path or str(output / "progress.jsonl")
    if not 0 <= args.min_ratio <= 1:
        parser.error("--min-ratio must be between 0 and 1")
    if args.min_bytes < 0:
        parser.error("--min-bytes must be non-negative")
    try:
        filter_capture(args)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
