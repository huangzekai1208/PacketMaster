"""生成可复现的多 TCP 流测试报文，供发布门禁与性能测试使用。"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw
from scapy.utils import PcapNgWriter


@dataclass
class Flow:
    client: str
    server: str
    client_port: int
    server_port: int
    direction: str
    client_seq: int = 2
    server_seq: int = 1001


class CaptureWriter:
    def __init__(self, writer: PcapNgWriter) -> None:
        self.writer = writer
        self.packet_count = 0

    def write(self, packet: object) -> None:
        self.packet_count += 1
        packet.time = 1.0 + self.packet_count * 0.0001
        self.writer.write(packet)


def _tcp_packet(
    source: str,
    destination: str,
    source_port: int,
    destination_port: int,
    *,
    flags: str,
    seq: int,
    ack: int = 0,
    window: int = 65535,
    payload: bytes = b"",
) -> object:
    packet = (
        Ether()
        / IP(src=source, dst=destination)
        / TCP(
            sport=source_port,
            dport=destination_port,
            flags=flags,
            seq=seq,
            ack=ack,
            window=window,
        )
    )
    return packet / Raw(payload) if payload else packet


def _handshake(output: CaptureWriter, flow: Flow) -> None:
    output.write(
        _tcp_packet(
            flow.client,
            flow.server,
            flow.client_port,
            flow.server_port,
            flags="S",
            seq=1,
        )
    )
    output.write(
        _tcp_packet(
            flow.server,
            flow.client,
            flow.server_port,
            flow.client_port,
            flags="SA",
            seq=1000,
            ack=2,
        )
    )
    output.write(
        _tcp_packet(
            flow.client,
            flow.server,
            flow.client_port,
            flow.server_port,
            flags="A",
            seq=flow.client_seq,
            ack=flow.server_seq,
        )
    )


def generate_capture(
    path: Path,
    *,
    flow_count: int,
    target: str,
    data_packets_per_flow: int,
    anomaly_after: int,
    include_zero_window: bool,
    payload_size: int,
) -> dict[str, int | str | bool]:
    if not 1 <= flow_count <= 64:
        raise ValueError("flows must be between 1 and 64")
    if data_packets_per_flow < 1:
        raise ValueError("data-packets-per-flow must be positive")
    if target not in {"download", "upload", "both"}:
        raise ValueError("target must be download, upload, or both")
    if target == "both" and flow_count < 2:
        raise ValueError("both target requires at least two flows")
    if anomaly_after < 1:
        raise ValueError("anomaly-after must be positive")
    if not 1 <= payload_size <= 1400:
        raise ValueError("payload-size must be between 1 and 1400")

    requested_target = target
    output_path = path.expanduser().resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(f".{output_path.name}.tmp")
    directions = (
        ["download" if index % 2 == 0 else "upload" for index in range(flow_count)]
        if requested_target == "both"
        else [requested_target] * flow_count
    )
    flows = [
        Flow(
            client=f"192.0.2.{10 + index}",
            server=f"198.51.100.{20 + index}",
            client_port=41000 + index,
            server_port=5201 + index,
            direction=directions[index],
        )
        for index in range(flow_count)
    ]
    payloads = [bytes([65 + index % 26]) * payload_size for index in range(flow_count)]
    writer = PcapNgWriter(str(temporary))
    output = CaptureWriter(writer)
    anomaly_start = 0
    try:
        for flow in flows:
            _handshake(output, flow)
        for _ in range(data_packets_per_flow):
            for index, flow in enumerate(flows):
                if flow.direction == "download":
                    output.write(
                        _tcp_packet(
                            flow.server,
                            flow.client,
                            flow.server_port,
                            flow.client_port,
                            flags="PA",
                            seq=flow.server_seq,
                            ack=flow.client_seq,
                            payload=payloads[index],
                        )
                    )
                    flow.server_seq += payload_size
                else:
                    output.write(
                        _tcp_packet(
                            flow.client,
                            flow.server,
                            flow.client_port,
                            flow.server_port,
                            flags="PA",
                            seq=flow.client_seq,
                            ack=flow.server_seq,
                            payload=payloads[index],
                        )
                    )
                    flow.client_seq += payload_size

        while output.packet_count <= anomaly_after:
            flow = flows[output.packet_count % len(flows)]
            download = flow.direction == "download"
            output.write(
                _tcp_packet(
                    flow.client if download else flow.server,
                    flow.server if download else flow.client,
                    flow.client_port if download else flow.server_port,
                    flow.server_port if download else flow.client_port,
                    flags="A",
                    seq=flow.client_seq if download else flow.server_seq,
                    ack=flow.server_seq if download else flow.client_seq,
                )
            )
        anomaly_start = output.packet_count + 1
        for index, flow in enumerate(flows):
            download = flow.direction == "download"
            retransmit_seq = (
                flow.server_seq - payload_size
                if download
                else flow.client_seq - payload_size
            )
            sender = (
                (flow.server, flow.client, flow.server_port, flow.client_port)
                if download
                else (flow.client, flow.server, flow.client_port, flow.server_port)
            )
            receiver = (
                (flow.client, flow.server, flow.client_port, flow.server_port)
                if download
                else (flow.server, flow.client, flow.server_port, flow.client_port)
            )
            output.write(
                _tcp_packet(
                    *sender,
                    flags="PA",
                    seq=retransmit_seq,
                    ack=flow.client_seq if download else flow.server_seq,
                    payload=payloads[index],
                )
            )
            duplicate_ack = retransmit_seq
            for _ in range(3):
                output.write(
                    _tcp_packet(
                        *receiver,
                        flags="A",
                        seq=flow.client_seq if download else flow.server_seq,
                        ack=duplicate_ack,
                    )
                )
            output.write(
                _tcp_packet(
                    *receiver,
                    flags="A",
                    seq=flow.client_seq if download else flow.server_seq,
                    ack=flow.server_seq if download else flow.client_seq,
                    window=0 if include_zero_window else 65535,
                )
            )
    finally:
        writer.close()
    temporary.replace(output_path)
    return {
        "output": str(output_path),
        "target": requested_target,
        "flows": flow_count,
        "packet_count": output.packet_count,
        "anomaly_start_frame": anomaly_start,
        "zero_window": include_zero_window,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate a deterministic PacketMaster TCP test capture"
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--target",
        choices=["download", "upload", "both"],
        default="download",
    )
    parser.add_argument("--flows", type=int, default=2)
    parser.add_argument("--data-packets-per-flow", type=int, default=2500)
    parser.add_argument("--anomaly-after", type=int, default=5000)
    parser.add_argument("--payload-size", type=int, default=256)
    parser.add_argument("--zero-window", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        result = generate_capture(
            Path(args.output),
            flow_count=args.flows,
            target=args.target,
            data_packets_per_flow=args.data_packets_per_flow,
            anomaly_after=args.anomaly_after,
            include_zero_window=args.zero_window,
            payload_size=args.payload_size,
        )
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
