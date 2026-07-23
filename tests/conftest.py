from __future__ import annotations

import os
import struct
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Ether
from scapy.utils import PcapNgWriter

from tests.helpers import load_script_module


def _speed_packets() -> list[object]:
    client = "192.0.2.10"
    server = "198.51.100.20"
    download = [
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=41000, dport=5201, flags="S", seq=1),
        Ether()
        / IP(src=server, dst=client)
        / TCP(sport=5201, dport=41000, flags="SA", seq=10, ack=2),
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=41000, dport=5201, flags="A", seq=2, ack=11),
        *[
            Ether()
            / IP(src=server, dst=client)
            / TCP(sport=5201, dport=41000, flags="PA", seq=11 + index * 256, ack=2)
            / (b"D" * 256)
            for index in range(3)
        ],
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=41000, dport=5201, flags="A", seq=2, ack=779),
    ]
    upload = [
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=42000, dport=5202, flags="S", seq=1),
        Ether()
        / IP(src=server, dst=client)
        / TCP(sport=5202, dport=42000, flags="SA", seq=10, ack=2),
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=42000, dport=5202, flags="A", seq=2, ack=11),
        *[
            Ether()
            / IP(src=client, dst=server)
            / TCP(sport=42000, dport=5202, flags="PA", seq=2 + index * 256, ack=11)
            / (b"U" * 256)
            for index in range(3)
        ],
        Ether()
        / IP(src=server, dst=client)
        / TCP(sport=5202, dport=42000, flags="A", seq=11, ack=770),
    ]
    return download + upload


def _write_packets(path: Path, packets: list[object]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    writer = PcapNgWriter(str(path))
    try:
        for index, packet in enumerate(packets):
            packet.time = 1.0 + index * 0.01
            writer.write(packet)
    finally:
        writer.close()
    return path.resolve()


@pytest.fixture(scope="session")
def tshark_path() -> Path:
    module = load_script_module("lib/tshark.py", "integration_tshark_discovery")
    try:
        return module.find_tshark()
    except RuntimeError as exc:
        if str(exc).startswith("DEPENDENCY_UNAVAILABLE"):
            if os.environ.get("PACKETMASTER_REQUIRE_TSHARK") == "1":
                pytest.fail("TShark is required by this release gate")
            pytest.skip("tshark not installed")
        raise


@pytest.fixture
def sample_capture(tmp_path: Path) -> Path:
    capture = tmp_path / "capture source" / "sample.pcapng"
    return _write_packets(capture, _speed_packets())


def _simple_packet_block(packet: object) -> bytes:
    packet_data = bytes(packet)
    padding = b"\x00" * ((4 - len(packet_data) % 4) % 4)
    block_length = 16 + len(packet_data) + len(padding)
    return (
        struct.pack("<III", 3, block_length, len(packet_data))
        + packet_data
        + padding
        + struct.pack("<I", block_length)
    )


@pytest.fixture
def spb_capture(tmp_path: Path) -> Path:
    path = tmp_path / "simple packet blocks.pcapng"
    section_header = (
        struct.pack("<II", 0x0A0D0D0A, 28)
        + struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1)
        + struct.pack("<I", 28)
    )
    interface_description = struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
    blocks = b"".join(_simple_packet_block(packet) for packet in _speed_packets())
    path.write_bytes(section_header + interface_description + blocks)
    return path.resolve()


@pytest.fixture
def no_tcp_capture(tmp_path: Path) -> Path:
    packet = (
        Ether()
        / IP(src="192.0.2.1", dst="198.51.100.1")
        / UDP(sport=1, dport=2)
        / b"udp"
    )
    return _write_packets(tmp_path / "udp only.pcapng", [packet])


@pytest.fixture
def no_speed_flow_capture(tmp_path: Path) -> Path:
    client = "192.0.2.10"
    server = "198.51.100.20"
    packets = [
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=43000, dport=5203, flags="S", seq=1),
        Ether()
        / IP(src=server, dst=client)
        / TCP(sport=5203, dport=43000, flags="SA", seq=10, ack=2),
        Ether()
        / IP(src=client, dst=server)
        / TCP(sport=43000, dport=5203, flags="PA", seq=2, ack=11)
        / (b"U" * 100),
        Ether()
        / IP(src=server, dst=client)
        / TCP(sport=5203, dport=43000, flags="PA", seq=11, ack=102)
        / (b"D" * 100),
    ]
    return _write_packets(tmp_path / "balanced tcp.pcapng", packets)
