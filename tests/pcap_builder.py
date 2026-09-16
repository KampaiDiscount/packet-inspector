from __future__ import annotations

import ipaddress
from pathlib import Path
import struct


def ethernet_ipv4_tcp(
    payload: bytes,
    *,
    seq: int,
    src: str = "10.0.0.10",
    dst: str = "10.0.0.20",
    sport: int = 50000,
    dport: int = 80,
    flags: int = 0x18,
) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    total_length = 20 + 20 + len(payload)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0x1234,
        0x4000,
        64,
        6,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        sport,
        dport,
        seq,
        1,
        5 << 4,
        flags,
        65535,
        0,
        0,
    )
    return ethernet + ip_header + tcp_header + payload


def ethernet_ipv4_fragment(
    payload: bytes,
    *,
    fragment_id: int = 0x1234,
    fragment_offset: int = 0,
    more_fragments: bool = True,
    protocol: int = 6,
    src: str = "10.0.0.10",
    dst: str = "10.0.0.20",
) -> bytes:
    if fragment_offset % 8:
        raise ValueError("fragment_offset must be a multiple of eight bytes")
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    fragment_field = fragment_offset // 8
    if more_fragments:
        fragment_field |= 0x2000
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        fragment_id,
        fragment_field,
        64,
        protocol,
        0,
        ipaddress.ip_address(src).packed,
        ipaddress.ip_address(dst).packed,
    )
    return ethernet + ip_header + payload


def write_pcap(
    path: Path,
    packets: list[bytes],
    *,
    wire_lengths: list[int] | None = None,
) -> None:
    if wire_lengths is not None and len(wire_lengths) != len(packets):
        raise ValueError("wire_lengths must match packets")
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, packet in enumerate(packets):
            wire_length = wire_lengths[index] if wire_lengths is not None else len(packet)
            handle.write(
                struct.pack(
                    "<IIII",
                    1_700_000_000 + index,
                    index * 1000,
                    len(packet),
                    wire_length,
                )
            )
            handle.write(packet)
