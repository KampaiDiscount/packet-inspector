#!/usr/bin/env python3
"""Repeatable synthetic hot-path benchmark; it captures no live traffic."""

from __future__ import annotations

import argparse
import ipaddress
import json
from pathlib import Path
import platform
import struct
import sys
import time

# Permit running directly from a source checkout without installing first.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from packet_audit.detectors import SensitiveDetector
from packet_audit.models import CapturedPacket, ParsedPacket
from packet_audit.packets import parse_packet_strict
from packet_audit.reassembly import TCPReassembler


_PAYLOAD = (
    b"POST /audit HTTP/1.1\r\nHost: synthetic.invalid\r\n"
    b"Authorization: Basic YXVkaXQtdXNlcjpzeW50aGV0aWMtc2VjcmV0\r\n"
    b"Content-Length: 0\r\n\r\n"
)


def _ethernet_ipv4_tcp(payload: bytes, seq: int) -> bytes:
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40 + len(payload),
        1,
        0x4000,
        64,
        6,
        0,
        ipaddress.ip_address("192.0.2.10").packed,
        ipaddress.ip_address("192.0.2.20").packed,
    )
    tcp_header = struct.pack(
        "!HHIIBBHHH", 50000, 80, seq, 1, 5 << 4, 0x18, 65535, 0, 0
    )
    return ethernet + ip_header + tcp_header + payload


def _parsed(packet_id: int, payload: bytes, seq: int, flags: int = 0x18) -> ParsedPacket:
    return ParsedPacket(
        session_id="synthetic-benchmark",
        packet_id=packet_id,
        timestamp_ns=1_700_000_000_000_000_000 + packet_id,
        interface="benchmark0",
        captured_length=54 + len(payload),
        wire_length=54 + len(payload),
        ip_version=4,
        src="192.0.2.10",
        dst="192.0.2.20",
        protocol=6,
        vlan_ids=(),
        network_payload=b"",
        transport_parsed=True,
        sport=50000,
        dport=80,
        tcp_seq=seq,
        tcp_ack=1,
        tcp_flags=flags,
        transport_payload=payload,
    )


def run(packet_count: int, attempt_count: int) -> dict[str, object]:
    frame = _ethernet_ipv4_tcp(_PAYLOAD, 1001)
    captured = CapturedPacket(
        session_id="synthetic-benchmark",
        packet_id=1,
        timestamp_ns=1_700_000_000_000_000_000,
        interface="benchmark0",
        datalink=1,
        captured_length=len(frame),
        wire_length=len(frame),
        raw=frame,
    )

    started = time.perf_counter()
    for _ in range(packet_count):
        if parse_packet_strict(captured) is None:
            raise RuntimeError("synthetic parser fixture was rejected")
    parser_seconds = time.perf_counter() - started

    reassembler = TCPReassembler(max_flows=128)
    detector = SensitiveDetector("synthetic-benchmark", max_flows=128)
    reassembler.process(_parsed(0, b"", 1000, flags=0x02))
    sequence = 1001
    finding_count = 0
    started = time.perf_counter()
    for packet_id in range(1, attempt_count + 1):
        packet = _parsed(packet_id, _PAYLOAD, sequence)
        sequence += len(_PAYLOAD)
        for chunk in reassembler.process(packet):
            finding_count += len(detector.process_stream(chunk))
    pipeline_seconds = time.perf_counter() - started

    return {
        "benchmark": "synthetic-no-live-capture",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "parser": {
            "packets": packet_count,
            "seconds": round(parser_seconds, 6),
            "packets_per_second": round(packet_count / parser_seconds, 1),
        },
        "reassembly_and_detection": {
            "credential_attempts": attempt_count,
            "findings": finding_count,
            "seconds": round(pipeline_seconds, 6),
            "attempts_per_second": round(attempt_count / pipeline_seconds, 1),
        },
        "note": "Synthetic rates are for regression comparison, not a live-line-rate guarantee.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packets", type=int, default=100_000)
    parser.add_argument("--attempts", type=int, default=10_000)
    args = parser.parse_args()
    if args.packets < 1 or args.attempts < 1:
        parser.error("counts must be positive")
    print(json.dumps(run(args.packets, args.attempts), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
