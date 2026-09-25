"""Exercise the installed native binding, not a mocked callback API."""
from pathlib import Path
import struct

import pytest

from packet_audit.capture import PcapyOfflineSource
from packet_audit.config import AuditConfig, DEFAULT_BPF
from packet_audit.packets import (
    DLT_EN10MB, DLT_IPV4, DLT_IPV6, DLT_LINUX_SLL, DLT_LINUX_SLL2,
    DLT_RAW, parse_packet,
)
from packet_audit.raw_capture import build_dumpcap_command
from tests.test_packets import ipv4, ipv6, udp_datagram


def test_native_offline_reads_every_record_across_batch_boundaries(tmp_path):
    pcapy = pytest.importorskip("pcapy", reason="native libpcap binding required")
    path = tmp_path / "synthetic.pcap"
    records = [b"\x00" * 12 + b"\x08\x00" + bytes([index]) * 50 for index in range(37)]
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for index, raw in enumerate(records):
            stream.write(struct.pack("<IIII", 100 + index, 123456, len(raw), len(raw) + index))
            stream.write(raw)
    with PcapyOfflineSource(path, batch_size=7, pcapy_module=pcapy) as source:
        captured = list(source)
        assert source.eof
        assert source.read_batch() == []
    assert [packet.raw for packet in captured] == records
    assert [packet.packet_id for packet in captured] == list(range(1, 38))
    assert [packet.timestamp_ns for packet in captured] == [
        (100 + index) * 1_000_000_000 + 123_456_000 for index in range(37)
    ]
    assert [packet.wire_length for packet in captured] == [len(raw) + index for index, raw in enumerate(records)]


def _link_frame(datalink: int, network: bytes, tags: tuple[tuple[int, int], ...] = ()) -> bytes:
    next_type = 0x0800 if network[0] >> 4 == 4 else 0x86DD
    body = network
    for tag_type, vlan_id in reversed(tags):
        body = struct.pack("!HH", vlan_id, next_type) + body
        next_type = tag_type
    if datalink == DLT_EN10MB:
        return b"\x00" * 12 + struct.pack("!H", next_type) + body
    if datalink == DLT_LINUX_SLL:
        return b"\x00" * 14 + struct.pack("!H", next_type) + body
    if datalink == DLT_LINUX_SLL2:
        return struct.pack("!H", next_type) + b"\x00" * 18 + body
    if datalink in (DLT_RAW, DLT_IPV4, DLT_IPV6) and not tags:
        return network
    raise AssertionError("unsupported synthetic link frame")


@pytest.mark.parametrize("datalink", [
    DLT_EN10MB, DLT_LINUX_SLL, DLT_LINUX_SLL2, DLT_RAW, DLT_IPV4, DLT_IPV6,
])
def test_default_bpf_preserves_untagged_and_stacked_vlan_ip_with_native_libpcap(tmp_path, datalink):
    pcapy = pytest.importorskip("pcapy", reason="native libpcap binding required")
    ip4 = ipv4(udp_datagram(b"synthetic"), protocol=17)
    ip6 = ipv6(udp_datagram(b"synthetic"))
    cases = [(ip4, ()), (ip6, ())]
    if datalink == DLT_IPV4:
        cases = [(ip4, ())]
    elif datalink == DLT_IPV6:
        cases = [(ip6, ())]
    elif datalink != DLT_RAW:
        cases += [
            (ip4, ((0x8100, 100),)),
            (ip6, ((0x88A8, 200), (0x8100, 201))),
            (ip4, ((0x9100, 300), (0x9200, 301))),
            (ip6, ((0x9200, 400),)),
        ]
    records = [_link_frame(datalink, network, tags) for network, tags in cases]
    path = tmp_path / "tagged.pcap"
    with path.open("wb") as stream:
        stream.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, datalink))
        for index, raw in enumerate(records):
            stream.write(struct.pack("<IIII", 100 + index, 0, len(raw), len(raw)))
            stream.write(raw)
    with PcapyOfflineSource(path, bpf=DEFAULT_BPF, pcapy_module=pcapy) as source:
        captured = list(source)
    assert [packet.raw for packet in captured] == records
    assert [parse_packet(packet).vlan_ids for packet in captured] == [
        tuple(vlan_id for _type, vlan_id in tags) for _network, tags in cases
    ]


def test_analyzer_example_and_raw_ring_share_vlan_capable_default_filter():
    example = AuditConfig.from_toml(Path(__file__).parents[1] / "config" / "example.toml")
    assert example.bpf == AuditConfig().bpf == DEFAULT_BPF
    command = build_dumpcap_command(AuditConfig())
    assert command[command.index("-f") + 1] == DEFAULT_BPF
