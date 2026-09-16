"""Exercise the installed native binding, not a mocked callback API."""
import struct

import pytest

from packet_audit.capture import PcapyOfflineSource


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
