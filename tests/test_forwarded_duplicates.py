"""Admission, proof, bounds, and non-forwarded-auth regression gates."""

from __future__ import annotations

from pathlib import Path
import ipaddress
import queue
import struct

import pytest

from packet_audit.config import AuditConfig
from packet_audit.forwarded_duplicates import (
    ForwardedDuplicateSuppressor,
    describe_forwarded_frame,
)
from packet_audit.models import CapturedPacket
from packet_audit.packets import parse_packet_strict
from packet_audit.supervisor import AuditSupervisor


LOCAL = bytes.fromhex("080027b84ff6")
VICTIM = bytes.fromhex("525400123500")
GATEWAY = bytes.fromhex("08002706d308")


def test_suppression_is_default_off_and_requires_explicit_boolean_opt_in(
    tmp_path: Path,
) -> None:
    assert AuditConfig().forwarded_duplicate_suppression is False
    config_file = tmp_path / "audit.toml"
    config_file.write_text("[capture]\nforwarded_duplicate_suppression = true\n")
    assert AuditConfig.from_toml(config_file).forwarded_duplicate_suppression is True
    with pytest.raises(ValueError, match="must be true or false"):
        AuditConfig(forwarded_duplicate_suppression="true").validate()


def _checksum(header: bytes) -> int:
    total = sum(int.from_bytes(header[index : index + 2], "big") for index in range(0, len(header), 2))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _frame(
    packet_id: int,
    *,
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: str = "192.168.1.11",
    dst_ip: str = "65.61.137.117",
    hop: int = 64,
    payload: bytes = b"GET /login HTTP/1.1\r\n\r\n",
    ip_id: int = 123,
    wire_extra: int = 0,
) -> tuple[CapturedPacket, object]:
    tcp = struct.pack("!HHIIHHHH", 50000, 80, 1000, 1, 0x5018, 65535, 0, 0)
    ip = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(tcp) + len(payload),
            ip_id,
            0,
            hop,
            6,
            0,
            ipaddress.IPv4Address(src_ip).packed,
            ipaddress.IPv4Address(dst_ip).packed,
        )
    )
    ip[10:12] = _checksum(ip).to_bytes(2, "big")
    raw = dst_mac + src_mac + b"\x08\x00" + bytes(ip) + tcp + payload
    captured = CapturedPacket(
        session_id="forwarded-test",
        packet_id=packet_id,
        timestamp_ns=packet_id,
        interface="eth0",
        datalink=1,
        captured_length=len(raw),
        wire_length=len(raw) + wire_extra,
        raw=raw,
    )
    return captured, parse_packet_strict(captured)


def _supervisor(tmp_path: Path) -> AuditSupervisor:
    config = AuditConfig(
        workers=1,
        raw_capture_enabled=False,
        forwarded_duplicate_suppression=True,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    supervisor = AuditSupervisor(config)
    supervisor.forwarded_duplicate_suppressor = ForwardedDuplicateSuppressor(LOCAL)
    supervisor.worker_queues[0] = queue.Queue()
    # Force queue pressure without filling the queue.  This exercises the
    # admission rule separately from actual queue capacity.
    supervisor.worker_queue_byte_counters[0].value = 8 * 1024 * 1024
    return supervisor


def _pair() -> tuple[tuple[CapturedPacket, object], tuple[CapturedPacket, object]]:
    ingress = _frame(1, src_mac=VICTIM, dst_mac=LOCAL)
    forwarded = _frame(2, src_mac=LOCAL, dst_mac=GATEWAY, hop=63)
    return ingress, forwarded


def _descriptors(*items: tuple[CapturedPacket, object]) -> dict[int, object]:
    result = {}
    for captured, parsed in items:
        frame = describe_forwarded_frame(captured, parsed, LOCAL)
        if frame is not None:
            result[captured.packet_id] = frame
    return result


def test_same_batch_suppression_requires_admitted_ingress(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    ingress, forwarded = _pair()
    supervisor.captured_packets = 2
    supervisor._dispatch_batch(
        0, [ingress[1], forwarded[1]], _descriptors(ingress, forwarded)
    )
    admitted, _bytes = supervisor.worker_queues[0].get_nowait()
    assert [packet.packet_id for packet in admitted] == [1]
    assert supervisor.dispatched_packets == 1
    assert supervisor.suppressed_forwarded_duplicate_packets == 1
    assert supervisor.userspace_queue_drops == 0
    assert (
        supervisor.dispatched_packets
        + supervisor.suppressed_forwarded_duplicate_packets
        + supervisor.userspace_queue_drops
        == supervisor.captured_packets
    )


def test_raw_forwarder_same_hop_and_checksum_copy_is_suppressed(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    ingress = _frame(1, src_mac=VICTIM, dst_mac=LOCAL)
    forwarded = _frame(2, src_mac=LOCAL, dst_mac=GATEWAY, hop=64)
    supervisor._dispatch_batch(
        0, [ingress[1], forwarded[1]], _descriptors(ingress, forwarded)
    )
    assert supervisor.dispatched_packets == 1
    assert supervisor.suppressed_forwarded_duplicate_packets == 1


def test_failed_ingress_admission_counts_both_frames_as_real_drops(tmp_path: Path) -> None:
    class FullQueue:
        def put_nowait(self, _item):
            raise queue.Full

    supervisor = _supervisor(tmp_path)
    supervisor.worker_queues[0] = FullQueue()
    ingress, forwarded = _pair()
    supervisor.captured_packets = 2
    supervisor._dispatch_batch(
        0, [ingress[1], forwarded[1]], _descriptors(ingress, forwarded)
    )
    assert supervisor.dispatched_packets == 0
    assert supervisor.suppressed_forwarded_duplicate_packets == 0
    assert supervisor.userspace_queue_drops == 2
    assert supervisor.worker_queue_slot_dropped_packets == 2
    assert supervisor.forwarded_duplicate_suppressor.entries == 0


def test_failed_mixed_batch_preserves_prior_skip_and_counts_unrelated_drop(
    tmp_path: Path,
) -> None:
    class FullQueue:
        def put_nowait(self, _item):
            raise queue.Full

    supervisor = _supervisor(tmp_path)
    ingress, forwarded = _pair()
    supervisor._dispatch_batch(0, [ingress[1]], _descriptors(ingress))
    assert supervisor.forwarded_duplicate_suppressor.entries == 1
    supervisor.worker_queues[0] = FullQueue()
    unrelated = _frame(
        3, src_mac=LOCAL, dst_mac=GATEWAY,
        src_ip="192.168.1.10", dst_ip="203.0.113.20",
        payload=b"Authorization: Basic ZHVtbXk=\r\n",
    )
    supervisor.captured_packets = 3
    supervisor._dispatch_batch(
        0, [forwarded[1], unrelated[1]], _descriptors(forwarded, unrelated)
    )
    assert supervisor.dispatched_packets == 1
    assert supervisor.suppressed_forwarded_duplicate_packets == 1
    assert supervisor.userspace_queue_drops == 1
    assert supervisor.worker_queue_slot_dropped_packets == 1
    assert supervisor.forwarded_duplicate_suppressor.entries == 0
    assert (
        supervisor.dispatched_packets
        + supervisor.suppressed_forwarded_duplicate_packets
        + supervisor.userspace_queue_drops
        == supervisor.captured_packets
    )


def test_prior_admitted_ingress_and_interleaved_local_auth(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    ingress, forwarded = _pair()
    local_auth = _frame(
        3,
        src_mac=LOCAL,
        dst_mac=GATEWAY,
        src_ip="192.168.1.10",
        dst_ip="203.0.113.20",
        payload=b"GET / HTTP/1.1\r\nAuthorization: Basic ZHVtbXk=\r\n\r\n",
    )
    supervisor.captured_packets = 3
    supervisor._dispatch_batch(0, [ingress[1]], _descriptors(ingress))
    supervisor._dispatch_batch(
        0,
        [local_auth[1], forwarded[1]],
        _descriptors(local_auth, forwarded),
    )
    admitted = []
    while not supervisor.worker_queues[0].empty():
        admitted.extend(supervisor.worker_queues[0].get_nowait()[0])
    assert [packet.packet_id for packet in admitted] == [1, 3]
    assert supervisor.dispatched_packets == 2
    assert supervisor.suppressed_forwarded_duplicate_packets == 1
    assert supervisor.userspace_queue_drops == 0


def test_low_pressure_pair_cannot_authorize_later_high_pressure_skip(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    supervisor.worker_queue_byte_counters[0].value = 0
    ingress, forwarded = _pair()
    supervisor.captured_packets = 3
    supervisor._dispatch_batch(
        0, [ingress[1], forwarded[1]], _descriptors(ingress, forwarded)
    )
    assert supervisor.dispatched_packets == 2
    assert supervisor.forwarded_duplicate_suppressor.entries == 0
    supervisor.worker_queue_byte_counters[0].value = 8 * 1024 * 1024
    repeated = _frame(3, src_mac=LOCAL, dst_mac=GATEWAY, hop=63)
    supervisor._dispatch_batch(0, [repeated[1]], _descriptors(repeated))
    assert supervisor.dispatched_packets == 3
    assert supervisor.suppressed_forwarded_duplicate_packets == 0


def test_low_pressure_egress_consumes_prior_admitted_ingress(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    supervisor.worker_queue_byte_counters[0].value = 0
    ingress, forwarded = _pair()
    supervisor._dispatch_batch(0, [ingress[1]], _descriptors(ingress))
    assert supervisor.forwarded_duplicate_suppressor.entries == 1
    supervisor._dispatch_batch(0, [forwarded[1]], _descriptors(forwarded))
    assert supervisor.dispatched_packets == 2
    assert supervisor.forwarded_duplicate_suppressor.entries == 0
    assert supervisor.suppressed_forwarded_duplicate_packets == 0


def test_failed_low_pressure_egress_cannot_reuse_prior_pair(tmp_path: Path) -> None:
    class FullQueue:
        def put_nowait(self, _item):
            raise queue.Full

    supervisor = _supervisor(tmp_path)
    supervisor.worker_queue_byte_counters[0].value = 0
    ingress, forwarded = _pair()
    supervisor._dispatch_batch(0, [ingress[1]], _descriptors(ingress))
    supervisor.worker_queues[0] = FullQueue()
    supervisor._dispatch_batch(0, [forwarded[1]], _descriptors(forwarded))
    assert supervisor.userspace_queue_drops == 1
    assert supervisor.suppressed_forwarded_duplicate_packets == 0
    assert supervisor.forwarded_duplicate_suppressor.entries == 0
    repeated = _frame(3, src_mac=LOCAL, dst_mac=GATEWAY, hop=63)
    supervisor.worker_queues[0] = queue.Queue()
    supervisor.worker_queue_byte_counters[0].value = 8 * 1024 * 1024
    supervisor._dispatch_batch(0, [repeated[1]], _descriptors(repeated))
    assert supervisor.dispatched_packets == 2
    assert supervisor.suppressed_forwarded_duplicate_packets == 0


def test_uncertain_frames_fail_open(tmp_path: Path) -> None:
    supervisor = _supervisor(tmp_path)
    ingress, forwarded = _pair()
    wrong_hop = _frame(3, src_mac=LOCAL, dst_mac=GATEWAY, hop=62)
    changed_body = _frame(
        4, src_mac=LOCAL, dst_mac=GATEWAY, hop=63,
        payload=b"GET /other HTTP/1.1\r\n\r\n",
    )
    truncated = _frame(5, src_mac=LOCAL, dst_mac=GATEWAY, hop=63, wire_extra=10)
    frames = _descriptors(ingress, forwarded, wrong_hop, changed_body, truncated)
    assert 5 not in frames
    supervisor.captured_packets = 4
    supervisor._dispatch_batch(
        0,
        [ingress[1], wrong_hop[1], changed_body[1], truncated[1]],
        frames,
    )
    assert supervisor.dispatched_packets == 4
    assert supervisor.suppressed_forwarded_duplicate_packets == 0


def test_duplicate_cache_is_bounded_and_releases_expired_entries() -> None:
    suppressor = ForwardedDuplicateSuppressor(
        LOCAL, max_bytes=250, max_entries=2, max_age_seconds=0.01
    )
    for index in range(1, 5):
        captured, parsed = _frame(
            index, src_mac=VICTIM, dst_mac=LOCAL, ip_id=index
        )
        frame = describe_forwarded_frame(captured, parsed, LOCAL)
        assert frame is not None
        plan = suppressor.plan([parsed], {index: frame}, pressure=False)
        suppressor.commit(plan)
        assert suppressor.entries <= 2
        assert suppressor.key_bytes <= 250
    assert suppressor.evicted >= 2
    # Control time explicitly; an expired ingress must never authorize a skip.
    suppressor._next_expire_ns = 0
    for ids in suppressor._accepted.values():
        for offset, (packet_id, _when, checksum) in enumerate(ids):
            ids[offset] = (packet_id, -100_000_000, checksum)
    captured, parsed = _frame(5, src_mac=LOCAL, dst_mac=GATEWAY, hop=63, ip_id=4)
    frame = describe_forwarded_frame(captured, parsed, LOCAL)
    assert frame is not None
    plan = suppressor.plan([parsed], {5: frame}, pressure=True)
    assert [packet.packet_id for packet in plan.retained] == [5]
    assert not plan.pairs
    assert suppressor.entries == 0
