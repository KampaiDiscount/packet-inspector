"""Conservative, bounded matching of an admitted ingress to its forwarded copy.

This is an analysis-queue optimization, not a capture filter.  The independent
raw ring still records both frames.  A match requires Ethernet direction at
the local interface and the complete same IP datagram.  A kernel-forwarded
copy may decrement the hop count and update the IPv4 checksum; a raw L3
forwarder can retain both exactly.  Ambiguous,
truncated, fragmented, unsupported, or unmatched frames pass through.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from dataclasses import dataclass
from pathlib import Path
import re

from .models import CapturedPacket, ParsedPacket
from .packets import DLT_EN10MB, ETHERTYPE_IPV4, ETHERTYPE_IPV6, VLAN_ETHERTYPES


MAX_MATCH_BYTES = 16 * 1024 * 1024
MAX_MATCH_ENTRIES = 16_384
MAX_MATCH_AGE_SECONDS = 2.0
MAX_INGRESS_COPIES_PER_KEY = 8


def read_interface_mac(interface: str) -> bytes | None:
    """Return a Linux interface MAC, or disable the optimization safely."""

    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", interface):
        return None
    try:
        value = (Path("/sys/class/net") / interface / "address").read_text().strip()
        mac = bytes.fromhex(value.replace(":", ""))
    except (OSError, ValueError):
        return None
    return mac if len(mac) == 6 and mac != b"\x00" * 6 else None


@dataclass(frozen=True, slots=True)
class ForwardedFrame:
    role: str  # "ingress" or "egress" relative to the local MAC
    key: bytes  # complete VLAN/IP datagram with only hop count/checksum erased
    hop_limit: int
    packet_id: int
    timestamp_ns: int
    ip_checksum: int | None


def describe_forwarded_frame(
    captured: CapturedPacket, parsed: ParsedPacket, local_mac: bytes
) -> ForwardedFrame | None:
    """Describe only complete, unfragmented Ethernet TCP/UDP IP datagrams."""

    if (
        captured.datalink != DLT_EN10MB
        or captured.captured_length != captured.wire_length
        or parsed.truncated
        or not parsed.transport_parsed
        or parsed.fragment_id is not None
        or parsed.protocol not in (6, 17)
        or len(local_mac) != 6
    ):
        return None
    raw = captured.raw
    if len(raw) < 14:
        return None
    dst_mac, src_mac = raw[:6], raw[6:12]
    if dst_mac == local_mac and src_mac != local_mac:
        role = "ingress"
    elif src_mac == local_mac and dst_mac != local_mac and not dst_mac[0] & 1:
        role = "egress"
    else:
        return None

    offset = 12
    ethertype = int.from_bytes(raw[offset : offset + 2], "big")
    offset += 2
    tags = 0
    while ethertype in VLAN_ETHERTYPES:
        if tags >= 8 or len(raw) < offset + 4:
            return None
        offset += 2  # VLAN tag control information
        ethertype = int.from_bytes(raw[offset : offset + 2], "big")
        offset += 2
        tags += 1
    network = raw[offset:]
    if ethertype == ETHERTYPE_IPV4:
        if len(network) < 20 or network[0] >> 4 != 4:
            return None
        header_length = (network[0] & 15) * 4
        length = int.from_bytes(network[2:4], "big")
        if header_length < 20 or length < header_length or length > len(network):
            return None
        hop_limit = network[8]
        ip_checksum: int | None = int.from_bytes(network[10:12], "big")
        if hop_limit < 1:
            return None
        normalized = bytearray(network[:length])
        normalized[8] = 0
        normalized[10:12] = b"\x00\x00"
    elif ethertype == ETHERTYPE_IPV6:
        if len(network) < 40 or network[0] >> 4 != 6:
            return None
        payload_length = int.from_bytes(network[4:6], "big")
        # A zero length may be a jumbogram; its end is not provable here.
        if not payload_length or 40 + payload_length > len(network):
            return None
        hop_limit = network[7]
        ip_checksum = None
        if hop_limit < 1:
            return None
        normalized = bytearray(network[: 40 + payload_length])
        normalized[7] = 0
    else:
        return None

    # Keep the complete VLAN encapsulation (including TCI), EtherType and IP
    # datagram.  Ethernet padding may differ and is outside the IP datagram.
    key = raw[12:offset] + bytes(normalized)
    return ForwardedFrame(
        role, key, hop_limit, captured.packet_id, captured.timestamp_ns, ip_checksum
    )


def _checksum_matches(
    ingress: int | None, egress: int | None, *, decremented: bool
) -> bool:
    if ingress is None or egress is None:
        return ingress is None and egress is None
    if not decremented:
        return ingress == egress
    # Decrementing the IPv4 TTL by one subtracts 0x0100 from a header word,
    # hence adds 0x0100 to the one's-complement header checksum.
    total = ingress + 0x0100
    total = (total & 0xFFFF) + (total >> 16)
    return total == egress


@dataclass(slots=True)
class DuplicatePlan:
    retained: list[ParsedPacket]
    pairs: list[tuple[int, int]]  # (forwarded packet ID, admitted ingress ID)
    prior_pairs: list[tuple[int, int]]
    accepted_uses: dict[tuple[bytes, int], int]
    ingress: dict[tuple[bytes, int], deque[tuple[int, int, int | None]]]
    pressure: bool


class ForwardedDuplicateSuppressor:
    """One-to-one matches committed only after the retained batch is admitted."""

    def __init__(
        self,
        local_mac: bytes,
        *,
        max_bytes: int = MAX_MATCH_BYTES,
        max_entries: int = MAX_MATCH_ENTRIES,
        max_age_seconds: float = MAX_MATCH_AGE_SECONDS,
    ) -> None:
        if len(local_mac) != 6 or max_bytes <= 0 or max_entries <= 0 or max_age_seconds <= 0:
            raise ValueError("invalid forwarded duplicate suppression bounds")
        self.local_mac = local_mac
        self.max_bytes = max_bytes
        self.max_entries = max_entries
        self.max_age_seconds = max_age_seconds
        self._accepted: OrderedDict[
            tuple[bytes, int], deque[tuple[int, int, int | None]]
        ] = OrderedDict()
        self._key_bytes = 0
        self._next_expire_ns = 0
        self.expired = 0
        self.evicted = 0

    @property
    def entries(self) -> int:
        return len(self._accepted)

    @property
    def key_bytes(self) -> int:
        return self._key_bytes

    def _remove(self, key: tuple[bytes, int]) -> None:
        self._accepted.pop(key)
        self._key_bytes -= len(key[0])

    def _expire(self, now_ns: int) -> None:
        if now_ns < self._next_expire_ns:
            return
        age_ns = int(self.max_age_seconds * 1_000_000_000)
        self._next_expire_ns = now_ns + min(250_000_000, age_ns // 4)
        # LRU order follows insertion/reuse.  Expire every stale entry even if
        # another key was refreshed in between; the table is finitely bounded.
        for key, ids in tuple(self._accepted.items()):
            while ids and now_ns - ids[0][1] > age_ns:
                ids.popleft()
                self.expired += 1
            if not ids:
                self._remove(key)

    def plan(
        self,
        packets: list[ParsedPacket],
        frames: dict[int, ForwardedFrame],
        *,
        pressure: bool,
    ) -> DuplicatePlan:
        if packets:
            self._expire(max(packet.timestamp_ns for packet in packets))
        max_age_ns = int(self.max_age_seconds * 1_000_000_000)
        retained: list[ParsedPacket] = []
        pairs: list[tuple[int, int]] = []
        prior_pairs: list[tuple[int, int]] = []
        accepted_uses: dict[tuple[bytes, int], int] = {}
        ingress: dict[
            tuple[bytes, int], deque[tuple[int, int, int | None]]
        ] = {}
        for packet in packets:
            frame = frames.get(packet.packet_id)
            if frame is None:
                retained.append(packet)
                continue
            if frame.role == "ingress":
                ingress.setdefault((frame.key, frame.hop_limit), deque()).append(
                    (packet.packet_id, frame.timestamp_ns, frame.ip_checksum)
                )
                retained.append(packet)
                continue
            matched = False
            for ingress_hop, decremented in (
                (frame.hop_limit + 1, True),
                (frame.hop_limit, False),
            ):
                key = (frame.key, ingress_hop)
                local = ingress.get(key)
                if (
                    local
                    and 0 <= frame.timestamp_ns - local[0][1] <= max_age_ns
                    and _checksum_matches(
                        local[0][2], frame.ip_checksum, decremented=decremented
                    )
                ):
                    ingress_id = local.popleft()[0]
                    if pressure:
                        pairs.append((packet.packet_id, ingress_id))
                    else:
                        # It was analyzed normally.  Consume the pairing so a
                        # later retransmission cannot use this ingress again.
                        retained.append(packet)
                    matched = True
                    break
                admitted = self._accepted.get(key)
                used = accepted_uses.get(key, 0)
                if (
                    admitted
                    and used < len(admitted)
                    and 0 <= frame.timestamp_ns - admitted[used][1] <= max_age_ns
                    and _checksum_matches(
                        admitted[used][2], frame.ip_checksum, decremented=decremented
                    )
                ):
                    accepted_uses[key] = used + 1
                    if pressure:
                        pair = (packet.packet_id, admitted[used][0])
                        pairs.append(pair)
                        prior_pairs.append(pair)
                    else:
                        retained.append(packet)
                    matched = True
                    break
            if not matched:
                retained.append(packet)
        return DuplicatePlan(retained, pairs, prior_pairs, accepted_uses, ingress, pressure)

    def commit_prior_skips_on_failure(self, plan: DuplicatePlan) -> None:
        """Account only copies of ingress already admitted in an earlier batch.

        Same-batch ingress was rejected with the queue batch, so its candidate
        forwarded copy is a real drop.  A low-pressure egress was retained and
        is also a real drop if this batch failed.
        """

        for key, count in plan.accepted_uses.items():
            ids = self._accepted.get(key)
            if ids is None or len(ids) < count:
                raise RuntimeError("forwarded duplicate cache changed before failure accounting")
            for _ in range(count):
                ids.popleft()
            if ids:
                self._accepted.move_to_end(key)
            else:
                self._remove(key)

    def commit(self, plan: DuplicatePlan) -> None:
        """Commit matches only after all retained packets were queue-admitted."""

        for key, count in plan.accepted_uses.items():
            ids = self._accepted.get(key)
            if ids is None or len(ids) < count:
                raise RuntimeError("forwarded duplicate cache changed before commit")
            for _ in range(count):
                ids.popleft()
            if ids:
                self._accepted.move_to_end(key)
            else:
                self._remove(key)
        for key, packet_ids in plan.ingress.items():
            if not packet_ids or len(key[0]) > self.max_bytes:
                continue
            ids = self._accepted.get(key)
            if ids is None:
                ids = deque()
                self._accepted[key] = ids
                self._key_bytes += len(key[0])
            else:
                self._accepted.move_to_end(key)
            ids.extend(packet_ids)
            while len(ids) > MAX_INGRESS_COPIES_PER_KEY:
                ids.popleft()
                self.evicted += 1
        while len(self._accepted) > self.max_entries or self._key_bytes > self.max_bytes:
            oldest = next(iter(self._accepted))
            self.evicted += len(self._accepted[oldest])
            self._remove(oldest)
