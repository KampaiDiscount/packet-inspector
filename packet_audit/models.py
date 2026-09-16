"""Shared immutable records passed between capture, workers, and exporters."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import ipaddress
from typing import Any, Literal


Completeness = Literal[
    "complete",
    "midstream",
    "gapped",
    "truncated",
    "encrypted",
    "parser_error",
    "potential",
]


@dataclass(frozen=True, slots=True)
class Endpoint:
    address: str
    port: int = 0

    def sort_key(self) -> tuple[str, int]:
        return self.address, self.port


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Canonical bidirectional flow identity with capture context."""

    protocol: int
    endpoint_a: Endpoint
    endpoint_b: Endpoint
    interface: str
    vlan_ids: tuple[int, ...] = ()

    @classmethod
    def canonical(
        cls,
        *,
        protocol: int,
        src: str,
        sport: int,
        dst: str,
        dport: int,
        interface: str,
        vlan_ids: tuple[int, ...] = (),
    ) -> tuple["FlowKey", int]:
        left = Endpoint(src, sport)
        right = Endpoint(dst, dport)
        if left.sort_key() <= right.sort_key():
            return cls(protocol, left, right, interface, vlan_ids), 0
        return cls(protocol, right, left, interface, vlan_ids), 1

    def stable_text(self) -> str:
        vlans = ",".join(str(v) for v in self.vlan_ids) or "-"
        return (
            f"{self.interface}|{vlans}|{self.protocol}|"
            f"{self.endpoint_a.address}:{self.endpoint_a.port}|"
            f"{self.endpoint_b.address}:{self.endpoint_b.port}"
        )


@dataclass(slots=True)
class CapturedPacket:
    session_id: str
    packet_id: int
    timestamp_ns: int
    interface: str
    datalink: int
    captured_length: int
    wire_length: int
    raw: bytes


@dataclass(slots=True)
class ParsedPacket:
    session_id: str
    packet_id: int
    timestamp_ns: int
    interface: str
    captured_length: int
    wire_length: int
    ip_version: int
    src: str
    dst: str
    protocol: int
    vlan_ids: tuple[int, ...]
    network_payload: bytes
    truncated: bool = False
    fragment_id: int | None = None
    fragment_offset: int = 0
    more_fragments: bool = False
    transport_parsed: bool = False
    sport: int = 0
    dport: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 0
    transport_payload: bytes = b""
    # Empty for a directly captured packet. Reassembled datagrams retain every
    # captured packet that contributed first-seen bytes so exported findings
    # can be traced back across all fragments.
    source_packet_ids: tuple[int, ...] = ()

    def flow(self) -> tuple[FlowKey, int]:
        return FlowKey.canonical(
            protocol=self.protocol,
            src=self.src,
            sport=self.sport,
            dst=self.dst,
            dport=self.dport,
            interface=self.interface,
            vlan_ids=self.vlan_ids,
        )


@dataclass(frozen=True, slots=True)
class ProvenanceSpan:
    """Captured-packet provenance for one absolute stream-offset interval."""

    stream_start: int
    stream_end: int
    packet_ids: tuple[int, ...]
    packet_ids_complete: bool = True


@dataclass(slots=True)
class StreamChunk:
    flow: FlowKey
    direction: int
    stream_offset: int
    data: bytes
    packet_ids: tuple[int, ...]
    first_timestamp_ns: int
    last_timestamp_ns: int
    connection_epoch: int = 0
    completeness: Completeness = "complete"
    provenance_spans: tuple[ProvenanceSpan, ...] = ()


@dataclass(slots=True)
class Finding:
    event_id: str
    session_id: str
    observed_timestamp_ns: int
    emitted_timestamp_ns: int
    category: str
    protocol: str
    detector: str
    material_type: str
    material: Any
    confidence: Literal["confirmed", "high", "medium", "low"]
    completeness: Completeness
    flow_id: str
    direction: int | None
    packet_ids: tuple[int, ...]
    stream_offset: int | None
    attempt_ordinal: int
    fields: dict[str, Any] = field(default_factory=dict)
    limitations: list[str] = field(default_factory=list)
    connection_epoch: int | None = None
    packet_ids_complete: bool = True

    def to_dict(self) -> dict[str, Any]:
        record = asdict(self)
        source, destination = finding_endpoints(self.flow_id, self.direction)
        record.update(
            source=asdict(source) if source else None,
            destination=asdict(destination) if destination else None,
            source_ip=source.address if source else None,
            source_port=source.port if source else None,
            destination_ip=destination.address if destination else None,
            destination_port=destination.port if destination else None,
        )
        return record


def finding_endpoints(
    flow_id: str, direction: int | None
) -> tuple[Endpoint | None, Endpoint | None]:
    """Resolve directional endpoints without confusing canonical order with source.

    Existing exports remain readable: their flow ID contains both endpoints,
    optionally followed by a connection epoch. Unknown direction is not guessed.
    IPv6 addresses are split at the final colon (the port separator).
    """
    if direction not in (0, 1):
        return None, None
    pieces = flow_id.split("|")
    if len(pieces) < 5:
        return None, None
    endpoints = []
    try:
        for value in pieces[3:5]:
            address, port_text = value.rsplit(":", 1)
            address = address.removeprefix("[").removesuffix("]")
            ipaddress.ip_address(address)
            port = int(port_text)
            if not 0 <= port <= 65535:
                return None, None
            endpoints.append(Endpoint(address, port))
    except (ValueError, TypeError):
        return None, None
    return (endpoints[0], endpoints[1]) if direction == 0 else (endpoints[1], endpoints[0])


@dataclass(slots=True)
class WorkerHeartbeat:
    worker_id: int
    timestamp_ns: int
    packets: int
    bytes_seen: int
    active_flows: int
    reassembly_bytes: int
    findings: int
    parser_errors: int
    queue_depth: int | None


@dataclass(slots=True)
class CaptureHeartbeat:
    timestamp_ns: int
    captured_packets: int
    dispatched_packets: int
    userspace_queue_drops: int
    libpcap_received: int | None
    libpcap_dropped: int | None
    interface_dropped: int | None
    last_packet_age_seconds: float | None


STOP_SENTINEL = ("__PACKET_AUDIT_STOP__",)
