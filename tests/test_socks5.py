"""RFC 1928/1929 username/password subnegotiation qualification."""

import json

import pytest

from packet_audit.config import AuditConfig
from packet_audit.detectors import SensitiveDetector
from packet_audit.models import ProvenanceSpan
from packet_audit.socks5 import display_value, parse_socks5_auth
from packet_audit.supervisor import AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_tcp, write_pcap
from tests.test_detectors import by_type, chunk, flow
from tests.test_protocol_coverage import feed


GREETING = b"\x05\x02\x00\x02"
SELECT_PASSWORD = b"\x05\x02"
AUTH = b"\x01\x0esynthetic-user\x12synthetic-password"


def _exchange(*, width: int = 1, target=None, client_direction: int = 0):
    detector = SensitiveDetector("synthetic-socks5")
    target = target or flow(dport=1080)
    greeting_findings, packet_id = feed(
        detector, GREETING, target, direction=client_direction, width=width,
    )
    selection_findings, packet_id = feed(
        detector, SELECT_PASSWORD, target, direction=1 - client_direction,
        width=width, packet_id=packet_id,
    )
    auth_findings, packet_id = feed(
        detector, AUTH, target, direction=client_direction,
        offset=len(GREETING), width=width, packet_id=packet_id,
    )
    return detector, greeting_findings + selection_findings + auth_findings, packet_id


@pytest.mark.parametrize("width", [1, 3, 4096])
def test_socks5_selected_username_password_segmented(width):
    detector, findings, packet_id = _exchange(width=width)
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].confidence == "confirmed"
    assert found[0].material == {
        "username": "synthetic-user", "password": "synthetic-password",
        "method": "username_password",
    }
    assert found[0].direction == 0
    assert found[0].packet_ids_complete
    assert found[0].packet_ids
    assert found[0].stream_offset == len(GREETING) + 2
    assert detector.stats()["parser_errors"] == 0
    # A retransmitted view of the same bytes cannot create a second attempt.
    assert not by_type(detector.process_stream(chunk(
        AUTH, target_flow=flow(dport=1080), offset=len(GREETING), packet_id=packet_id,
    )), "socks5_credentials")


def test_socks5_canonical_reverse_direction_keeps_client_provenance():
    _detector, findings, _ = _exchange(
        target=flow(sport=1080, dport=40000), client_direction=1, width=2,
    )
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].direction == 1
    assert found[0].packet_ids_complete


def test_socks5_late_observed_server_selection_uses_client_packet_ids():
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    early, next_packet = feed(detector, GREETING + AUTH, target,
                              packet_id=10, width=4096)
    assert not by_type(early, "socks5_credentials")
    late, _ = feed(detector, SELECT_PASSWORD, target, direction=1,
                   packet_id=next_packet, width=4096)
    found = by_type(late, "socks5_credentials")
    assert len(found) == 1
    assert found[0].material["password"] == "synthetic-password"
    assert found[0].packet_ids == (10,)
    assert found[0].direction == 0
    assert found[0].packet_ids_complete


def test_socks5_late_selection_preserves_ambiguous_client_provenance():
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    payload = GREETING + AUTH
    detector.process_stream(chunk(
        payload, target_flow=target, packet_id=10,
        provenance_spans=(ProvenanceSpan(0, len(payload), (10,), False),),
    ))
    findings = detector.process_stream(chunk(
        SELECT_PASSWORD, target_flow=target, direction=1, packet_id=11,
    ))
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].packet_ids == (10,)
    assert found[0].packet_ids_complete is False
    assert any("provenance" in value.lower() for value in found[0].limitations)


def test_socks5_capped_client_provenance_is_not_reported_complete():
    detector = SensitiveDetector(
        "synthetic-socks5", max_provenance_spans=64,
        max_provenance_packet_id_refs=64,
    )
    target = flow(dport=1080)
    auth = b"\x01\x50" + b"u" * 80 + b"\x50" + b"p" * 80
    _, packet_id = feed(detector, GREETING + auth, target,
                        width=1, packet_id=100)
    findings, _ = feed(detector, SELECT_PASSWORD, target,
                       direction=1, width=1, packet_id=packet_id)
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].packet_ids_complete is False
    assert detector.stats()["provenance_cap_trimmed_spans"] > 0


@pytest.mark.parametrize("server_selection", [b"", b"\x05\x00", b"\x05\xff", b"\x04\x02"])
def test_socks5_requires_server_selection_of_offered_password_method(server_selection):
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    feed(detector, GREETING, target)
    if server_selection:
        feed(detector, server_selection, target, direction=1)
    findings, _ = feed(detector, AUTH, target, offset=len(GREETING))
    assert not by_type(findings, "socks5_credentials")


@pytest.mark.parametrize("client", [
    b"\x05\x01\x00" + AUTH,  # Username/password was not offered.
    b"\x05\x02\x00\x02\x01\x00\x01x",  # Zero-length username.
    b"\x05\x02\x00\x02\x01\x01x\x00",  # Zero-length password.
    b"\x05\x02\x00\x02\x01\x01x\x02y",  # Incomplete password.
    b"\x05\x02\x00\x02\x00\x01x\x01y",  # Wrong auth version.
    b"\x05\x02\x00\x02\x05\x01x\x01y",  # SOCKS request, not auth.
])
def test_socks5_rejects_malformed_or_incomplete_auth(client):
    assert parse_socks5_auth(client, SELECT_PASSWORD) is None


def test_socks5_does_not_search_inside_tunneled_payload():
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    feed(detector, b"X" * 30, target)
    feed(detector, SELECT_PASSWORD, target, direction=1)
    findings, _ = feed(detector, GREETING + AUTH, target, offset=30)
    assert not by_type(findings, "socks5_credentials")


def test_socks5_binary_credentials_are_preserved_losslessly():
    auth = b"\x01\x01\xff\x02\x00\xfe"
    parsed = parse_socks5_auth(GREETING + auth, SELECT_PASSWORD)
    assert parsed is not None
    assert parsed.username == b"\xff"
    assert parsed.password == b"\x00\xfe"
    assert display_value(parsed.username) == b"\xff"
    assert display_value(parsed.password) == b"\x00\xfe"
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    feed(detector, GREETING, target)
    feed(detector, SELECT_PASSWORD, target, direction=1)
    findings, _ = feed(detector, auth, target, offset=len(GREETING))
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].material["username"] == b"\xff"
    assert found[0].material["password"] == b"\x00\xfe"


def test_socks5_maximum_rfc_lengths_survive_bounded_segmented_lookback():
    greeting = b"\x05\xff" + b"\x00" * 254 + b"\x02"
    auth = b"\x01\xff" + b"u" * 255 + b"\xff" + b"p" * 255
    assert len(greeting + auth) == 770
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=1080)
    _, packet_id = feed(detector, greeting, target, width=1)
    _, packet_id = feed(detector, SELECT_PASSWORD, target, direction=1,
                        packet_id=packet_id, width=1)
    findings, _ = feed(detector, auth, target, offset=len(greeting),
                       packet_id=packet_id, width=1)
    found = by_type(findings, "socks5_credentials")
    assert len(found) == 1
    assert found[0].material["username"] == "u" * 255
    assert found[0].material["password"] == "p" * 255
    assert found[0].packet_ids_complete


def test_socks5_nonstandard_port_is_explicitly_unqualified():
    detector = SensitiveDetector("synthetic-socks5")
    target = flow(dport=2080)
    feed(detector, GREETING, target)
    feed(detector, SELECT_PASSWORD, target, direction=1)
    findings, _ = feed(detector, AUTH, target, offset=len(GREETING))
    assert not by_type(findings, "socks5_credentials")


def test_socks5_offline_packet_to_export(tmp_path):
    client_port = 45678
    packets = [
        ethernet_ipv4_tcp(b"", seq=1000, sport=client_port, dport=1080, flags=0x02),
        ethernet_ipv4_tcp(
            b"", seq=5000, src="10.0.0.20", dst="10.0.0.10",
            sport=1080, dport=client_port, flags=0x12,
        ),
        ethernet_ipv4_tcp(GREETING, seq=1001, sport=client_port, dport=1080),
        ethernet_ipv4_tcp(
            SELECT_PASSWORD, seq=5001, src="10.0.0.20", dst="10.0.0.10",
            sport=1080, dport=client_port,
        ),
    ]
    for offset in range(0, len(AUTH), 3):
        packets.append(ethernet_ipv4_tcp(
            AUTH[offset:offset + 3], seq=1001 + len(GREETING) + offset,
            sport=client_port, dport=1080,
        ))
    capture = tmp_path / "synthetic-socks5.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline", workers=2, queue_size=256, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl", heartbeat_seconds=1,
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    records = [json.loads(line) for line in config.output_jsonl.read_text().splitlines()]
    found = [record for record in records if record["material_type"] == "socks5_credentials"]
    assert len(found) == 1
    assert found[0]["material"]["username"] == "synthetic-user"
    assert found[0]["material"]["password"] == "synthetic-password"
    assert found[0]["source_ip"] == "10.0.0.10"
    assert found[0]["source_port"] == client_port
    assert found[0]["destination_ip"] == "10.0.0.20"
    assert found[0]["destination_port"] == 1080
    assert found[0]["packet_ids_complete"] is True
