"""MQTT 3.1.1/5.0 CONNECT credential qualification with synthetic data."""

import json

import pytest

from packet_audit.config import AuditConfig
from packet_audit.detectors import SensitiveDetector
from packet_audit.mqtt import (
    MAX_CONNECT_BYTES, MQTTConnectLimit, MalformedMQTT, parse_mqtt_connect,
)
from packet_audit.models import ProvenanceSpan
from packet_audit.supervisor import AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_tcp, write_pcap
from tests.test_detectors import by_type, chunk, flow
from tests.test_protocol_coverage import feed


def field(value: bytes) -> bytes:
    return len(value).to_bytes(2, "big") + value


def varint(value: int) -> bytes:
    encoded = bytearray()
    while True:
        octet = value % 128
        value //= 128
        encoded.append(octet | (0x80 if value else 0))
        if not value:
            return bytes(encoded)


def connect(
    *, version: int = 4, username: bytes | None = b"synthetic-user",
    password: bytes | None = b"synthetic-password", client_id: bytes = b"synthetic-id",
    properties: bytes = b"", will: bool = False, will_properties: bytes = b"",
    flags_override: int | None = None,
) -> bytes:
    flags = (0x80 if username is not None else 0) | (
        0x40 if password is not None else 0
    ) | (0x04 if will else 0) | 0x02
    if flags_override is not None:
        flags = flags_override
    body = b"\x00\x04MQTT" + bytes([version, flags]) + b"\x00\x3c"
    if version == 5:
        body += varint(len(properties)) + properties
    body += field(client_id)
    if will:
        if version == 5:
            body += varint(len(will_properties)) + will_properties
        body += field(b"will/topic") + field(b"binary-will-data")
    if username is not None:
        body += field(username)
    if password is not None:
        body += field(password)
    return b"\x10" + varint(len(body)) + body


@pytest.mark.parametrize("version", [4, 5])
@pytest.mark.parametrize("width", [1, 7, 4096])
def test_mqtt_connect_segmented_valid_versions(version, width):
    detector = SensitiveDetector("synthetic-mqtt")
    payload = connect(version=version)
    findings, next_packet = feed(detector, payload, flow(dport=1883), width=width)
    found = by_type(findings, "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].confidence == "confirmed"
    assert found[0].material == {
        "mqtt_version": "3.1.1" if version == 4 else "5.0",
        "client_id": "synthetic-id", "username": "synthetic-user",
        "password": "synthetic-password",
    }
    assert found[0].packet_ids_complete
    assert found[0].stream_offset == payload.index(field(b"synthetic-user"))
    assert detector.stats()["parser_errors"] == 0
    assert not by_type(detector.process_stream(chunk(
        payload, target_flow=flow(dport=1883), packet_id=next_packet,
    )), "mqtt_connect_credentials")


def test_mqtt_5_connect_and_will_properties_are_walked_before_credentials():
    properties = (
        b"\x11\x00\x00\x00\x3c"  # Session expiry.
        + b"\x26" + field(b"name") + field(b"value")
        + b"\x15" + field(b"token")
        + b"\x16" + field(b"opaque-auth-data")
    )
    will_properties = (
        b"\x18\x00\x00\x00\x01"
        + b"\x26" + field(b"will-key") + field(b"will-value")
    )
    payload = connect(
        version=5, properties=properties, will=True,
        will_properties=will_properties,
    )
    parsed = parse_mqtt_connect(payload)
    assert parsed is not None
    assert parsed.version == 5
    assert parsed.username == "synthetic-user"
    assert parsed.password == b"synthetic-password"
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, payload, flow(dport=1883), width=3)
    found = by_type(findings, "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].stream_offset == payload.index(field(b"synthetic-user"))
    assert found[0].packet_ids_complete
    auth_data = by_type(findings, "mqtt_connect_authentication_data")
    assert len(auth_data) == 1
    assert auth_data[0].confidence == "medium"
    assert auth_data[0].material["authentication_method"] == "token"
    assert auth_data[0].material["authentication_data"] == "opaque-auth-data"


def test_mqtt_5_method_defined_auth_data_without_password_is_candidate():
    properties = (
        b"\x15" + field(b"SCRAM-SHA-256")
        + b"\x16" + field(b"client-first-nonce")
    )
    payload = connect(version=5, username=None, password=None,
                      properties=properties)
    parsed = parse_mqtt_connect(payload)
    assert parsed is not None
    assert parsed.authentication_method == "SCRAM-SHA-256"
    assert parsed.authentication_data == b"client-first-nonce"
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, payload, flow(dport=1883), width=1)
    assert not by_type(findings, "mqtt_connect_credentials")
    candidate = by_type(findings, "mqtt_connect_authentication_data")
    assert len(candidate) == 1
    assert candidate[0].confidence == "medium"
    assert candidate[0].material["authentication_data"] == "client-first-nonce"
    assert candidate[0].packet_ids_complete
    assert any("may be a public nonce" in note for note in candidate[0].limitations)


def test_mqtt_5_auth_data_and_method_provenance_follow_wire_order():
    method = b"SYNTHETIC-METHOD"
    data = b"\x00\xff"
    properties = b"\x16" + field(data) + b"\x15" + field(method)
    payload = connect(version=5, username=None, password=None,
                      properties=properties)
    data_start = payload.index(b"\x16" + field(data))
    method_start = payload.index(b"\x15" + field(method))
    assert data_start < method_start
    detector = SensitiveDetector("synthetic-mqtt")
    target = flow(dport=1883)
    for packet_id, (start, end) in enumerate((
        (0, data_start), (data_start, method_start),
        (method_start, method_start + 3 + len(method)),
        (method_start + 3 + len(method), len(payload)),
    ), start=1):
        findings = detector.process_stream(chunk(
            payload[start:end], target_flow=target, offset=start,
            packet_id=packet_id,
        ))
        if packet_id < 4:
            assert not by_type(findings, "mqtt_connect_authentication_data")
    candidate = by_type(findings, "mqtt_connect_authentication_data")
    assert len(candidate) == 1
    assert candidate[0].material["authentication_data"] == data
    assert candidate[0].packet_ids == (2, 3)
    assert candidate[0].stream_offset == data_start
    assert candidate[0].packet_ids_complete


def test_mqtt_empty_auth_data_property_does_not_claim_material():
    properties = b"\x15" + field(b"method") + b"\x16" + field(b"")
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, connect(version=5, username=None,
                                         password=None, properties=properties),
                       flow(dport=1883))
    assert not by_type(findings, "mqtt_connect_authentication_data")


def test_mqtt_auth_method_ambiguous_provenance_marks_candidate_incomplete():
    properties = b"\x15" + field(b"method") + b"\x16" + field(b"data")
    payload = connect(version=5, username=None, password=None,
                      properties=properties)
    parsed = parse_mqtt_connect(payload)
    assert parsed is not None
    assert parsed.authentication_method_span is not None
    assert parsed.authentication_data_span is not None
    method_start, method_end = parsed.authentication_method_span
    data_start, data_end = parsed.authentication_data_span
    spans = (
        ProvenanceSpan(0, method_start, (1,), True),
        ProvenanceSpan(method_start, method_end, (2,), False),
        ProvenanceSpan(method_end, data_start, (1,), True),
        ProvenanceSpan(data_start, data_end, (3,), True),
        ProvenanceSpan(data_end, len(payload), (1,), True),
    )
    detector = SensitiveDetector("synthetic-mqtt")
    found = by_type(detector.process_stream(chunk(
        payload, target_flow=flow(dport=1883), provenance_spans=spans,
    )), "mqtt_connect_authentication_data")
    assert len(found) == 1
    assert found[0].packet_ids == (2, 3)
    assert found[0].packet_ids_complete is False


def test_mqtt_5_password_only_and_empty_binary_password_are_observed():
    for password in (b"\xff\x00\xfe", b""):
        detector = SensitiveDetector("synthetic-mqtt")
        payload = connect(version=5, username=None, password=password)
        findings, _ = feed(detector, payload, flow(dport=1883), width=1)
        found = by_type(findings, "mqtt_connect_credentials")
        assert len(found) == 1
        assert found[0].material["username"] is None
        assert found[0].material["password"] == (password if password else "")
        assert found[0].packet_ids_complete


def test_mqtt_311_password_without_username_is_rejected():
    with pytest.raises(MalformedMQTT):
        parse_mqtt_connect(connect(version=4, username=None))


@pytest.mark.parametrize("payload", [
    b"\x30" + connect()[1:],  # PUBLISH cannot be mistaken for CONNECT.
    connect().replace(b"\x00\x04MQTT", b"\x00\x04MPTT", 1),
    connect().replace(b"\x00\x04MQTT\x04", b"\x00\x04MQTT\x03", 1),
    connect(flags_override=0xC3),  # Reserved flag.
    connect(flags_override=0xF2),  # Will QoS and Retain without Will flag.
    connect(flags_override=0xDE),  # Invalid Will QoS 3.
    connect(username=b"bad\xff"),  # Invalid UTF-8 username.
    connect(client_id=b"bad\x00id"),  # Forbidden NUL in MQTT string.
    connect(version=5, properties=b"\xff"),  # Unknown property.
    connect(version=5, properties=b"\x11\x00"),  # Truncated property.
    connect(version=5, properties=b"\x11" + b"\x00" * 8),  # Duplicate property.
    connect(version=5, properties=b"\x16" + field(b"data")),  # Auth data without method.
    connect(version=5, properties=b"\x21\x00\x00"),  # Invalid Receive Maximum.
    connect(version=5, will=True, will_properties=b"\x18\x00"),
    b"\x10\x80\x00" + connect()[2:],  # Non-minimal remaining length.
])
def test_mqtt_rejects_malformed_initial_connect(payload):
    with pytest.raises(MalformedMQTT):
        parse_mqtt_connect(payload)
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, payload, flow(dport=1883), width=4096)
    assert not by_type(findings, "mqtt_connect_credentials")


def test_mqtt_incomplete_frame_waits_without_partial_findings():
    payload = connect(version=5)
    for split in range(1, len(payload)):
        detector = SensitiveDetector("synthetic-mqtt")
        target = flow(dport=1883)
        assert not by_type(detector.process_stream(chunk(
            payload[:split], target_flow=target,
        )), "mqtt_connect_credentials")
        found = by_type(detector.process_stream(chunk(
            payload[split:], target_flow=target, offset=split, packet_id=2,
        )), "mqtt_connect_credentials")
        assert len(found) == 1
        assert found[0].material["password"] == "synthetic-password"


def test_mqtt_credential_provenance_excludes_header_packet():
    payload = connect()
    username_start = payload.index(field(b"synthetic-user"))
    password_start = payload.index(field(b"synthetic-password"))
    detector = SensitiveDetector("synthetic-mqtt")
    target = flow(dport=1883)
    assert not detector.process_stream(chunk(
        payload[:username_start], target_flow=target, packet_id=1,
    ))
    assert not detector.process_stream(chunk(
        payload[username_start:password_start], target_flow=target,
        offset=username_start, packet_id=2,
    ))
    found = by_type(detector.process_stream(chunk(
        payload[password_start:], target_flow=target,
        offset=password_start, packet_id=3,
    )), "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].packet_ids == (2, 3)
    assert found[0].packet_ids_complete
    assert found[0].stream_offset == username_start


def test_mqtt_ambiguous_credential_span_marks_provenance_incomplete():
    payload = connect()
    username_start = payload.index(field(b"synthetic-user"))
    spans = (
        ProvenanceSpan(0, username_start, (1,), True),
        ProvenanceSpan(username_start, len(payload), (2,), False),
    )
    detector = SensitiveDetector("synthetic-mqtt")
    found = by_type(detector.process_stream(chunk(
        payload, target_flow=flow(dport=1883), packet_id=2,
        provenance_spans=spans,
    )), "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].packet_ids == (2,)
    assert found[0].packet_ids_complete is False


def test_mqtt_no_password_or_nested_connect_in_publish_is_not_reported():
    detector = SensitiveDetector("synthetic-mqtt")
    target = flow(dport=1883)
    first = connect(version=5, username=b"only-user", password=None)
    findings, packet_id = feed(detector, first, target)
    assert not by_type(findings, "mqtt_connect_credentials")
    findings, _ = feed(detector, b"\x30" + varint(len(connect())) + connect(),
                       target, offset=len(first), packet_id=packet_id)
    assert not by_type(findings, "mqtt_connect_credentials")


def test_mqtt_binary_password_and_capped_provenance_are_explicit():
    detector = SensitiveDetector(
        "synthetic-mqtt", max_provenance_spans=64,
        max_provenance_packet_id_refs=64,
    )
    payload = connect(password=b"\xff" * 100)
    findings, _ = feed(detector, payload, flow(dport=1883), width=1)
    found = by_type(findings, "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].material["password"] == b"\xff" * 100
    assert found[0].packet_ids_complete is False
    assert detector.stats()["provenance_cap_trimmed_spans"] > 0


def test_mqtt_maximum_binary_password_field_within_frame_bound():
    password = b"\xff" * 65_535
    payload = connect(password=password)
    assert len(payload) < MAX_CONNECT_BYTES
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, payload, flow(dport=1883), width=4096)
    found = by_type(findings, "mqtt_connect_credentials")
    assert len(found) == 1
    assert found[0].material["password"] == password
    assert found[0].packet_ids_complete


def test_mqtt_declared_oversize_is_visible_without_buffering():
    payload = b"\x10" + varint(MAX_CONNECT_BYTES)
    with pytest.raises(MQTTConnectLimit):
        parse_mqtt_connect(payload)
    detector = SensitiveDetector("synthetic-mqtt")
    feed(detector, payload, flow(dport=1883), width=1)
    assert detector.stats()["coverage_mqtt_connect_frame_limit"] == 1


def test_mqtt_new_connection_epoch_is_distinct_attempt():
    detector = SensitiveDetector("synthetic-mqtt")
    target = flow(dport=1883)
    payload = connect()
    first, _ = feed(detector, payload, target, connection_epoch=0)
    second, _ = feed(detector, payload, target, connection_epoch=1, packet_id=100)
    assert len(by_type(first, "mqtt_connect_credentials")) == 1
    assert len(by_type(second, "mqtt_connect_credentials")) == 1


def test_mqtt_nonstandard_port_is_not_claimed():
    detector = SensitiveDetector("synthetic-mqtt")
    findings, _ = feed(detector, connect(), flow(dport=2883))
    assert not by_type(findings, "mqtt_connect_credentials")


@pytest.mark.parametrize("password,expected", [
    (b"synthetic-password", "synthetic-password"),
    (b"\x00\xff", {"encoding": "hex", "value": "00ff"}),
])
def test_mqtt_offline_packet_to_export(tmp_path, password, expected):
    client_port = 45679
    properties = (
        b"\x11\x00\x00\x00\x01"
        + b"\x15" + field(b"SYNTHETIC-METHOD")
        + b"\x16" + field(b"\x00\xfe")
    )
    payload = connect(version=5, properties=properties, password=password)
    packets = [
        ethernet_ipv4_tcp(b"", seq=1000, sport=client_port, dport=1883, flags=0x02),
    ]
    for offset in range(0, len(payload), 5):
        packets.append(ethernet_ipv4_tcp(
            payload[offset:offset + 5], seq=1001 + offset,
            sport=client_port, dport=1883,
        ))
    capture = tmp_path / "synthetic-mqtt.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline", workers=2, queue_size=256, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl", heartbeat_seconds=1,
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    records = [json.loads(line) for line in config.output_jsonl.read_text().splitlines()]
    found = [record for record in records if record["material_type"] == "mqtt_connect_credentials"]
    assert len(found) == 1
    assert found[0]["material"]["password"] == expected
    assert found[0]["source_ip"] == "10.0.0.10"
    assert found[0]["destination_port"] == 1883
    assert found[0]["packet_ids_complete"] is True
    candidates = [record for record in records
                  if record["material_type"] == "mqtt_connect_authentication_data"]
    assert len(candidates) == 1
    assert candidates[0]["confidence"] == "medium"
    assert candidates[0]["material"]["authentication_method"] == "SYNTHETIC-METHOD"
    assert candidates[0]["material"]["authentication_data"] == {
        "encoding": "hex", "value": "00fe",
    }
    assert candidates[0]["packet_ids_complete"] is True
