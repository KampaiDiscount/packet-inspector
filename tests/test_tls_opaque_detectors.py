"""Encrypted TLS records must not become cleartext credential evidence."""

from __future__ import annotations

import base64

from packet_audit.config import AuditConfig
from packet_audit.detectors import SensitiveDetector
from packet_audit.supervisor import AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_tcp, write_pcap
from tests.test_detectors import chunk, flow, tds_login7


def _client_hello() -> bytes:
    # Complete, minimal TLS 1.2 ClientHello with a one-suite offer.
    body = (
        b"\x03\x03" + bytes(range(32)) + b"\x00"
        + b"\x00\x02\x00\x2f" + b"\x01\x00" + b"\x00\x00"
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def _tls_application_record(body: bytes) -> bytes:
    return b"\x17\x03\x03" + len(body).to_bytes(2, "big") + body


def test_tls_application_bytes_do_not_become_http_or_line_credentials() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    hello = _client_hello()
    assert detector.process_stream(chunk(hello, target_flow=target)) == []

    basic = base64.b64encode(b"fixture-user:fixture-password")
    apparent_cleartext = (
        b"POST /login HTTP/1.1\r\nHost: example.invalid\r\n"
        b"Authorization: Basic " + basic + b"\r\n\r\n"
        b"USER fixture-user\r\nPASS fixture-password\r\n"
    )
    encrypted = _tls_application_record(apparent_cleartext)
    findings = detector.process_stream(
        chunk(encrypted, target_flow=target, offset=len(hello), packet_id=2)
    )
    assert not [item for item in findings if item.category == "credential"]


def test_tls_application_bytes_do_not_become_tds_on_new_direction() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    hello = _client_hello()
    detector.process_stream(chunk(hello, target_flow=target))
    apparent_tds = tds_login7("fixture-user", "fixture-password")
    findings = detector.process_stream(
        chunk(_tls_application_record(apparent_tds), target_flow=target, direction=1, packet_id=2)
    )
    assert not [item for item in findings if item.category == "credential"]


def test_midstream_tls_application_record_is_not_cleartext_evidence() -> None:
    # A capture may begin after the handshake. The first observed bytes are
    # then a complete TLS ApplicationData record at stream offset zero.
    detector = SensitiveDetector("session")
    apparent_http = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    findings = detector.process_stream(
        chunk(_tls_application_record(apparent_http), target_flow=flow(40000, 443))
    )
    assert not [item for item in findings if item.category == "credential"]


def test_fragmented_midstream_tls_record_waits_before_scanning() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    apparent_http = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    record = _tls_application_record(apparent_http)
    assert detector.process_stream(chunk(record[:35], target_flow=target)) == []
    findings = detector.process_stream(
        chunk(record[35:], target_flow=target, offset=35, packet_id=2)
    )
    assert not [item for item in findings if item.category == "credential"]
    assert detector.stats()["tls_opaque_midstream_flows"] == 1


def test_tls_state_isolated_from_reused_five_tuple() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    detector.process_stream(chunk(_client_hello(), target_flow=target, connection_epoch=1))
    cleartext = tds_login7("fixture-user", "fixture-password")
    findings = detector.process_stream(
        chunk(cleartext, target_flow=target, connection_epoch=2, packet_id=2)
    )
    assert len([item for item in findings if item.material_type == "mssql_login7_credentials"]) == 1


def test_cleartext_before_midstream_tls_upgrade_remains_detected() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    request = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    findings = detector.process_stream(chunk(request, target_flow=target))
    assert len([item for item in findings if item.material_type == "http_basic_credentials"]) == 1
    detector.process_stream(
        chunk(_client_hello(), target_flow=target, offset=len(request), packet_id=2)
    )
    # A protocol upgrade later in this stream is not established by the
    # stream-origin TLS gate; this is a documented coverage boundary.
    assert detector.stats().get("tls_opaque_flows", 0) == 0


def test_segmented_and_retransmitted_tls_hello_is_opaque_after_completion() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    hello = _client_hello()
    assert detector.process_stream(chunk(hello[:3], target_flow=target)) == []
    assert detector.process_stream(
        chunk(hello[3:], target_flow=target, offset=3, packet_id=2)
    ) == []
    assert detector.process_stream(
        chunk(hello[3:], target_flow=target, offset=3, packet_id=3)
    ) == []
    apparent_http = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    findings = detector.process_stream(
        chunk(_tls_application_record(apparent_http), target_flow=target,
              offset=len(hello), packet_id=4)
    )
    assert not [item for item in findings if item.category == "credential"]
    assert detector.stats()["tls_opaque_flows"] == 1


def test_malformed_tls_lookalike_does_not_hide_cleartext_credentials() -> None:
    detector = SensitiveDetector("session")
    target = flow(40000, 443)
    # The alleged handshake body starts with an invalid protocol version.
    lookalike = b"\x16\x03\x03\x00\x06\x01\x00\x00\x02\x00\x00"
    apparent_http = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    findings = detector.process_stream(chunk(lookalike + apparent_http, target_flow=target))
    assert [item for item in findings if item.material_type == "http_basic_credentials"]


def test_tls_opaque_telemetry_is_informational_for_complete_replay(tmp_path) -> None:
    hello = _client_hello()
    apparent_http = b"GET / HTTP/1.1\r\nAuthorization: Basic Zm9vOmJhcg==\r\n\r\n"
    encrypted = _tls_application_record(apparent_http)
    packets = [
        ethernet_ipv4_tcp(b"", seq=1000, dport=443, flags=0x02),
        ethernet_ipv4_tcp(hello, seq=1001, dport=443),
        ethernet_ipv4_tcp(encrypted, seq=1001 + len(hello), dport=443),
    ]
    capture = tmp_path / "tls-opaque.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline", workers=1, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    assert result["worker_health_totals"]["detector_tls_opaque_flows"] == 1
    assert result["worker_health_totals"]["detector_tls_opaque_chunks"] >= 2
    assert result["worker_findings_emitted"] == 0
