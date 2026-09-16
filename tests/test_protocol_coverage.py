"""Synthetic publication gate for advertised credential protocol coverage.

The NTLM responses are structural fixtures, not responses from real accounts.
These tests prove extraction/correlation, never successful authentication.
"""
from __future__ import annotations

import base64
import json

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.config import AuditConfig
from packet_audit.supervisor import AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_tcp, write_pcap
from tests.test_detectors import (
    by_type, chunk, der, der_int, flow, ntlm_type2, ntlm_type3, tds_login7,
)


def feed(detector, payload, target_flow, *, direction=0, offset=0, packet_id=1,
         width=7, timestamp=None, connection_epoch=0):
    findings = []
    for start in range(0, len(payload), width):
        findings.extend(detector.process_stream(chunk(
            payload[start:start + width], target_flow=target_flow,
            direction=direction, offset=offset + start, packet_id=packet_id,
            timestamp=timestamp, connection_epoch=connection_epoch,
        )))
        packet_id += 1
    return findings, packet_id


@pytest.mark.parametrize("version", [1, 2])
@pytest.mark.parametrize("transport", ["raw", "raw-embedded", "http-ntlm", "http-negotiate"])
@pytest.mark.parametrize("width", [1, 7, 4096])
def test_netntlm_versions_wrapping_fragmentation_and_retries(version, transport, width):
    detector = SensitiveDetector("synthetic-protocol-gate")
    target = flow(dport=445 if transport.startswith("raw") else 80)
    challenge = b"TESTONLY"
    nt = (b"N" * 24 if version == 1
          else b"P" * 16 + b"\x01\x01\x00\x00" + b"B" * 28)
    type2 = ntlm_type2(challenge)
    type3 = ntlm_type3(nt_response=nt, username="synthetic-user", domain="SYNTHETIC")
    if transport == "raw-embedded":
        # Opaque surrounding bytes exercise signature scanning without claiming
        # a full SMB/SPNEGO framing implementation.
        type2 = b"SYNTHETIC-WRAPPER" + bytes(48) + type2
        type3 = b"SYNTHETIC-WRAPPER" + bytes(48) + type3
    elif transport != "raw":
        scheme = b"NTLM" if transport == "http-ntlm" else b"Negotiate"
        type2 = (b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: " + scheme
                 + b" " + base64.b64encode(type2) + b"\r\nContent-Length: 0\r\n\r\n")
        type3 = (b"GET /synthetic HTTP/1.1\r\nHost: synthetic.invalid\r\nAuthorization: "
                 + scheme + b" " + base64.b64encode(type3) + b"\r\n\r\n")
    findings, packet_id = feed(detector, type2, target, direction=1, width=width)
    assert len(by_type(findings, "ntlm_type2_challenge")) == 1
    found = []
    for attempt in range(3):
        findings, packet_id = feed(
            detector, type3, target, offset=attempt * len(type3),
            packet_id=packet_id, width=width,
        )
        found.extend(by_type(findings, f"netntlmv{version}"))
    assert len(found) == 3
    assert len({item.event_id for item in found}) == 3
    assert [item.attempt_ordinal for item in found] == [1, 2, 3]
    for item in found:
        assert item.material["hashcat_mode"] == (5500 if version == 1 else 5600)
        expected = (f"synthetic-user::SYNTHETIC:{(b'L' * 24).hex()}:{nt.hex()}:{challenge.hex()}"
                    if version == 1 else
                    f"synthetic-user::SYNTHETIC:{challenge.hex()}:{nt[:16].hex()}:{nt[16:].hex()}")
        assert item.material["hashcat"] == expected
        assert item.packet_ids_complete is True
        assert len(item.packet_ids) >= 2


@pytest.mark.parametrize("case", ["missing", "different-flow", "same-direction", "new-epoch"])
def test_netntlm_does_not_invent_or_cross_pair_challenges(case):
    detector = SensitiveDetector("synthetic-protocol-gate")
    target = flow(dport=445)
    if case != "missing":
        feed(detector, ntlm_type2(b"TESTONLY"), target,
             direction=0 if case == "same-direction" else 1,
             timestamp=1000)
    findings, _ = feed(
        detector, ntlm_type3(nt_response=b"N" * 24),
        flow(sport=40001, dport=445) if case == "different-flow" else target,
        offset=100, packet_id=100, timestamp=2000,
        connection_epoch=1 if case == "new-epoch" else 0,
    )
    assert len(by_type(findings, "ntlm_type3_response")) == 1
    assert not [item for item in findings if item.material_type in {"netntlmv1", "netntlmv2"}]


def protocol_cases():
    username = b"synthetic-user"
    password = b"synthetic-password"
    plain = base64.b64encode(b"\x00" + username + b"\x00" + password)
    login = base64.b64encode(username) + b"\r\n" + base64.b64encode(password) + b"\r\n"
    body = b"username=" + username + b"&password=" + password
    ldap = der(0x30, der_int(7) + der(
        0x60, der_int(3) + der(0x04, b"cn=synthetic-user,dc=invalid") + der(0x80, password),
    ))
    return [
        pytest.param(80, b"GET / HTTP/1.1\r\nHost: synthetic.invalid\r\nAuthorization: Basic "
                     + base64.b64encode(username + b":" + password) + b"\r\n\r\n",
                     "http_basic_credentials", "password", id="http-basic"),
        pytest.param(80, b"POST /login HTTP/1.1\r\nHost: synthetic.invalid\r\n"
                     b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
                     + str(len(body)).encode() + b"\r\n\r\n" + body,
                     "sensitive_field", "value", id="http-form"),
        pytest.param(21, b"USER " + username + b"\r\nPASS " + password + b"\r\n",
                     "ftp_credentials", "password", id="ftp"),
        pytest.param(110, b"USER " + username + b"\r\nPASS " + password + b"\r\n",
                     "pop3_credentials", "password", id="pop3"),
        pytest.param(25, b"AUTH PLAIN " + plain + b"\r\n",
                     "smtp_auth_plain_credentials", "password", id="smtp-plain-inline"),
        pytest.param(25, b"AUTH PLAIN\r\n" + plain + b"\r\n",
                     "smtp_auth_plain_credentials", "password", id="smtp-plain-multistep"),
        pytest.param(587, b"AUTH LOGIN\r\n" + login,
                     "smtp_auth_login_credentials", "password", id="smtp-login"),
        pytest.param(143, b'A1 LOGIN "' + username + b'" "' + password + b'"\r\n',
                     "imap_login_credentials", "password", id="imap-login"),
        pytest.param(143, b"A1 AUTHENTICATE PLAIN " + plain + b"\r\n",
                     "imap_auth_plain_credentials", "password", id="imap-plain-inline"),
        pytest.param(143, b"A1 AUTHENTICATE PLAIN\r\n" + plain + b"\r\n",
                     "imap_auth_plain_credentials", "password", id="imap-plain-multistep"),
        pytest.param(143, b"A1 AUTHENTICATE LOGIN\r\n" + login,
                     "imap_auth_login_credentials", "password", id="imap-auth-login"),
        pytest.param(389, ldap, "ldap_simple_bind_credentials", "password", id="ldap-simple"),
        pytest.param(1433, tds_login7(username.decode(), password.decode()),
                     "mssql_login7_credentials", "password", id="mssql-login7"),
        pytest.param(23, b"login: " + username + b"\r\npassword: " + password + b"\r\n",
                     "telnet_like_login_field", "value", id="telnet-like-fields"),
    ]


@pytest.mark.parametrize("port,payload,material_type,password_key", protocol_cases())
@pytest.mark.parametrize("width", [7, 4096])
def test_major_plaintext_protocols_segmented_and_repeated(port, payload, material_type,
                                                        password_key, width):
    detector = SensitiveDetector("synthetic-protocol-gate")
    findings, _ = feed(detector, payload * 3, flow(dport=port), width=width)
    found = [item for item in by_type(findings, material_type)
             if item.material.get(password_key) == "synthetic-password"]
    assert len(found) == 3
    assert len({item.event_id for item in found}) == 3
    assert all(item.packet_ids_complete for item in found)
    if material_type not in {"ldap_simple_bind_credentials", "telnet_like_login_field"}:
        assert all(item.material["username"] == "synthetic-user" for item in found)


def test_netntlm_v1_v2_replay_through_packet_workers_and_export(tmp_path):
    packets = []
    for version in (1, 2):
        sport = 50100 + version
        packets.append(ethernet_ipv4_tcp(b"", seq=1000, sport=sport, dport=445, flags=0x02))
        packets.append(ethernet_ipv4_tcp(
            b"", seq=5000, src="10.0.0.20", dst="10.0.0.10",
            sport=445, dport=sport, flags=0x12,
        ))
        challenge = ntlm_type2(b"TESTONLY")
        response = ntlm_type3(
            nt_response=b"N" * 24 if version == 1 else b"P" * 16 + b"\x01\x01\x00\x00" + b"B" * 28,
            username=f"synthetic-v{version}", domain="SYNTHETIC",
        ) * 3
        for offset in range(0, len(challenge), 11):
            packets.append(ethernet_ipv4_tcp(
                challenge[offset:offset + 11], seq=5001 + offset,
                src="10.0.0.20", dst="10.0.0.10", sport=445, dport=sport,
            ))
        for offset in range(0, len(response), 11):
            packets.append(ethernet_ipv4_tcp(
                response[offset:offset + 11], seq=1001 + offset, sport=sport, dport=445,
            ))
        packets.append(ethernet_ipv4_tcp(
            b"", seq=1001 + len(response), sport=sport, dport=445, flags=0x04,
        ))
    capture = tmp_path / "synthetic-ntlm.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline", workers=2, queue_size=256, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl", operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    assert result["worker_findings_emitted"] == result["writer_findings_written"]
    records = [json.loads(line) for line in config.output_jsonl.read_text().splitlines()]
    for version in (1, 2):
        found = [record for record in records if record["material_type"] == f"netntlmv{version}"]
        assert len(found) == 3
        assert len({record["event_id"] for record in found}) == 3
        for record in found:
            assert record["material"]["username"] == f"synthetic-v{version}"
            assert record["material"]["hashcat_mode"] == (5500 if version == 1 else 5600)
            assert record["source_ip"] == "10.0.0.10"
            assert record["source_port"] == 50100 + version
            assert record["destination_ip"] == "10.0.0.20"
            assert record["destination_port"] == 445
            assert len(record["packet_ids"]) > 2
            assert record["packet_ids_complete"] is True
