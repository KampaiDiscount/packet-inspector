"""Four independent-review failures, reproduced using synthetic NTLM only."""
import struct

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.ntlm_wrappers import smb2_session_for_token
from tests.test_detectors import by_type, chunk, flow, ntlm_type2, ntlm_type3
from tests.test_ntlm_wrappers import smb2


def _response(version):
    return b"N" * 24 if version == 1 else b"P" * 16 + b"\x01\x01\0\0" + b"B" * 28


@pytest.mark.parametrize("version", [1, 2])
def test_late_challenge_correlation_preserves_client_endpoints_and_observation_time(version):
    detector = SensitiveDetector("synthetic-late-challenge")
    target = flow(dport=445)
    response = ntlm_type3(nt_response=_response(version))
    initial = detector.process_stream(chunk(
        response, target_flow=target, direction=0, offset=100,
        packet_id=20, timestamp=2000,
    ))
    assert not by_type(initial, f"netntlmv{version}")
    # This challenge was observed earlier but completed reassembly later.
    findings = detector.process_stream(chunk(
        ntlm_type2(b"TESTONLY"), target_flow=target, direction=1, offset=10,
        packet_id=10, timestamp=1000,
    ))
    pairs = by_type(findings, f"netntlmv{version}")
    assert len(pairs) == 1
    record = pairs[0]
    exported = record.to_dict()
    assert record.direction == 0
    assert record.observed_timestamp_ns == 2000
    assert record.stream_offset == 100
    assert exported["source_port"] == target.endpoint_a.port
    assert exported["destination_port"] == 445
    assert record.fields["response_stream_offset"] == 100
    assert set(record.packet_ids) == {10, 20}


@pytest.mark.parametrize("invalid_response", [
    b"Z" * 25,
    b"Z" * 48,
    b"P" * 16 + b"\x01\x01\0\0" + b"B" * 27,
])
def test_arbitrary_or_truncated_nt_response_is_not_confirmed_netntlmv2(invalid_response):
    detector = SensitiveDetector("synthetic-invalid-v2")
    target = flow(dport=445)
    detector.process_stream(chunk(
        ntlm_type2(b"TESTONLY"), target_flow=target, direction=1,
        packet_id=1, timestamp=1000,
    ))
    findings = detector.process_stream(chunk(
        ntlm_type3(nt_response=invalid_response), target_flow=target,
        direction=0, packet_id=2, timestamp=2000,
    ))
    assert by_type(findings, "ntlm_type3_response")  # Keep raw evidence.
    assert not by_type(findings, "netntlmv2")
    assert not by_type(findings, "netntlmv1")
    assert detector.stats()["coverage_ntlm_response_format_unsupported"] == 1


@pytest.mark.parametrize("version", [1, 2])
def test_delayed_lower_offset_smb_session_pair_is_not_squelched_by_other_session(version):
    detector = SensitiveDetector("synthetic-multiplexed-pending")
    target = flow(dport=445)
    first = smb2(ntlm_type3(nt_response=_response(version), username="synthetic-a"), 101)
    second = smb2(ntlm_type3(nt_response=_response(version), username="synthetic-b"), 202)
    detector.process_stream(chunk(first, target_flow=target, direction=0, offset=0,
                                  packet_id=3, timestamp=3000))
    detector.process_stream(chunk(second, target_flow=target, direction=0, offset=len(first),
                                  packet_id=4, timestamp=4000))
    second_challenge = smb2(ntlm_type2(b"SESSIONB"), 202, response=True)
    first_challenge = smb2(ntlm_type2(b"SESSIONA"), 101, response=True)
    later_pair = by_type(detector.process_stream(chunk(
        second_challenge, target_flow=target, direction=1, offset=0,
        packet_id=1, timestamp=1000,
    )), f"netntlmv{version}")
    earlier_pair = by_type(detector.process_stream(chunk(
        first_challenge, target_flow=target, direction=1, offset=len(second_challenge),
        packet_id=2, timestamp=2000,
    )), f"netntlmv{version}")
    assert len(later_pair) == len(earlier_pair) == 1
    assert later_pair[0].material["smb_session_id"] == 202
    assert earlier_pair[0].material["smb_session_id"] == 101
    assert earlier_pair[0].material["challenge_hex"] == b"SESSIONA".hex()
    assert earlier_pair[0].stream_offset < later_pair[0].stream_offset
    assert earlier_pair[0].direction == later_pair[0].direction == 0
    assert set(earlier_pair[0].packet_ids) == {2, 3}
    retry = by_type(detector.process_stream(chunk(
        first, target_flow=target, direction=0, offset=len(first) + len(second),
        packet_id=5, timestamp=5000,
    )), f"netntlmv{version}")
    assert len(retry) == 1
    assert len({record.event_id for record in later_pair + earlier_pair + retry}) == 3


def test_smb_session_security_buffer_must_contain_entire_token_not_only_signature_start():
    token = ntlm_type2(b"TESTONLY")
    wire = bytearray(smb2(token, 42, response=True))
    start = wire.index(b"NTLMSSP\0")
    assert smb2_session_for_token(wire, start, len(token)) == 42
    for declared_length in (1, 11, len(token) - 1):
        malformed = bytearray(wire)
        struct.pack_into("<HH", malformed, 4 + 68, start - 4, declared_length)
        assert smb2_session_for_token(malformed, start, len(token)) is None
    malformed = bytearray(wire)
    struct.pack_into("<HH", malformed, 4 + 68, start - 4, 1)
    assert smb2_session_for_token(malformed, start) is None

    detector = SensitiveDetector("synthetic-short-smb-security-buffer")
    target = flow(dport=445)
    findings = detector.process_stream(chunk(
        bytes(malformed), target_flow=target, direction=1,
        packet_id=1, timestamp=1000,
    ))
    findings += detector.process_stream(chunk(
        smb2(ntlm_type3(nt_response=b"N" * 24), 42), target_flow=target,
        direction=0, packet_id=2, timestamp=2000,
    ))
    assert by_type(findings, "ntlm_type2_challenge")
    assert by_type(findings, "ntlm_type3_response")
    assert not by_type(findings, "netntlmv1")
    assert detector.stats()["coverage_ntlm_session_unavailable"] >= 1
