"""Synthetic-only regressions for live HTTP login framing."""
from __future__ import annotations

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.models import FlowKey, ProvenanceSpan, StreamChunk


def chunk(data: bytes, offset: int = 0, packet_id: int = 1) -> StreamChunk:
    flow, direction = FlowKey.canonical(protocol=6, src="192.0.2.10", sport=43210, dst="192.0.2.20", dport=80, interface="eth0")
    return StreamChunk(flow=flow, direction=direction, stream_offset=offset, data=data, packet_ids=(packet_id,), first_timestamp_ns=packet_id * 1000, last_timestamp_ns=packet_id * 1000, connection_epoch=0, completeness="complete", provenance_spans=(ProvenanceSpan(offset, offset + len(data), (packet_id,)),))


def request(body: bytes, content_type: bytes = b"application/x-www-form-urlencoded") -> bytes:
    return b"POST /Login.asp HTTP/1.1\r\nHost: audit.invalid\r\nContent-Type: " + content_type + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body


def fields(findings):
    return [finding for finding in findings if finding.detector == "sensitive_field"]


def test_vulnweb_final_field_is_not_lost_and_has_companion_user():
    payload = request(b"tfUName=FakeUser&tfUPass=FakePass")
    findings = fields(SensitiveDetector("test").process_stream(chunk(payload)))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.material == {"name": "tfUPass", "encoded_value": "FakePass", "value": "FakePass", "source": "form", "username": "FakeUser", "username_field": "tfUName"}
    assert finding.stream_offset == payload.index(b"FakePass")
    assert finding.fields["http_body_complete"] is True
    assert finding.packet_ids == (1,)


def test_all_two_segment_splits_wait_for_complete_body():
    payload = request(b"username=FakeUser&password=Fake+Pass%21")
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        first = detector.process_stream(chunk(payload[:split]))
        assert not fields(first), split
        assert not [finding for finding in first if finding.detector == "generic_secret_assignment"], split
        final = fields(detector.process_stream(chunk(payload[split:], split, 2)))
        assert len(final) == 1, split
        assert final[0].material["value"] == "Fake Pass!", split


def test_bytewise_segments_and_exact_provenance():
    payload = request(b"tfUName=FakeUser&tfUPass=FakePass")
    detector = SensitiveDetector("test")
    found = []
    for offset, value in enumerate(payload):
        found.extend(detector.process_stream(chunk(bytes([value]), offset, offset + 1)))
    finding = fields(found)[0]
    user_start = payload.index(b"FakeUser")
    pass_start = payload.index(b"FakePass")
    assert set(finding.packet_ids) == set(range(user_start + 1, user_start + 9)) | set(range(pass_start + 1, pass_start + 9))
    assert finding.packet_ids_complete


def test_same_buffer_pipeline_separate_retry_attempts_and_no_password_extension():
    login = request(b"username=FakeUser&password=FakePass")
    next_request = b"GET /?token=FakeToken HTTP/1.1\r\nHost: audit.invalid\r\n\r\n"
    detector = SensitiveDetector("test")
    found = detector.process_stream(chunk(login + next_request + login))
    values = [finding.material["value"] for finding in fields(found)]
    assert values == ["FakePass", "FakeToken", "FakePass"]
    assignments = [finding.material["value"] for finding in found if finding.detector == "generic_secret_assignment"]
    assert all(value != "FakePassGET" for value in assignments)
    assert "FakePassGET" not in str(found)
    assert detector.process_stream(chunk(login + next_request + login)) == []
    retry = fields(detector.process_stream(chunk(login, len(login + next_request + login), 2)))
    assert retry[0].material["value"] == "FakePass"
    assert retry[0].attempt_ordinal == 4


def test_generic_assignment_cannot_cross_verified_message_boundary():
    login = request(b"password=FakePass")
    following = b"GET / HTTP/1.1\r\n\r\n"
    detector = SensitiveDetector("test")
    found = detector.process_stream(chunk(login + following))
    assignments = [finding.material["value"] for finding in found if finding.detector == "generic_secret_assignment"]
    assert assignments == ["FakePass"]
    assert "FakePassGET" not in str(found)


def test_pipeline_at_every_two_segment_split():
    payload = request(b"username=FakeUser&password=FakePass") + request(b"username=FakeUser&password=OtherPass")
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        found = detector.process_stream(chunk(payload[:split]))
        found += detector.process_stream(chunk(payload[split:], split, 2))
        assert [finding.material["value"] for finding in fields(found)] == ["FakePass", "OtherPass"], split


@pytest.mark.parametrize("name", [b"tfUPass", b"txtPassword", b"user[password]", b"login_password", b"password1", b"passwd", b"credentials.password", b"ctl00%24Main%24txtPassword"])
def test_password_aliases(name):
    found = fields(SensitiveDetector("test").process_stream(chunk(request(b"username=FakeUser&" + name + b"=FakePass"))))
    assert len(found) == 1
    assert found[0].material["value"] == "FakePass"


def test_json_nested_escaped_duplicate_fields_and_last_field():
    body = b'{"credentials":{"username":"FakeUser","password":"Fake\\u0020Pass!"},"password":"SecondPass"}'
    payload = request(body, b"application/json")
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        assert fields(detector.process_stream(chunk(payload[:split]))) == []
        found = fields(detector.process_stream(chunk(payload[split:], split, 2)))
        assert [finding.material["value"] for finding in found] == ["Fake Pass!", "SecondPass"]
        assert found[0].material["username"] == "FakeUser"
        assert found[0].stream_offset == payload.index(b'"Fake\\u0020Pass!"')


def test_truncated_body_never_emits_partial_values_even_with_delimiters():
    payload = request(b"username=FakeUser&password=FakePass&other=next")
    detector = SensitiveDetector("test")
    assert fields(detector.process_stream(chunk(payload[:-4]))) == []
    assert detector.stats().get("http_framed_requests", 0) == 0


def test_chunked_form_all_splits_and_wire_offsets():
    first = b"username=FakeUser&password=Fake"
    second = b"Pass"
    chunks = f"{len(first):X}\r\n".encode() + first + b"\r\n4\r\n" + second + b"\r\n0\r\n\r\n"
    payload = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        assert not fields(detector.process_stream(chunk(payload[:split])))
        found = fields(detector.process_stream(chunk(payload[split:], split, 2)))
        assert len(found) == 1, split
        assert found[0].material["value"] == "FakePass"
        assert found[0].stream_offset == payload.index(b"password=Fake") + len(b"password=")


@pytest.mark.parametrize("extra", [b"Content-Length: 25\r\nContent-Length: 25\r\n", b"Content-Length: 25\r\nTransfer-Encoding: chunked\r\n", b"Content-Length: no\r\n", b"Transfer-Encoding: gzip\r\n"])
def test_ambiguous_framing_is_visible_not_a_bogus_login(extra):
    payload = b"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n" + extra + b"\r\npassword=FakePassGET / HTTP/1.1\r\n\r\n"
    detector = SensitiveDetector("test")
    assert not fields(detector.process_stream(chunk(payload)))
    assert any(key.startswith("http_framing_") and value for key, value in detector.stats().items())


def test_oversized_length_skip_preserves_later_known_boundary():
    body = b"x" * 5000
    oversize = request(body)
    payload = oversize + request(b"password=FakePass")
    detector = SensitiveDetector("test", overlap_bytes=4096)
    found = fields(detector.process_stream(chunk(payload)))
    assert [finding.material["value"] for finding in found] == ["FakePass"]
    assert detector.stats()["http_framing_body_limit"] == 1
    assert detector.stats()["retained_tail_bytes"] <= 4096


def test_compressed_body_is_not_interpreted_as_plain_form():
    payload = request(b"password=FakePass").replace(b"Content-Length:", b"Content-Encoding: gzip\r\nContent-Length:")
    detector = SensitiveDetector("test")
    assert fields(detector.process_stream(chunk(payload))) == []
    assert detector.stats()["http_body_unsupported_content_encoding"] == 1


def test_invalid_json_does_not_produce_typed_field_and_is_counted():
    detector = SensitiveDetector("test")
    assert fields(detector.process_stream(chunk(request(b'{"password":"FakePass",}', b"application/json")))) == []
    assert detector.stats()["http_body_invalid_json"] == 1


def test_multiple_usernames_do_not_invent_a_credential_pair():
    found = fields(SensitiveDetector("test").process_stream(chunk(request(
        b"username=FirstUser&email=SecondUser&password=FakePass"
    ))))
    assert len(found) == 1
    assert "username" not in found[0].material
    assert "not inferred" in found[0].fields["username_context"]
