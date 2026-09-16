"""Synthetic detector integration for bounded cleartext message cursors."""
import pytest

from packet_audit.detectors import SensitiveDetector
from tests.test_detectors import by_type, flow
from tests.test_protocol_coverage import feed


def pg(tag, payload):
    return tag + (len(payload) + 4).to_bytes(4, "big") + payload


def resp(*arguments):
    return b"*" + str(len(arguments)).encode() + b"\r\n" + b"".join(
        b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n" for value in arguments
    )


@pytest.mark.parametrize("width", [1, 7, 4096])
@pytest.mark.parametrize("command", [resp(b"AUTH", b"synthetic-secret"), resp(b"AUTH", b"synthetic-user", b"synthetic-secret"), resp(b"HELLO", b"3", b"AUTH", b"synthetic-user", b"synthetic-secret")])
def test_redis_segmented_retries(width, command):
    detector = SensitiveDetector("synthetic-redis")
    findings, _ = feed(detector, command * 3, flow(dport=6379), width=width)
    found = by_type(findings, "redis_auth")
    assert len(found) == 3
    assert all(f.material["password"] == "synthetic-secret" for f in found)
    assert all(f.packet_ids_complete for f in found)


def test_redis_frame_cursor_survives_many_tail_rotations():
    detector = SensitiveDetector("synthetic-redis", overlap_bytes=4096)
    target = flow(dport=6379)
    command = resp(b"AUTH", b"synthetic-secret")
    findings, _ = feed(detector, command * 1000, target, width=37)
    assert len(by_type(findings, "redis_auth")) == 1000
    assert detector.stats().get("coverage_cleartext_frame_boundary_lost", 0) == 0


@pytest.mark.parametrize("width", [1, 7, 4096])
def test_pg_cleartext_only_with_server_method_and_retries(width):
    detector = SensitiveDetector("synthetic-pg")
    target = flow(dport=5432)
    _, packet_id = feed(detector, pg(b"R", (3).to_bytes(4, "big")), target, direction=1, width=width)
    findings, _ = feed(detector, pg(b"p", b"synthetic-secret\0") * 3, target, packet_id=packet_id, width=width)
    found = by_type(findings, "postgres_cleartext_password")
    assert len(found) == 3
    assert all(f.material["password"] == "synthetic-secret" for f in found)
    assert all(f.confidence == "confirmed" for f in found)


def test_pg_unknown_method_is_not_confirmed_plaintext_and_md5_is_not_password():
    detector = SensitiveDetector("synthetic-pg")
    target = flow(dport=5432)
    findings, _ = feed(detector, pg(b"p", b"synthetic-secret\0"), target)
    assert not by_type(findings, "postgres_cleartext_password")
    assert by_type(findings, "postgres_password_message")[0].confidence == "medium"
    detector = SensitiveDetector("synthetic-pg")
    _, packet_id = feed(detector, pg(b"R", (5).to_bytes(4, "big") + b"SALT"), target, direction=1)
    findings, _ = feed(detector, pg(b"p", b"md5" + b"0" * 32 + b"\0"), target, packet_id=packet_id)
    assert not by_type(findings, "postgres_cleartext_password")
    assert not by_type(findings, "postgres_password_message")


def test_nested_redis_auth_in_value_is_not_a_login():
    detector = SensitiveDetector("synthetic-redis")
    wire = resp(b"SET", b"key", resp(b"AUTH", b"not-a-password"))
    findings, _ = feed(detector, wire, flow(dport=6379), width=1)
    assert not by_type(findings, "redis_auth")


def test_cleartext_boundary_loss_is_visible_not_speculatively_resynchronized():
    detector = SensitiveDetector("synthetic-redis", overlap_bytes=4096)
    payload = resp(b"SET", b"key", b"X" * 12000) + resp(b"AUTH", b"synthetic-secret")
    findings, _ = feed(detector, payload, flow(dport=6379), width=300)
    assert not by_type(findings, "redis_auth")
    assert detector.stats()["coverage_cleartext_frame_boundary_lost"] == 1


def test_pg_invalid_auth_request_cannot_reuse_previous_cleartext_method():
    detector = SensitiveDetector("synthetic-pg")
    target = flow(dport=5432)
    server = pg(b"R", (3).to_bytes(4, "big")) + pg(b"R", (1234).to_bytes(4, "big"))
    _, packet_id = feed(detector, server, target, direction=1)
    findings, _ = feed(detector, pg(b"p", b"synthetic-secret\0"), target, packet_id=packet_id)
    assert not by_type(findings, "postgres_cleartext_password")
    assert by_type(findings, "postgres_password_message")
    assert detector.stats()["coverage_cleartext_postgres_authentication_invalid"] == 1


def test_oversized_auth_is_visible_not_exported_as_a_credential():
    detector = SensitiveDetector("synthetic-redis")
    findings, _ = feed(detector, resp(b"AUTH", b"X" * 9000), flow(dport=6379), width=1000)
    assert not by_type(findings, "redis_auth")
    assert any(value for key, value in detector.stats().items() if key.startswith("coverage_cleartext_"))


def test_partial_cleartext_is_pending_until_completed_or_evicted():
    detector = SensitiveDetector("synthetic-redis", max_flows=1)
    target = flow(dport=6379)
    command = resp(b"AUTH", b"synthetic-secret")
    _, packet_id = feed(detector, command[:-2], target)
    assert detector.stats()["coverage_cleartext_pending_frames"] == 1
    findings, _ = feed(detector, command[-2:], target, offset=len(command) - 2, packet_id=packet_id)
    assert len(by_type(findings, "redis_auth")) == 1
    assert detector.stats()["coverage_cleartext_pending_frames"] == 0
    feed(detector, b"*2\r\n$4\r\nAUTH\r\n", target, offset=len(command), packet_id=100)
    feed(detector, b"anything", flow(sport=50000, dport=80))
    assert detector.stats()["coverage_cleartext_pending_frames"] == 0
    assert detector.stats()["coverage_cleartext_incomplete_at_eviction"] == 1
