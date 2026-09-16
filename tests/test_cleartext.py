"""Synthetic Redis/PostgreSQL framing, retries and false-positive regressions."""
import pytest

from packet_audit.cleartext import (
    MAX_FIELD_BYTES, UNKNOWN_POSTGRES_METHOD, postgres_authentication_requests,
    postgres_passwords, redis_auth, scan_postgres, scan_postgres_authentication, scan_redis,
)


def resp(*arguments):
    return b"*" + str(len(arguments)).encode() + b"\r\n" + b"".join(
        b"$" + str(len(arg)).encode() + b"\r\n" + arg + b"\r\n" for arg in arguments
    )


def pg(tag, payload):
    return tag + (len(payload) + 4).to_bytes(4, "big") + payload


def auth(method, suffix=b""):
    return pg(b"R", method.to_bytes(4, "big") + suffix)


@pytest.mark.parametrize("wire,username,password,command", [
    (resp(b"AUTH", b"SyntheticOnly"), "default", "SyntheticOnly", "AUTH"),
    (resp(b"auth", b"alice", b"SyntheticOnly"), "alice", "SyntheticOnly", "AUTH"),
    (b"AUTH SyntheticOnly\r\n", "default", "SyntheticOnly", "AUTH"),
    (b"auth alice SyntheticOnly\r\n", "alice", "SyntheticOnly", "AUTH"),
    (b'AUTH "Fake User" "Synthetic Value"\r\n', "Fake User", "Synthetic Value", "AUTH"),
    (b"AUTH 'Synthetic Value'\r\n", "default", "Synthetic Value", "AUTH"),
    (resp(b"HELLO", b"3", b"AUTH", b"alice", b"SyntheticOnly"), "alice", "SyntheticOnly", "HELLO AUTH"),
    (resp(b"HELLO", b"2", b"SETNAME", b"audit", b"AUTH", b"alice", b"SyntheticOnly"), "alice", "SyntheticOnly", "HELLO AUTH"),
    (b"HELLO 3 AUTH alice SyntheticOnly SETNAME audit\r\n", "alice", "SyntheticOnly", "HELLO AUTH"),
])
def test_redis_auth_formats(wire, username, password, command):
    records, consumed = scan_redis(wire)
    assert consumed == len(wire)
    assert len(records) == 1
    record = records[0]
    assert (record.start, record.end) == (0, len(wire))
    assert record.material == {"kind": "redis_auth", "command": command,
                               "username": username, "password": password}


@pytest.mark.parametrize("wire", [
    resp(b"AUTH", b"SyntheticOnly"),
    resp(b"AUTH", b"alice", b"SyntheticOnly"),
    b"AUTH SyntheticOnly\r\n",
    pg(b"p", b"SyntheticOnly\0"),
    auth(3),
])
def test_partial_frames_emit_only_after_complete_reassembly(wire):
    parser = (scan_postgres_authentication if wire.startswith(b"R") else
              scan_postgres if wire.startswith(b"p") else scan_redis)
    for split in range(1, len(wire)):
        records, consumed = parser(wire[:split])
        assert records == []
        assert consumed == 0
        records, consumed = parser(wire[:split] + wire[split:])
        assert len(records) == 1
        assert consumed == len(wire)


def test_redis_binary_password_preserves_bytes():
    secret = b"\x00\xff\r\n*2\r\n$4\r\nAUTH\r\n"
    records = redis_auth(resp(b"AUTH", secret))
    assert len(records) == 1
    assert records[0].material["password"] == secret


@pytest.mark.parametrize("wire", [
    b"AUTH SyntheticOnly", b"AUTH SyntheticOnly\n", b"AUTH\r\n",
    b"AUTH alice fake extra\r\n", b'AUTH "unclosed\r\n',
    b'AUTH "Fake\\nOnly"\r\n', b"AUTH Fake\\Only\r\n",
    b"*2\r\n$4\r\nAUTH\r\n$99999999999\r\nx\r\n",
    b"*2\r\n$4\r\nAUTH\r\n$-1\r\n", b"*129\r\n",
    b"*2\r\n$4\r\nAUTHxx$4\r\nfake\r\n",
    resp(b"HELLO", b"3", b"AUTH", b"alice", b"fake", b"unknown"),
    resp(b"HELLO", b"3", b"AUTH", b"alice", b"fake", b"AUTH", b"bob", b"fake"),
])
def test_redis_malformed_or_ambiguous_data_is_not_reported(wire):
    assert redis_auth(wire) == []


def test_redis_never_searches_inside_unrelated_bulk_values():
    nested = resp(b"AUTH", b"NestedFake") + b"AUTH AlsoNestedFake\r\n"
    unrelated = resp(b"SET", b"key", nested)
    real = resp(b"AUTH", b"ActualSynthetic")
    records, consumed = scan_redis(unrelated + real * 2)
    assert consumed == len(unrelated + real * 2)
    assert len(records) == 2
    assert records[0].start == len(unrelated)
    assert records[1].start == len(unrelated) + len(real)
    assert all(record.material["password"] == "ActualSynthetic" for record in records)


def test_redis_never_searches_inside_standalone_bulk_string():
    value = b"AUTH NestedFake\r\n" + resp(b"AUTH", b"AlsoNestedFake")
    wire = b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n"
    assert scan_redis(wire) == ([], len(wire))


def test_redis_oversized_field_is_skipped_without_losing_next_boundary():
    large = resp(b"AUTH", b"X" * (MAX_FIELD_BYTES + 1))
    valid = resp(b"AUTH", b"SyntheticOnly")
    records, consumed = scan_redis(large + valid)
    assert consumed == len(large + valid)
    assert len(records) == 2
    assert records[0].material["kind"] == "cleartext_coverage"
    assert records[0].material["reason"] == "redis_auth_field_or_message_limit"
    assert records[1].start == len(large)


def test_redis_consumed_cursor_stays_at_partial_frame_start():
    unrelated = resp(b"PING")
    attempt = resp(b"AUTH", b"SyntheticOnly")
    records, consumed = scan_redis(unrelated + attempt[:-2])
    assert records == [] and consumed == len(unrelated)
    assert len(redis_auth((unrelated + attempt)[consumed:])) == 1


@pytest.mark.parametrize("method,expected_kind,key", [
    (None, "postgres_password_message", "password_message"),
    (3, "postgres_cleartext_password", "password"),
])
def test_postgres_password_classification_depends_on_authentication_request(method, expected_kind, key):
    wire = pg(b"p", b"SyntheticOnly\0")
    records, consumed = scan_postgres(wire, authentication_method=method)
    assert consumed == len(wire)
    assert len(records) == 1
    record = records[0]
    assert record.material == {"kind": expected_kind, "authentication_method": method, key: "SyntheticOnly"}
    assert record.limitations == ((UNKNOWN_POSTGRES_METHOD,) if method is None else ())
    if method is None:
        assert "password" not in record.material


@pytest.mark.parametrize("method", [0, 5, 7, 8, 9, 10, 11, 12])
def test_postgres_known_noncleartext_methods_do_not_emit_passwords(method):
    wire = pg(b"p", b"SyntheticOnly\0")
    assert scan_postgres(wire, method) == ([], len(wire))


@pytest.mark.parametrize("payload", [
    b"md5" + b"a" * 32 + b"\0",
    b"SCRAM-SHA-256\0\x00\x00\x00\x15n,,n=alice,r=fake",
    b"c=biws,r=fake,p=synthetic-proof",
    b"no-terminating-null", b"interior\0null\0",
])
def test_postgres_unknown_method_does_not_mislabel_md5_or_sasl(payload):
    assert postgres_passwords(pg(b"p", payload)) == []


def test_postgres_no_search_inside_query_or_other_frontend_payload():
    fake = pg(b"p", b"NestedFake\0")
    unrelated = pg(b"Q", b"SELECT '" + fake + b"'\0") + pg(b"P", fake)
    valid = pg(b"p", b"ActualSynthetic\0")
    records, consumed = scan_postgres(unrelated + valid * 2, 3)
    assert consumed == len(unrelated + valid * 2)
    assert len(records) == 2
    assert records[0].start == len(unrelated)
    assert records[1].start == len(unrelated) + len(valid)
    assert all(record.material["password"] == "ActualSynthetic" for record in records)


def test_postgres_consumed_cursor_preserves_partial_frame():
    query = pg(b"Q", b"SELECT 1\0")
    password = pg(b"p", b"SyntheticOnly\0")
    assert scan_postgres(query + password[:-1], 3) == ([], len(query))
    assert len(postgres_passwords((query + password)[len(query):], 3)) == 1


@pytest.mark.parametrize("wire", [
    b"p\0\0\0\x03", b"p\xff\xff\xff\xffSyntheticOnly\0",
    b"p\0\0\0\x20short\0", b"unknown" + pg(b"p", b"NestedFake\0"),
    pg(b"p", b"X" * (MAX_FIELD_BYTES + 1) + b"\0"),
])
def test_postgres_malformed_oversized_or_unaligned_frames_are_not_reported(wire):
    assert postgres_passwords(wire, 3) == []


def test_postgres_startup_and_ssl_request_framing_are_consumed():
    startup_payload = (3 << 16).to_bytes(4, "big") + b"user\0alice\0database\0audit\0\0"
    startup = (len(startup_payload) + 4).to_bytes(4, "big") + startup_payload
    ssl = (8).to_bytes(4, "big") + (80877103).to_bytes(4, "big")
    password = pg(b"p", b"SyntheticOnly\0")
    records, consumed = scan_postgres(ssl + startup + password, 3)
    assert consumed == len(ssl + startup + password)
    assert len(records) == 1 and records[0].start == len(ssl + startup)


@pytest.mark.parametrize("method,suffix", [(0, b""), (3, b""), (5, b"salt"),
    (10, b"SCRAM-SHA-256\0\0"), (11, b"r=synthetic,s=synthetic,i=4096"), (12, b"v=synthetic")])
def test_postgres_server_authentication_methods(method, suffix):
    wire = auth(method, suffix)
    records, consumed = scan_postgres_authentication(wire)
    assert consumed == len(wire)
    assert len(records) == 1 and records[0].material["authentication_method"] == method


@pytest.mark.parametrize("wire", [auth(3, b"extra"), auth(5, b"short"), auth(10),
    auth(10, b"SCRAM-SHA-256\0"), auth(10, b"\0\0"), auth(11), auth(99)])
def test_postgres_server_authentication_format_validation(wire):
    records = postgres_authentication_requests(wire)
    assert len(records) == 1
    assert records[0].material["authentication_method"] is None
    assert records[0].material["coverage_reason"] == "postgres_authentication_invalid"
    assert records[0].limitations


def test_postgres_server_no_nested_authentication_request_in_notice():
    nested = pg(b"N", b"message" + auth(3))
    later = auth(5, b"salt")
    records, consumed = scan_postgres_authentication(nested + later)
    assert consumed == len(nested + later)
    assert len(records) == 1
    assert records[0].start == len(nested)
    assert records[0].material["authentication_method"] == 5


def test_postgres_refused_ssl_upgrade_before_cleartext_request():
    wire = b"N" + auth(3)
    for split in range(1, len(wire)):
        assert scan_postgres_authentication(wire[:split]) == ([], 0)
    records, consumed = scan_postgres_authentication(wire)
    assert consumed == len(wire)
    assert len(records) == 1
    assert records[0].start == 1
    assert records[0].material["authentication_method"] == 3


def test_invalid_postgres_authentication_resets_preceding_cleartext_method():
    wire = auth(3) + auth(99)
    records, consumed = scan_postgres_authentication(wire)
    assert consumed == len(wire)
    assert [record.material["authentication_method"] for record in records] == [3, None]
    subsequent = postgres_passwords(pg(b"p", b"SyntheticOnly\0"), records[-1].material["authentication_method"])
    assert subsequent[0].material["kind"] == "postgres_password_message"
    assert "password" not in subsequent[0].material


@pytest.mark.parametrize("wire,reason", [
    (pg(b"p", b"X" * (MAX_FIELD_BYTES + 1) + b"\0"), "postgres_password_field_limit"),
    (pg(b"p", b"unterminated"), "postgres_cleartext_password_malformed"),
    (pg(b"p", b"two\0strings\0"), "postgres_cleartext_password_malformed"),
])
def test_postgres_known_auth_coverage_limits_are_visible(wire, reason):
    records, consumed = scan_postgres(wire, 3)
    assert consumed == len(wire)
    assert len(records) == 1
    assert records[0].material == {"kind": "cleartext_coverage", "protocol": "postgresql", "reason": reason}


def test_redis_unsupported_quoted_auth_is_visible_and_next_boundary_retained():
    unsupported = b'AUTH "Fake\\nOnly"\r\n'
    valid = resp(b"AUTH", b"SyntheticOnly")
    records, consumed = scan_redis(unsupported + valid)
    assert consumed == len(unsupported + valid)
    assert records[0].material["kind"] == "cleartext_coverage"
    assert records[0].material["reason"] == "redis_auth_unsupported_inline"
    assert records[1].material["password"] == "SyntheticOnly"
