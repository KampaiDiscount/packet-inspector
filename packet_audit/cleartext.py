"""Bounded, boundary-preserving Redis and PostgreSQL wire recognizers.

Pass data beginning at a known command/message boundary. ``scan_*`` returns
records plus the end of the last completely consumed frame, so callers can keep
a stream cursor without retaining a second payload buffer. An incomplete or
malformed frame stops the walk; recognizers never search inside another frame.
A record proves an observed submission, not successful authentication.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any


MAX_FIELD_BYTES = 8192
MAX_AUTH_MESSAGE_BYTES = 32768
MAX_RESP_ARGUMENTS = 128
MAX_PG_FRAME_BYTES = 16 * 1024 * 1024
UNKNOWN_POSTGRES_METHOD = "method not established without server auth request"


@dataclass(frozen=True, slots=True)
class CleartextRecord:
    start: int
    end: int
    material: dict[str, Any]
    limitations: tuple[str, ...] = ()


def _value(raw: bytes) -> str | bytes:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw  # Evidence writer preserves non-UTF-8 bytes as hex.


def _decimal_line(data: bytes, start: int) -> tuple[int, int] | None:
    end = data.find(b"\r\n", start, start + 13)
    if end < 0:
        return None
    raw = data[start:end]
    if not raw or len(raw) > 10 or not raw.isdigit():
        return None
    return int(raw), end + 2


def _resp_command(data: bytes, start: int) -> tuple[int, list[bytes] | None, bool] | None:
    count_line = _decimal_line(data, start + 1)
    if count_line is None:
        return None
    count, cursor = count_line
    if not 1 <= count <= MAX_RESP_ARGUMENTS:
        return None
    arguments: list[bytes] | None = []
    known_auth_command = False
    for index in range(count):
        if cursor >= len(data) or data[cursor] != ord("$"):
            return None
        length_line = _decimal_line(data, cursor + 1)
        if length_line is None:
            return None
        size, begin = length_line
        end = begin + size
        if end + 2 > len(data) or data[end:end + 2] != b"\r\n":
            return None
        if index == 0 and size <= 5:
            known_auth_command = data[begin:end].upper() in (b"AUTH", b"HELLO")
        if size > MAX_FIELD_BYTES or end + 2 - start > MAX_AUTH_MESSAGE_BYTES:
            arguments = None
        elif arguments is not None:
            arguments.append(data[begin:end])
        cursor = end + 2
    return cursor, arguments, known_auth_command and arguments is None


def _coverage(start: int, end: int, protocol: str, reason: str) -> CleartextRecord:
    return CleartextRecord(start, end, {
        "kind": "cleartext_coverage", "protocol": protocol, "reason": reason,
    }, (reason.replace("_", " "),))


def _inline_arguments(line: bytes) -> list[bytes] | None:
    """Accept simple tokens and matched quotes without speculative unescaping."""
    if len(line) > MAX_AUTH_MESSAGE_BYTES or any(byte < 32 and byte != 9 for byte in line):
        return None
    arguments = []
    cursor = 0
    while cursor < len(line):
        while cursor < len(line) and line[cursor] in b" \t":
            cursor += 1
        if cursor == len(line):
            break
        if line[cursor] in b"\"'":
            quote = line[cursor]
            cursor += 1
            end = line.find(bytes([quote]), cursor)
            if end < 0 or b"\\" in line[cursor:end]:
                return None
            argument = line[cursor:end]
            cursor = end + 1
            if cursor < len(line) and line[cursor] not in b" \t":
                return None
        else:
            begin = cursor
            while cursor < len(line) and line[cursor] not in b" \t":
                cursor += 1
            argument = line[begin:cursor]
            if any(byte in argument for byte in (b"'", b'"', b"\\")):
                return None
        if len(argument) > MAX_FIELD_BYTES or len(arguments) >= MAX_RESP_ARGUMENTS:
            return None
        arguments.append(argument)
    return arguments


def _redis_material(arguments: list[bytes]) -> dict[str, Any] | None:
    if not arguments:
        return None
    command = arguments[0].upper()
    username = password = None
    if command == b"AUTH" and len(arguments) in (2, 3):
        username = arguments[1] if len(arguments) == 3 else b"default"
        password = arguments[-1]
    elif command == b"HELLO" and len(arguments) >= 5 and arguments[1] in (b"2", b"3"):
        cursor = 2
        setname_seen = False
        while cursor < len(arguments):
            option = arguments[cursor].upper()
            if option == b"AUTH" and cursor + 2 < len(arguments) and password is None:
                username, password = arguments[cursor + 1:cursor + 3]
                cursor += 3
            elif option == b"SETNAME" and cursor + 1 < len(arguments) and not setname_seen:
                setname_seen = True
                cursor += 2
            else:
                return None
    if username is None or password is None:
        return None
    return {
        "kind": "redis_auth", "command": "AUTH" if command == b"AUTH" else "HELLO AUTH",
        "username": _value(username), "password": _value(password),
    }


def scan_redis(data: bytes) -> tuple[list[CleartextRecord], int]:
    records: list[CleartextRecord] = []
    cursor = 0
    while cursor < len(data):
        start = cursor
        if data[cursor] == ord("*"):
            parsed = _resp_command(data, cursor)
            if parsed is None:
                break
            cursor, arguments, auth_limit = parsed
            if auth_limit:
                records.append(_coverage(start, cursor, "redis", "redis_auth_field_or_message_limit"))
        elif data[cursor] in b"$!=":
            # Bulk strings may contain arbitrary AUTH-looking bytes. Even if
            # the caller supplies a server-side window, do not inspect them.
            length_line = _decimal_line(data, cursor + 1)
            if length_line is None:
                break
            size, begin = length_line
            end = begin + size
            if end + 2 > len(data) or data[end:end + 2] != b"\r\n":
                break
            cursor, arguments = end + 2, None
        else:
            end = data.find(b"\r\n", cursor)
            if end < 0:
                break
            arguments = _inline_arguments(data[cursor:end])
            if arguments is None:
                if data[cursor:end].lstrip().upper().startswith((b"AUTH ", b"AUTH\t", b"HELLO ", b"HELLO\t")):
                    cursor = end + 2
                    records.append(_coverage(start, cursor, "redis", "redis_auth_unsupported_inline"))
                    continue
                break
            cursor = end + 2
        material = _redis_material(arguments) if arguments is not None else None
        if material is not None:
            records.append(CleartextRecord(start, cursor, material))
        elif arguments and arguments[0].upper() == b"AUTH":
            records.append(_coverage(start, cursor, "redis", "redis_auth_invalid_arguments"))
    return records, cursor


def redis_auth(data: bytes) -> list[CleartextRecord]:
    return [record for record in scan_redis(data)[0] if record.material["kind"] == "redis_auth"]


_FRONTEND_TAGS = frozenset(b"BCDEFHPSXQdcfp")
_BACKEND_TAGS = frozenset(b"RKEANSTDCIZ123nsGtHVWcdv")


def _pg_frame(data: bytes, cursor: int, *, backend: bool) -> tuple[int, int, bytes] | None:
    remaining = len(data) - cursor
    if remaining < 5:
        return None
    if backend and cursor == 0 and remaining >= 10 and data[:2] == b"NR":
        # A refused SSL/GSS upgrade is a standalone N, not a NoticeResponse.
        # Require a complete following authentication frame before accepting
        # that negotiation byte, avoiding guesses from a split N message tag.
        following_length = int.from_bytes(data[2:6], "big")
        if 8 <= following_length <= MAX_AUTH_MESSAGE_BYTES and 2 + following_length <= len(data):
            return 1, 0, b""
    # Startup packets and SSL/GSS negotiation requests have no one-byte tag.
    # Recognizing them lets a full client stream reach its first PasswordMessage.
    if not backend and data[cursor] == 0:
        if remaining < 8:
            return None
        length = int.from_bytes(data[cursor:cursor + 4], "big")
        code = int.from_bytes(data[cursor + 4:cursor + 8], "big")
        startup = code >> 16 == 3 and length >= 9
        special = (code in (80877103, 80877104) and length == 8) or (code == 80877102 and length == 16)
        if not (startup or special) or length > MAX_PG_FRAME_BYTES or length > remaining:
            return None
        if startup and data[cursor + length - 1] != 0:
            return None
        return cursor + length, 0, b""
    tag = data[cursor]
    if tag not in (_BACKEND_TAGS if backend else _FRONTEND_TAGS):
        return None
    length = int.from_bytes(data[cursor + 1:cursor + 5], "big")
    end = cursor + 1 + length
    if length < 4 or length > MAX_PG_FRAME_BYTES or end > len(data):
        return None
    # Only authentication payloads need copying; skip other frames by length.
    wanted = tag == (ord("R") if backend else ord("p"))
    payload = data[cursor + 5:end] if wanted and length <= MAX_AUTH_MESSAGE_BYTES else b""
    return end, tag, payload


def scan_postgres(data: bytes, authentication_method: int | None = None) -> tuple[list[CleartextRecord], int]:
    records: list[CleartextRecord] = []
    cursor = 0
    while cursor < len(data):
        parsed = _pg_frame(data, cursor, backend=False)
        if parsed is None:
            break
        start = cursor
        cursor, tag, payload = parsed
        if tag != ord("p") or authentication_method not in (None, 3):
            continue
        frame_length = cursor - start - 1
        if frame_length > MAX_FIELD_BYTES + 5:
            records.append(_coverage(start, cursor, "postgresql", "postgres_password_field_limit"))
            continue
        if not payload.endswith(b"\0") or b"\0" in payload[:-1]:
            if authentication_method == 3:
                records.append(_coverage(start, cursor, "postgresql", "postgres_cleartext_password_malformed"))
            continue
        value = payload[:-1]
        # MD5 responses use the same PasswordMessage framing, not plaintext.
        if authentication_method is None and re.fullmatch(rb"md5[0-9a-fA-F]{32}", value):
            continue
        if authentication_method == 3:
            material = {"kind": "postgres_cleartext_password", "authentication_method": 3,
                        "password": _value(value)}
            limitations: tuple[str, ...] = ()
        else:
            material = {"kind": "postgres_password_message", "authentication_method": None,
                        "password_message": _value(value)}
            limitations = (UNKNOWN_POSTGRES_METHOD,)
        records.append(CleartextRecord(start, cursor, material, limitations))
    return records, cursor


def postgres_passwords(data: bytes, authentication_method: int | None = None) -> list[CleartextRecord]:
    return [record for record in scan_postgres(data, authentication_method)[0]
            if record.material["kind"] != "cleartext_coverage"]


def scan_postgres_authentication(data: bytes) -> tuple[list[CleartextRecord], int]:
    records: list[CleartextRecord] = []
    cursor = 0
    names = {0: "ok", 2: "kerberos_v5", 3: "cleartext", 5: "md5", 6: "scm", 7: "gss",
             8: "gss_continue", 9: "sspi", 10: "sasl", 11: "sasl_continue", 12: "sasl_final"}
    while cursor < len(data):
        parsed = _pg_frame(data, cursor, backend=True)
        if parsed is None:
            break
        start = cursor
        cursor, tag, payload = parsed
        if tag != ord("R"):
            continue
        method = int.from_bytes(payload[:4], "big") if len(payload) >= 4 else None
        valid = method in names
        if method in (0, 2, 3, 6, 7, 9) and len(payload) != 4:
            valid = False
        if method == 5 and len(payload) != 8:
            valid = False
        if method in (8, 11, 12) and len(payload) <= 4:
            valid = False
        if method == 10:
            mechanisms = payload[4:]
            if not mechanisms.endswith(b"\0\0"):
                valid = False
            items = mechanisms[:-2].split(b"\0")
            if not items or any(not item or len(item) > 128 or not all(33 <= c <= 126 for c in item) for item in items):
                valid = False
        if not valid:
            records.append(CleartextRecord(start, cursor, {
                "kind": "postgres_authentication_request", "authentication_method": None,
                "authentication_name": "invalid", "coverage_reason": "postgres_authentication_invalid",
            }, ("invalid or unsupported server authentication request; previous method invalidated",)))
            continue
        records.append(CleartextRecord(start, cursor, {
            "kind": "postgres_authentication_request", "authentication_method": method,
            "authentication_name": names[method],
        }))
    return records, cursor


def postgres_authentication_requests(data: bytes) -> list[CleartextRecord]:
    return scan_postgres_authentication(data)[0]
