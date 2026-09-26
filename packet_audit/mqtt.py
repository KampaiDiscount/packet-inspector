"""Strict, bounded MQTT 3.1.1/5.0 CONNECT credential parser.

Parses only a complete CONNECT at TCP stream offset zero. MQTT 5 property
sections are walked by their declared lengths and allowed property types; no
search for credential-shaped bytes inside a payload or subsequent PUBLISH.
"""

from __future__ import annotations

from dataclasses import dataclass


MAX_CONNECT_BYTES = 128 * 1024


class MalformedMQTT(ValueError):
    """The initial bytes cannot be a supported MQTT CONNECT packet."""


class MQTTConnectLimit(ValueError):
    """The CONNECT packet exceeds the bounded detector window."""


@dataclass(frozen=True, slots=True)
class MQTTConnect:
    version: int
    frame_end: int
    client_id: str
    username: str | None
    password: bytes | None
    credential_start: int | None
    credential_end: int | None
    authentication_method: str | None = None
    authentication_data: bytes | None = None
    authentication_method_span: tuple[int, int] | None = None
    authentication_data_span: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class _Properties:
    end: int
    authentication_method: str | None = None
    authentication_data: bytes | None = None
    authentication_method_span: tuple[int, int] | None = None
    authentication_data_span: tuple[int, int] | None = None


_CONNECT_PROPERTIES = {
    0x11: "u32",  # Session Expiry Interval
    0x21: "u16",  # Receive Maximum
    0x27: "u32",  # Maximum Packet Size
    0x22: "u16",  # Topic Alias Maximum
    0x19: "bool",  # Request Response Information
    0x17: "bool",  # Request Problem Information
    0x26: "pair",  # User Property; may repeat
    0x15: "string",  # Authentication Method
    0x16: "binary",  # Authentication Data
}
_WILL_PROPERTIES = {
    0x18: "u32",  # Will Delay Interval
    0x01: "bool",  # Payload Format Indicator
    0x02: "u32",  # Message Expiry Interval
    0x03: "string",  # Content Type
    0x08: "string",  # Response Topic
    0x09: "binary",  # Correlation Data
    0x26: "pair",  # User Property; may repeat
}


def _varint(data: bytes | bytearray, pos: int, end: int) -> tuple[int, int] | None:
    value = 0
    multiplier = 1
    for width in range(1, 5):
        if pos >= end:
            return None
        octet = data[pos]
        pos += 1
        value += (octet & 0x7F) * multiplier
        if octet < 0x80:
            if width > 1 and value < 128 ** (width - 1):
                raise MalformedMQTT("non-minimal variable byte integer")
            return value, pos
        multiplier *= 128
    raise MalformedMQTT("variable byte integer exceeds four bytes")


def _field(
    data: bytes | bytearray, pos: int, end: int, *, utf8: bool,
) -> tuple[bytes, str | None, int, int]:
    if pos + 2 > end:
        raise MalformedMQTT("missing length-prefixed field")
    length = int.from_bytes(data[pos:pos + 2], "big")
    start = pos + 2
    after = start + length
    if after > end:
        raise MalformedMQTT("field exceeds declared section")
    raw = bytes(data[start:after])
    if not utf8:
        return raw, None, start, after
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise MalformedMQTT("invalid UTF-8 string") from error
    if "\x00" in decoded:
        raise MalformedMQTT("null in UTF-8 string")
    return raw, decoded, start, after


def _properties(
    data: bytes | bytearray, pos: int, frame_end: int, *, will: bool,
) -> _Properties:
    parsed = _varint(data, pos, frame_end)
    if parsed is None:
        raise MalformedMQTT("missing property length")
    size, cursor = parsed
    end = cursor + size
    if end > frame_end:
        raise MalformedMQTT("properties exceed CONNECT frame")
    allowed = _WILL_PROPERTIES if will else _CONNECT_PROPERTIES
    seen: set[int] = set()
    auth_method: str | None = None
    auth_data: bytes | None = None
    method_span: tuple[int, int] | None = None
    data_span: tuple[int, int] | None = None
    while cursor < end:
        property_start = cursor
        identifier = data[cursor]
        cursor += 1
        kind = allowed.get(identifier)
        if kind is None or (identifier in seen and identifier != 0x26):
            raise MalformedMQTT("unknown or repeated property")
        seen.add(identifier)
        if kind in ("u16", "u32", "bool"):
            width = {"u16": 2, "u32": 4, "bool": 1}[kind]
            if cursor + width > end:
                raise MalformedMQTT("truncated numeric property")
            value = int.from_bytes(data[cursor:cursor + width], "big")
            if kind == "bool" and value not in (0, 1):
                raise MalformedMQTT("invalid boolean property")
            if not will and identifier in (0x21, 0x27) and value == 0:
                raise MalformedMQTT("zero not allowed for this property")
            cursor += width
        elif kind in ("string", "binary"):
            raw, decoded, _, cursor = _field(
                data, cursor, end, utf8=kind == "string",
            )
            if will and identifier == 0x08 and not decoded:
                raise MalformedMQTT("empty response topic")
            if not will and identifier == 0x15:
                auth_method = decoded
                method_span = (property_start, cursor)
            elif not will and identifier == 0x16:
                auth_data = raw
                data_span = (property_start, cursor)
        else:  # UTF-8 user-property name/value pair
            _, _, _, cursor = _field(data, cursor, end, utf8=True)
            _, _, _, cursor = _field(data, cursor, end, utf8=True)
    if not will and 0x16 in seen and 0x15 not in seen:
        raise MalformedMQTT("authentication data without method")
    return _Properties(
        end=end, authentication_method=auth_method,
        authentication_data=auth_data,
        authentication_method_span=method_span,
        authentication_data_span=data_span,
    )


def parse_mqtt_connect(data: bytes | bytearray) -> MQTTConnect | None:
    """Return a complete validated CONNECT; None means more stream bytes needed.

    MalformedMQTT and MQTTConnectLimit distinguish invalid or unsupported
    initial frames so callers do not repeatedly parse later tunneled bytes.
    """
    if not data:
        return None
    if data[0] != 0x10:
        raise MalformedMQTT("not a CONNECT fixed header")
    parsed = _varint(data, 1, len(data))
    if parsed is None:
        return None
    remaining, cursor = parsed
    frame_end = cursor + remaining
    if frame_end > MAX_CONNECT_BYTES:
        raise MQTTConnectLimit("CONNECT exceeds supported frame bound")
    if len(data) < frame_end:
        return None
    if cursor + 10 > frame_end or data[cursor:cursor + 6] != b"\x00\x04MQTT":
        raise MalformedMQTT("invalid MQTT protocol name or variable header")
    version = data[cursor + 6]
    if version not in (4, 5):
        raise MalformedMQTT("unsupported MQTT protocol level")
    flags = data[cursor + 7]
    if flags & 1:
        raise MalformedMQTT("reserved CONNECT flag set")
    will = bool(flags & 0x04)
    will_qos = (flags >> 3) & 3
    if (not will and flags & 0x38) or (will and will_qos == 3):
        raise MalformedMQTT("invalid Will flags")
    username_flag = bool(flags & 0x80)
    password_flag = bool(flags & 0x40)
    if version == 4 and password_flag and not username_flag:
        raise MalformedMQTT("MQTT 3.1.1 requires username with password")
    cursor += 10  # Name, level, flags, and two-byte keepalive.
    connect_properties = _Properties(cursor)
    if version == 5:
        connect_properties = _properties(data, cursor, frame_end, will=False)
        cursor = connect_properties.end
    _, client_id, _, cursor = _field(data, cursor, frame_end, utf8=True)
    assert client_id is not None
    if will:
        if version == 5:
            cursor = _properties(data, cursor, frame_end, will=True).end
        _, topic, _, cursor = _field(data, cursor, frame_end, utf8=True)
        if not topic:
            raise MalformedMQTT("empty Will topic")
        _, _, _, cursor = _field(data, cursor, frame_end, utf8=False)
    username: str | None = None
    credential_start: int | None = None
    credential_end: int | None = None
    if username_flag:
        credential_start = cursor
        _, username, _, cursor = _field(
            data, cursor, frame_end, utf8=True,
        )
        credential_end = cursor
    password: bytes | None = None
    if password_flag:
        password_field_start = cursor
        password, _, _, cursor = _field(
            data, cursor, frame_end, utf8=False,
        )
        if credential_start is None:
            credential_start = password_field_start
        credential_end = cursor
    if cursor != frame_end:
        raise MalformedMQTT("CONNECT contains unclaimed payload bytes")
    return MQTTConnect(
        version=version, frame_end=frame_end, client_id=client_id,
        username=username, password=password,
        credential_start=credential_start, credential_end=credential_end,
        authentication_method=connect_properties.authentication_method,
        authentication_data=connect_properties.authentication_data,
        authentication_method_span=connect_properties.authentication_method_span,
        authentication_data_span=connect_properties.authentication_data_span,
    )


def display_binary(raw: bytes) -> str | bytes:
    """Decode human-readable bytes while preserving invalid UTF-8 losslessly."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
