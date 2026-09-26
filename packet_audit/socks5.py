"""Bounded SOCKS5 username/password subnegotiation recognition (RFC 1928/1929).

Only an initial client greeting which offered method 0x02, an initial server
selection of that method, and a complete client authentication request count.
No search is performed inside tunneled traffic or an arbitrary stream tail.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Socks5Auth:
    start: int
    end: int
    username: bytes
    password: bytes


def parse_socks5_auth(client: bytes | bytearray, server: bytes | bytearray) -> Socks5Auth | None:
    """Return one complete initial request, or None for incomplete/other wire data."""
    if len(client) < 3 or len(server) < 2 or server[:2] != b"\x05\x02":
        return None
    method_count = client[1]
    greeting_end = 2 + method_count
    if client[0] != 5 or method_count == 0 or len(client) < greeting_end + 3:
        return None
    if 2 not in client[2:greeting_end]:
        return None
    auth_start = greeting_end
    username_len = client[auth_start + 1]
    username_start = auth_start + 2
    password_len_offset = username_start + username_len
    if client[auth_start] != 1 or username_len == 0 or len(client) <= password_len_offset:
        return None
    password_len = client[password_len_offset]
    password_start = password_len_offset + 1
    auth_end = password_start + password_len
    if password_len == 0 or len(client) < auth_end:
        return None
    return Socks5Auth(
        start=username_start,
        end=auth_end,
        username=bytes(client[username_start:password_len_offset]),
        password=bytes(client[password_start:auth_end]),
    )


def display_value(raw: bytes) -> str | bytes:
    """Preserve binary values losslessly for the evidence writer."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw
