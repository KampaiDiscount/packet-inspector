"""Bounded HTTP/1 framing and typed login-field extraction.

The framer retains offsets only. Payload retention belongs to the detector's
existing byte-accounted tail. It never guesses that the end of a TCP segment
ends a body. Unsupported/ambiguous framing is counted rather than interpreted.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import re
from urllib.parse import unquote_plus

_REQUEST = re.compile(rb"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) ([^\r\n ]{1,8192}) HTTP/1\.[01]\r\n")
_REQUEST_AT = re.compile(rb"(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) ([^\r\n ]{1,8192}) HTTP/1\.[01]\r\n")
_MAX_HEADER = 32768
_MAX_FIELDS = 256
# Canonical spellings, not substring rules. See LOGIN_FIELDS.md for primary
# sources and coverage boundaries. Tables are built once, never per packet.
_PASSWORD_BASES = frozenset({"password", "passwd", "passw", "pwd", "pass", "passphrase"})
_PASSWORD_FIELD_NAMES = frozenset(
    {prefix + base + suffix
     for prefix in ("", "old", "new", "current", "confirm", "repeat", "retype", "user", "login", "account")
     for base in _PASSWORD_BASES
     for suffix in ("", "1", "2")}
    | {"passwordconfirmation", "passwordconfirm", "passwordagain", "passwordnew", "passwordold",
       "confirmnewpassword", "tfupass"}
)
_CONTROL_PREFIXES = ("txt", "tb", "tf", "input", "inp")
_PASSWORD_FIELD_NAMES |= frozenset(prefix + base for prefix in _CONTROL_PREFIXES for base in _PASSWORD_BASES)
_IDENTITY_FIELD_NAMES = frozenset({
    "username", "user", "userid", "uid", "uname", "usr", "userlogin", "log",
    "email", "emailaddress", "mail", "loginemail", "loginid", "loginname",
    "accountname", "accountid", "membername", "memberid", "screenname",
    "tfuname", "tfuser",
})
_IDENTITY_FIELD_NAMES |= frozenset(prefix + base for prefix in _CONTROL_PREFIXES
                                 for base in ("username", "user", "userid", "uname", "email"))
# Weak identifiers are context only and never override a stronger identity.
# In particular a submit control named "login" must not mask "username".
_WEAK_IDENTITY_FIELD_NAMES = frozenset({"name", "login", "account", "identifier", "identity"})
_AUTH_CODE_FIELD_NAMES = frozenset({"otp", "totp", "otpcode", "totpcode", "onetimepassword",
                                  "onetimecode", "mfacode", "twofactorcode", "verificationcode"})
_NORMALIZED_SECRET_FIELD_NAMES = frozenset({"accesstoken", "refreshtoken", "idtoken", "apikey",
                                          "clientsecret", "privatekey", "sessionid"})
_FIELD_PARTS = re.compile(r"[^a-z0-9]+")
_FIELD_PATH = re.compile(r"[\[\].$/:\\]+")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NUMBERED_FIELD = re.compile(r"[0-9]{1,3}$")
_JSON_FIELD = re.compile(rb'("(?:[^"\\\x00-\x1f]|\\.)*")\s*:\s*("(?:[^"\\\x00-\x1f]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)')


@dataclass(slots=True)
class Field:
    name: str
    value: str
    encoded: str
    start: int
    end: int


@dataclass(slots=True)
class Message:
    start: int
    header_end: int
    end: int
    target: bytes
    target_start: int
    content_type: str
    body: bytes
    # Decoded range and its corresponding wire start, all message-relative.
    body_spans: tuple[tuple[int, int, int], ...]
    complete: bool = True
    encoded_content: bool = False

    def wire_span(self, start: int, end: int) -> tuple[int, int]:
        first = next((wire + start - left for left, right, wire in self.body_spans if left <= start < right), self.header_end)
        last = next((wire + end - left for left, right, wire in self.body_spans if left < end <= right), first)
        return first, last


@dataclass(slots=True)
class HTTPFramer:
    cursor: int | None = None
    recognized: bool = False
    blocked: bool = False
    unframed_start: int | None = None
    last_unframed_end: int = -1
    search_end: int = 0

    def scan(self, data: bytes | bytearray, base: int, limit: int, stats: Counter[str]) -> list[Message]:
        result: list[Message] = []
        available_end = base + len(data)
        if self.blocked:
            return result
        if self.cursor is not None and self.cursor < base:
            stats["http_framing_tail_lost"] += 1
            # Lost framing cannot safely be recovered by interpreting arbitrary
            # body text as a request. A new TCP connection starts a new framer.
            self.blocked = True
            return result
        if self.cursor is None:
            search_start = max(0, self.search_end - base - 8192)
            match = _REQUEST.search(data, search_start)
            self.search_end = available_end
            if match is None:
                return result
            self.cursor = base + match.start()
            self.recognized = True
        while self.cursor < available_end:
            start = self.cursor - base
            match = _REQUEST_AT.match(data, start)
            if match is None:
                # A split next request line is allowed; a complete invalid one
                # is not a reason to guess a new body boundary.
                if data.find(b"\n", start) >= 0 or available_end - self.cursor > _MAX_HEADER:
                    stats["http_framing_invalid_request"] += 1
                    self.blocked = True
                break
            header_end = data.find(b"\r\n\r\n", match.end() - 2)
            if header_end < 0:
                if available_end - self.cursor > _MAX_HEADER:
                    stats["http_framing_header_limit"] += 1
                    self.blocked = True
                break
            header_end += 4
            if header_end - start > _MAX_HEADER:
                stats["http_framing_header_limit"] += 1
                self.blocked = True
                break
            headers: dict[bytes, list[bytes]] = {}
            valid = True
            for line in bytes(data[match.end():header_end - 2]).split(b"\r\n"):
                if not line:
                    continue
                if line[:1] in (b" ", b"\t") or b":" not in line:
                    valid = False
                    break
                key, value = line.split(b":", 1)
                if not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
                    valid = False
                    break
                headers.setdefault(key.lower(), []).append(value.strip())
            lengths = headers.get(b"content-length", [])
            transfer = headers.get(b"transfer-encoding", [])
            if not valid or (lengths and transfer) or len(lengths) > 1 or len(transfer) > 1:
                stats["http_framing_ambiguous"] += 1
                self.blocked = True
                break
            content_type = headers.get(b"content-type", [b""])[0].split(b";", 1)[0].strip().decode("latin-1").lower()
            encoded = headers.get(b"content-encoding", [b"identity"])[0].lower() not in (b"", b"identity")
            spans: tuple[tuple[int, int, int], ...]
            if transfer:
                if transfer[0].lower() != b"chunked":
                    stats["http_framing_unsupported_transfer_encoding"] += 1
                    self.blocked = True
                    break
                decoded = _chunked(data, header_end, start, limit)
                if decoded is None:
                    if available_end - self.cursor > limit:
                        stats["http_framing_body_limit"] += 1
                        self.blocked = True
                    break
                if isinstance(decoded, str):
                    stats["http_framing_" + decoded] += 1
                    self.blocked = True
                    break
                body, spans, end = decoded
            elif lengths:
                raw_length = lengths[0]
                if not raw_length.isdigit() or len(raw_length) > 10:
                    stats["http_framing_invalid_length"] += 1
                    self.blocked = True
                    break
                length = int(raw_length)
                end = header_end + length
                if end - start > limit:
                    stats["http_framing_body_limit"] += 1
                    self.cursor = base + end
                    continue
                if end > len(data):
                    break
                body = bytes(data[header_end:end])
                spans = ((0, len(body), header_end - start),)
            elif match.group(1) in (b"POST", b"PUT", b"PATCH") and content_type:
                # Legacy/malformed samples without a body length remain
                # delimiter-only evidence. They are NEVER considered complete
                # forms; this also preserves old snippet scanning semantics.
                if self.unframed_start != self.cursor:
                    stats["http_framing_missing_body_length"] += 1
                    self.unframed_start = self.cursor
                following = _REQUEST.search(data, header_end)
                end = following.start() if following else len(data)
                if base + end > self.last_unframed_end:
                    result.append(Message(start, header_end - start, end - start, bytes(match.group(2)), match.start(2) - start, content_type, bytes(data[header_end:end]), ((0, end - header_end, header_end - start),), False, encoded))
                    self.last_unframed_end = base + end
                if following:
                    self.cursor = base + end
                    continue
                break
            else:
                end = header_end
                body, spans = b"", ()
            result.append(Message(start, header_end - start, end - start, bytes(match.group(2)), match.start(2) - start, content_type, body, spans, True, encoded))
            stats["http_framed_requests"] += 1
            self.cursor = base + end
        return result


def _chunked(data: bytes | bytearray, pos: int, start: int, limit: int):
    body = bytearray()
    spans: list[tuple[int, int, int]] = []
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end < 0:
            return None
        if line_end - pos > 1024 or len(spans) >= 4096:
            return "chunk_limit"
        length_text = bytes(data[pos:line_end]).split(b";", 1)[0]
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,8}", length_text):
            return "invalid_chunk"
        length = int(length_text, 16)
        pos = line_end + 2
        if length == 0:
            if data[pos:pos + 2] == b"\r\n":
                return bytes(body), tuple(spans), pos + 2
            trailers_end = data.find(b"\r\n\r\n", pos)
            if trailers_end < 0:
                return None
            if trailers_end + 4 - start > limit:
                return "body_limit"
            return bytes(body), tuple(spans), trailers_end + 4
        if pos + length + 2 - start > limit:
            return "body_limit"
        if pos + length + 2 > len(data):
            return None
        if data[pos + length:pos + length + 2] != b"\r\n":
            return "invalid_chunk"
        spans.append((len(body), len(body) + length, pos - start))
        body.extend(data[pos:pos + length])
        pos += length + 2


def form_fields(data: bytes, *, complete: bool = True) -> list[Field]:
    result: list[Field] = []
    for match in re.finditer(rb"(?:^|[&;])([^=&;]{1,256})=([^&;]{0,8192})", data):
        raw = match.group(2)
        if match.end() < len(data) and data[match.end()] not in (38, 59):
            continue
        if not complete and match.end() == len(data) and not re.search(rb"\s", raw):
            continue
        # In delimiter-only mode, whitespace is an observed terminator.
        if not complete:
            raw = re.split(rb"\s", raw, maxsplit=1)[0]
        name = unquote_plus(match.group(1).decode("utf-8", "replace"))
        encoded = raw.decode("utf-8", "replace")
        result.append(Field(name, unquote_plus(encoded), encoded, match.start(2), match.start(2) + len(raw)))
        if len(result) >= _MAX_FIELDS:
            break
    return result


def json_fields(data: bytes) -> list[Field]:
    # Reject excessive nesting before calling the stdlib decoder. This keeps
    # malicious input from consuming the interpreter recursion budget.
    depth = 0
    in_string = escaped = False
    for value in data:
        if in_string:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                in_string = False
        elif value == 34:
            in_string = True
        elif value in (91, 123):
            depth += 1
            if depth > 32:
                raise ValueError("JSON nesting limit")
        elif value in (93, 125):
            depth -= 1
    json.loads(data)
    result: list[Field] = []
    for match in _JSON_FIELD.finditer(data):
        name = json.loads(match.group(1))
        value = json.loads(match.group(2))
        if value is None or isinstance(value, bool):
            continue
        result.append(Field(name, str(value), match.group(2).decode("utf-8"), match.start(2), match.end(2)))
        if len(result) >= _MAX_FIELDS:
            break
    return result


def field_role(name: str, sensitive_names: set[str]) -> str | None:
    lowered = name.lower()
    if lowered in sensitive_names:
        return "sensitive"
    parts = [part for part in _FIELD_PARTS.split(lowered) if part]
    normalized = "".join(parts)
    leaf = parts[-1] if parts else ""
    path = [part for part in _FIELD_PATH.split(lowered) if part]
    path_leaf = "".join(_FIELD_PARTS.split(path[-1])) if path else ""
    camel_parts = _FIELD_PARTS.split(_CAMEL_BOUNDARY.sub("_", name).lower())
    camel_leaf = next((part for part in reversed(camel_parts) if part), "")
    candidates = (normalized, leaf, path_leaf, camel_leaf)
    # Respect nested/container names, but do not interpret a sensitive ancestor
    # as its unrelated child: password_policy and password[enabled] are not
    # password values. Preserve exact operator-configured names above.
    if (leaf in sensitive_names or camel_leaf in sensitive_names
            or any(value in _PASSWORD_FIELD_NAMES or _NUMBERED_FIELD.sub("", value) in _PASSWORD_FIELD_NAMES
                   or value in _AUTH_CODE_FIELD_NAMES or value in _NORMALIZED_SECRET_FIELD_NAMES
                   for value in candidates)):
        return "sensitive"
    if any(value in _IDENTITY_FIELD_NAMES for value in candidates):
        return "username"
    if normalized in _WEAK_IDENTITY_FIELD_NAMES or (len(path) > 1 and path_leaf in _WEAK_IDENTITY_FIELD_NAMES):
        return "username_weak"
    return None
