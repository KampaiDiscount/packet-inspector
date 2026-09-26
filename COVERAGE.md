# Protocol coverage: Packet Inspector

Coverage describes wire formats, not a guarantee that every login is visible.
The sensor needs the relevant traffic, both directions for correlation, and
complete bytes within configured retention/reassembly limits. A network path,
capture filter, missing packet, encryption, or unsupported encoding can prevent
extraction. An SMB login does not necessarily use NTLM.

| Family | Implemented detection | Important boundaries |
| --- | --- | --- |
| SMB / NTLM | Raw NTLM Type 2/3, NetNTLMv1/v2 exports; direct-TCP SMB2/3 SESSION_SETUP session IDs keep concurrent sessions separate | Clear authentication exchange required. SMB1 and other raw wrappers have flow/direction correlation, not their own session dissectors. No SMB encrypted/compressed transform decoding or cross-connection/multichannel authentication correlation. |
| HTTP NTLM | Direct NTLM and bounded ASN.1 SPNEGO NegTokenInit/NegTokenResp in authentication headers | No Kerberos-to-NTLM conversion, HTTPS decryption, or arbitrary ASN.1 search. |
| Mail NTLM | Complete base64 NTLM/SPNEGO tokens in SMTP/POP3/IMAP lines on 25/587/110/143 | 16 KiB encoded token limit; not encrypted SMTP/IMAP/POP3 sessions. |
| LDAP | BER simple bind credentials; embedded raw NTLM in SASL exchanges | Does not decode every SASL mechanism, signed/sealed application data, or LDAPS. Repeated binds are separately emitted. |
| HTTP cleartext | Basic, form/query fields, typed JSON secrets, cookies, Bearer, Digest | HTTP/1 framing. See LOGIN_FIELDS.md. No deep HTTP/2, multipart, or compressed body decoding. |
| HTTP file signatures | PNG, JPEG, GIF, WebP, PDF and ZIP magic at the start of clear HTTP/1 request/response bodies | Content-Length framing and a bounded prefix are required. This is a file-type observation, not proof that the transfer completed or the application accepted it. |
| FTP / POP3 | USER/PASS correlation | Clear command channel only. |
| SMTP | AUTH PLAIN and LOGIN, including multistep forms | No TLS or every SASL mechanism. |
| IMAP | LOGIN, AUTHENTICATE PLAIN/LOGIN | Not a complete IMAP literal/extension implementation. |
| Redis | RESP AUTH, HELLO AUTH, simple/matched-quote inline AUTH, username and password | Port 6379; bounded fields/frames; escaped inline forms are not guessed. |
| PostgreSQL | PasswordMessage; confirmed cleartext when server requests method 3 | Port 5432; otherwise method-unknown candidate. MD5/SASL responses are not labeled plaintext. No username pairing yet. |
| MQTT | MQTT 3.1.1 and 5.0 CONNECT Password field with optional User Name; MQTT 5 nonempty Authentication Method/Data property candidate; validates fixed header, remaining length, flags, payload order and CONNECT/Will properties | Initial clear TCP CONNECT on port 1883 only, complete within 128 KiB. The method-defined Authentication Data candidate is not labeled a password or successful login. No TLS, WebSocket, subsequent AUTH exchange or arbitrary later-packet search. |
| SOCKS5 | RFC 1929 username/password submission after a complete offered-and-selected method 0x02 handshake | TCP port 1080; both initial stream directions and the complete request must be captured. No encrypted tunnel decoding or authentication-result claim. |
| MSSQL | TDS Login7 deobfuscation | Not TLS, TDS8 encryption, or arbitrary multi-packet TDS framing. |
| SNMP | v1/v2c communities | Not SNMPv3 decryption. |
| IRC / Telnet-like | Registration secrets and recognizable login/password fields | Telnet prompt/field patterns, not a full negotiated terminal/keystroke reassembler. |
| Other authentication | Kerberos AS-REQ etype 23 and SIP Digest when required fields are present | Not universal Kerberos, RADIUS, EAP or VPN decoding. |
| Generic secrets | Named secret fields, selected tokens, JWTs, PEM private keys and Luhn-valid card candidates | Candidates are not validity or successful-authentication claims. |

An explicit HTTP Bearer header is recognized even when the value is short,
within the bounded 8 KiB header-token limit. All observed HTTP cookies remain
visible; a cookie is marked as a session candidate only when its name matches
a known session-token pattern. Compact JWT candidates require base64url JSON
object header/payload structure. Signed three-part candidates have structural
confidence only; valid unsecured `alg:none` candidates with an empty signature
have medium confidence. Signatures, issuers, expiry, and current usability are
not verified. Five-part JWE and tokens beyond the bounded segment/window limits
are not classified as JWTs by this detector.

At an observed TCP stream origin, a complete TLS ClientHello/ServerHello or
ApplicationData record identifies an opaque encrypted flow. Cleartext credential
scanners then skip both directions, and `tls_opaque_flows`,
`tls_opaque_midstream_flows` and `tls_opaque_chunks` count this as informational
telemetry. The raw capture ring remains available. These counters do not make a
capture verdict incomplete by themselves because TLS decryption is outside the
configured inspection scope. The detector does not decrypt TLS. If observation
begins inside a TLS record, or a cleartext connection upgrades to TLS later
(such as STARTTLS), this origin check may miss the transition; ciphertext must
not be treated as confirmed cleartext authentication without protocol review.

The table deliberately does not claim "all protocols." Dedicated MySQL
mysql_clear_password, PostgreSQL SCRAM/MD5 export, RADIUS/PAP,
AMQP/SASL, XMPP SASL, and full Telnet handling are not
implemented/qualified here. These are potential additions, not advertised
coverage. Protocols on nonstandard ports need a dedicated test before relying
on the port-gated detectors.

MQTT CONNECT detection requires the first complete control packet of a TCP
connection to be a structurally valid MQTT 3.1.1 or 5.0 CONNECT. MQTT 5 permits
a Password without a User Name; MQTT 3.1.1 does not. A present zero-length
Password is still recorded. A nonempty MQTT 5 CONNECT Authentication Data
property is exported separately with its Authentication Method at medium
confidence. The method defines its meaning: it may be a public nonce or
challenge, not a secret. An absent or empty Authentication Data property does
not create this candidate. Subsequent AUTH/CONNACK exchanges and authentication
outcomes are not interpreted. MQTT 5 CONNECT and Will properties are bounded and
validated before the payload fields are read. Frames over 128 KiB, malformed
or missing initial framing, and missing stream origins are visible in
`coverage_mqtt_connect_*` counters; these cases are not treated as detected
credentials. A CONNECT Password is binary data and can be an opaque token.

SOCKS5 detection requires the initial client greeting to offer username/password
method 0x02, the initial server selection to choose it, and a complete RFC 1929
client request. It does not search later tunneled bytes for a coincidental
credential-shaped sequence, nor infer a password from an unobserved handshake.
The wire format permits 1–255 octets each for username and password. The
detector reports submitted bytes; a server success or failure response does
not change the submission evidence.

HTTP file-signature findings record the observed type, request/response role,
declared length, bounded MIME type and, when present, a sanitized basename.
Their packet IDs point to the bytes carrying the magic signature. They do not
store the file body. The existing detector tail still holds a bounded transient
window, and the independently configured raw PCAP ring can retain the original
body; this feature does not alter those policies. Once a binary signature is
verified, general credential scanners do not interpret that framed file body
as a login or token. This may also omit a real secret embedded inside a file.

The transfer tracker supports clear HTTP/1 Content-Length bodies, including
files larger than the detector tail because it inspects a prefix without
buffering the whole body. Multipart inspection is limited to the first part's
first 2 KiB. A 206 response is classified only when a valid Content-Range
begins at byte zero and is explicitly marked partial. Chunked bodies,
close-delimited/unframed bodies, compressed content, HTTP/2, HTTP/3, TLS and
nonzero-range partial responses are not file-type qualified by this tracker;
visible unsupported framing and prefix limits increment `http_transfer_*`
coverage counters and make the replay/session verdict incomplete.

The default capture filter admits IPv4/IPv6 and recognized outer VLAN tags
(802.1Q, 802.1ad, 0x9100 and 0x9200) on Ethernet and Linux cooked links. The
decoder then checks up to eight stacked tags and processes only inner IP. The
filter deliberately includes non-IP traffic inside those VLANs, which the
decoder discards; qualify the resulting capture load on the target host.

## Correlation and bounds

SMB2 session scoping validates the enclosing SESSION_SETUP security-buffer
offset/length and direct-TCP header. It uses already-retained stream data, not
an unbounded session cache. Its challenges share the existing per-flow and
global NTLM budgets. If a recognized SMB2 flow loses session framing, raw Type
2/3 evidence is exported with a limitation; a paired hash is not guessed and a
coverage counter marks the session incomplete. Unscoped raw NTLM correlation
outside the SMB2 parser assumes sequential exchanges within one TCP epoch.
Some test listeners leave SMB2 SessionId at zero. A sole challenge and response
can still be associated within one TCP connection, with reduced confidence and
an explicit limitation. Competing zero-ID challenges are left unpaired while raw
Type 2/3 evidence and a coverage counter remain available.

Redis and PostgreSQL use persistent frame-boundary cursors, so ordinary tail
rotation does not rescan nested values as commands. Fields are bounded to
8 KiB and authentication messages to 32 KiB. If an unfinished frame exceeds
retained data, that direction is marked coverage-incomplete until a new
connection; the parser does not invent a resynchronization point inside a value.
Oversized/unsupported recognized auth records are reported as coverage limits.

Distinct protocol retries are retained. TCP retransmission of the same stream
bytes is not an additional authentication attempt. NetNTLM material is a
challenge/response, not a plaintext password or the account's reusable NT hash.

## Primary protocol references

- [Microsoft SMB2 authentication relationship](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/06451bf2-578a-4b9d-94c0-8ce531bf14c4)
- [SMB2 SESSION_SETUP response](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/0324190f-a31b-4666-9fa9-5c624273a694)
- [SMB2 SESSION_SETUP request](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f)
- [SPNEGO ASN.1 definitions, RFC 4178](https://www.rfc-editor.org/rfc/rfc4178.html)
- [Redis AUTH](https://redis.io/docs/latest/commands/auth/), [HELLO](https://redis.io/docs/latest/commands/hello/)
- [PostgreSQL message formats](https://www.postgresql.org/docs/current/protocol-message-formats.html)
- [MQTT 3.1.1 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html), [MQTT 5.0 OASIS Standard](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html)
- [SOCKS5 method negotiation, RFC 1928](https://www.rfc-editor.org/rfc/rfc1928.html), [username/password subnegotiation, RFC 1929](https://www.rfc-editor.org/rfc/rfc1929.html)
- [TLS 1.2 record layer, RFC 5246](https://www.rfc-editor.org/rfc/rfc5246.html), [TLS 1.3 record layer, RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)
