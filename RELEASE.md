# Packet Inspector / Packet Audit 0.1.7 test prerelease

Package release date: 2026-09-26.

- Prevents a duplicate copy of each unfragmented TCP/UDP payload from crossing
  the worker queue. Necessary literal and BER-tag prefilters avoid expensive
  HTTP and LDAP parsing on unrelated binary bytes without suppressing their
  supported signatures.
- Raises the bounded defaults to 1,024 batch slots and 128 MiB of captured
  bytes per worker. Queue-slot, byte-budget, occupancy and capture-loop timing
  counters expose pressure; overload still forces an incomplete verdict.
- A controlled Win11-to-Linode 48 MiB HTTP transfer through the Kali ARP path
  exposed live-analysis queue loss in 0.1.6. The fixed build captured and
  dispatched 87,144 packets with zero reported capture or analysis drops, zero
  parser errors and a complete final verdict. Its 40 test-flow findings matched
  a replay of the new independent PCAP by detector and observed time. Separate
  strict replays of the original 85,656-frame stress capture, the new capture,
  and the earlier 188-frame qualification capture passed their expected counts.

Existing installations retain explicit queue settings in `/etc`. Installing
0.1.7 alone does not enlarge those settings: back up and review the host config
before adopting the new bounds. This finite burst result is not a sustained
line-rate or universal-protocol guarantee. A worker took about 10 seconds to
drain traffic recorded over 6.9 seconds; a longer burst can still overflow.
Retain and monitor the independent raw PCAP ring for recovery within its
configured retention window.

---

# Historical Packet Inspector / Packet Audit 0.1.6 test prerelease

Package release date: 2026-09-26.

- Recognizes PNG, JPEG, GIF, WebP, PDF and ZIP file signatures in bounded,
  clear HTTP/1 request and response bodies, with packet provenance and only
  file-type/header metadata in findings. The raw PCAP ring remains independent.
- Excludes verified binary file bodies from credential-text classification,
  preventing incidental bytes in an image from appearing as a login or token.
- Recognizes short explicit Bearer values, distinguishes ordinary cookies from
  session-name candidates, and validates bounded compact JWT structure before
  issuing a high-confidence label. Token validity and signatures are not tested.
- Replays the actual lab PNG transfer and prior SMB/authentication captures,
  in addition to unit, segmentation, false-positive and performance checks.

File signatures are observations of a prefix, not proof of a completed
transfer. This tracker does not decode encrypted, compressed, chunked,
HTTP/2/3, or most multipart content. A real secret embedded inside a file is
not inspected by generic text scanners once the binary body is verified. See
[COVERAGE.md](COVERAGE.md) for exact boundaries and health counters.

---

# Historical Packet Inspector / Packet Audit 0.1.5 test prerelease

Package release date: 2026-09-26.

- Fixes NetNTLMv1/v2 correlation for SMB2 listeners that retain a zero
  SessionId through SESSION_SETUP, while refusing to guess between competing
  zero-ID challenges. Raw challenge/response evidence remains available.
- Preserves all packets in bounded offline replay by waiting for worker queue
  capacity. Live capture continues to report overload rather than blocking.
- Captures recognized outer VLAN tags by default on Ethernet and Linux cooked
  links, so tagged IPv4/IPv6 can reach both analysis and the raw ring.
- Ignores acknowledged one-byte TCP keepalive probes when reporting stream
  overlap conflicts, while retaining alerts for conflicting payload bytes.
- Keeps HTTP form and text-body login evidence in HTTP-specific categories,
  avoids calling bare login lines HTTP or Telnet without matching framing, and
  does not treat the `Negotiate` authentication scheme name as a secret.
- Validated against the controlled NXC-to-Responder capture, synthetic
  concurrency/fragmentation/ambiguity cases, native libpcap VLAN fixtures and
  the Kali test suite. Live synthetic HTTP and non-HTTP flows checked detector
  output against the actual packets and transport endpoints. The zero-ID pair
  has reduced confidence because the listener did not provide a unique session
  identifier.

Existing Kali installations retain an explicit `bpf` setting. Change the old
`ip or ip6` setting to the 0.1.5 default after backing up the configuration;
installing the package alone does not alter it. Encrypted, out-of-path, and
unsupported protocols remain outside this release's coverage. Host-specific
live traffic and sustained-load qualification remain required.

---

# Historical Packet Inspector / Packet Audit 0.1.4 test prerelease

Package release date: 2026-09-17. Runtime fix committed: 2026-09-16.

- Uses bounded native `next()` reads to prevent a callback-binding failure
  from consuming and silently skipping captured packets.
- Rejects malformed records and callback count mismatches visibly.
- Adds native libpcap offline regression coverage across batch boundaries,
  including payload bytes, packet IDs, timestamps and wire lengths.
- Publishes the source distribution, Python wheel and SHA-256 manifest.
- Adds package project links and complete source-install/download guidance.

The source distribution includes the Kali installer and supporting systemd,
configuration, documentation and test files. The wheel contains the Python
engine; it is not a standalone host installer and does not bundle `pcapy-ng`,
libpcap or `dumpcap`. Python 3.11+ and target-host dependencies are required.

This is a test prerelease. Automated regression checks and native offline
binding tests do not establish live NIC performance, sustained-load coverage,
systemd recovery or hardware qualification. Run the acceptance checks in
[RELIABILITY.md](RELIABILITY.md) on the intended sensor. Existing deployments
are not automatically upgraded by publishing these packages.

---

# Historical Packet Inspector / Packet Audit 0.1.3 release notes

Release date: 2026-09-16

- Nonblocking live capture and main-loop-driven external systemd watchdog.
- Fixed repeated LDAP binds beyond the first 64 bytes of a scan window.
- SMB2 session-scoped NTLM correlation, including concurrent sessions.
- HTTP SPNEGO and mail-protocol base64 NTLM wrappers.
- Bounded Redis AUTH/HELLO AUTH and PostgreSQL password-message coverage.
- Expanded synthetic replay/fault tests and Linux Python 3.11/3.13 CI gates.
- Explicit protocol coverage and live-host qualification documents.

This build is not a universal-protocol or lossless-capture guarantee. Native
live-host latency, saturation, restart and long-soak qualification remain
separate acceptance gates. Existing deployed installations are not upgraded
merely by publishing this source.

---

# Historical Packet Audit 0.1.2 release notes

Release date: 2026-09-16

- Source-backed HTTP login identity/password families documented in LOGIN_FIELDS.md.
- Testfire uid/passw, WordPress log/pwd, Drupal name/pass, Roundcube _user/_pass,
  framework prefixes, nested fields, case/separator/camelCase variants.
- Password-change and explicit OTP/MFA-code candidates; no authentication-success claim.
- Weak identity hints cannot override explicit username/email fields. Equally
  preferred multiple identities remain unpaired; username-only data is not a secret.
- Whole/terminal-component matching avoids unrelated password-policy/count fields.
- One classification per parsed field, bounded tables, unchanged retry handling.
- Includes the operator-requested token-free loopback dashboard mode. CLI token
  mode remains available; shipped systemd web service uses --no-auth.

Existing evidence/configuration are preserved during deployment. Encrypted or
unsupported body formats remain outside the documented coverage. This is not
a measured global field-name popularity ranking or a lossless-capture guarantee.

---

# Historical Packet Audit 0.1.1 release notes

Release date: 2026-09-16

## Immediate login and visibility fixes

- Bounded HTTP/1 request framing for Content-Length and chunked requests.
- Complete final form fields are recognized without requiring a trailing delimiter.
- Common nonstandard password fields, including `tfUPass`, and typed JSON secrets.
- Companion username context when unambiguous; no authentication-success claim.
- Split packets, pipelining, repeated attempts, and provenance regression coverage.
- Separate source/destination IP and port fields in new findings.
- Independent authenticated localhost-only live dashboard with search, health,
  legacy endpoint support, bounded reads, safe text rendering, and private token.
- Installer `--skip-system-deps`, active-service upgrade refusal, readable code
  permissions, and independent hardened dashboard unit.

The dashboard is read-only and does not control capture. Its recent-history
limits do not suppress evidence exports. Access remotely through an SSH tunnel,
not a public bind. Neither service is automatically enabled at boot.

Correctly encrypted HTTPS/TLS/QUIC is not decrypted. HTTP/2, multipart and
compressed request bodies remain outside typed form coverage. Limits and
unsupported framing are visible in HTTP detector health counters; see README.

Validation includes synthetic split/pipeline/retry tests, end-to-end worker
replay, dashboard authentication/XSS/read-bound tests, and native Kali checks.
Synthetic test rates are regression evidence, not a promise of lossless capture
at every load. Validate capture health on the intended deployment host.

---

# Historical Packet Audit 0.1.0 release notes

Release date: 2026-08-27

## Outcome

Packet Audit is a Kali-first live packet-audit sensor with an offline replay
path for tests and raw-ring recovery. The live supervisor keeps packet capture,
bounded parsing, and flow-affine dispatch short; worker processes perform IP/TCP
reconstruction and sensitive-material detection; one restricted writer appends
unredacted JSONL; and an independent rotating `dumpcap` PCAPNG ring preserves
recent frames.

Credential retries at new stream offsets or in new TCP connection epochs are
never suppressed. Exact retransmitted bytes at an already-consumed TCP sequence
position are treated as transport mechanics, not fabricated login attempts.

## Release hardening

- Per-worker queues are bounded by both batch count and an atomic 64 MiB
  captured-payload reservation. Count- and byte-budget drops are separately
  reported and force an incomplete verdict.
- TCP, fragment, detector-tail, metadata, provenance, NTLM correlation, and
  multi-step SMTP/IMAP/FTP-POP state all have explicit global and per-flow
  bounds. Cap pressure, eviction, trimming, or correlation loss is visible.
- Findings carry exact contributing packet IDs for retained byte spans.
  `packet_ids_complete=false` and limitations make bounded or missing
  provenance explicit.
- Final worker PIDs and the writer must acknowledge durable shutdown. Packet,
  finding, queue-byte, child-state, and available capture-drop counts must agree
  for a complete verdict.
- Evidence parents are private real directories, JSONL files are mode `0600`,
  symlink and same-inode/hardlink destinations are rejected, and a non-newline
  partial tail fails closed. The read-only doctor enforces the same invariants.
- The source manifest includes the Kali installer, doctor, systemd unit,
  configuration, tests, benchmark, notices, and release notes. Runtime binding
  behavior is pinned to `pcapy-ng==1.1.0`.

## Release verification

- 135 deterministic tests passed. Six POSIX permission/symlink cases were
  skipped on the Windows development host; the corresponding implementation
  paths remain target-host release gates.
- Coverage includes packet decoding, IPv4/IPv6 fragments, TCP
  ordering/retransmission/gaps/epochs, detector families, repeated attempts,
  exact and bounded provenance, retained-state pressure, writer security,
  queue-byte races, child lifecycle acknowledgements, offline multiprocess
  replay, configuration, doctor, and deployment contracts.
- Malformed-input smoke coverage includes 1,000 random frames and 1,000 random
  detector payloads in addition to hand-built truncated protocol cases.
- Python byte-compilation passed on Python 3.12.13.
- On the Windows development host, the synthetic parser benchmark processed
  100,000 Ethernet/IPv4/TCP frames at 172,487.7 packets/s. The combined
  sequential TCP reconstruction plus detector path processed 10,000 repeated
  synthetic HTTP Basic attempts at 3,293.6 attempts/s and emitted all 10,000
  findings.

Synthetic rates are regression evidence only. They are not a live line-rate
guarantee; traffic mix, frame size, CPU scheduling, storage, kernel/libpcap
drops, and raw-ring contention materially affect capacity.

## Validation boundary

The development host is Windows and does not expose the target Kali `eth0`,
libpcap permissions, systemd, Bash syntax execution, or `dumpcap`. A native
Kali installation and live interface smoke test therefore remain host-specific
release gates. On the authorized capture host, run the installer, review the
config, run the doctor, start the service, and confirm increasing capture and
worker counters plus a healthy raw ring before beginning any separately
approved interception.

## Known limits

- Correctly encrypted TLS, QUIC/HTTP/3, SSH, SNMPv3, LDAPS, IMAPS, SMTPS, and
  similar payloads are not decrypted.
- Capture loss, a truncated snap length, unsupported encapsulation, missing
  first fragments, capture started mid-flow, or configured memory/queue limits
  can make findings incomplete. Observable cases are counted and force an
  incomplete verdict.
- Stream provenance retains a bounded recent span history. Findings explicitly
  mark packet-ID provenance incomplete when older or capped context is needed.
- Generic secret and payment-card matches are candidates, not proof of validity
  or usability. Multipart form bodies are not deeply decoded.
- Unredacted JSONL and raw PCAPNG are restricted plaintext evidence. Store the
  state directory on an approved encrypted volume when at-rest encryption is
  required by the engagement.
