# Reliability and acceptance gate

Version 0.1.9 excludes syntactically valid HTTP byte-range offsets from the
payment-card candidate detector, after a historical capture showed Luhn-valid
offsets creating false alarms. Header parsing is bounded; other card-shaped
values remain subject to the ordinary detector. The first historical replay
still has incomplete HTTP/TCP coverage, so its findings require context.

## What 0.1.7 and 0.1.8 change

- Removes duplicate queued payload bytes for unfragmented TCP/UDP packets and
  avoids costly HTTP/LDAP false gates on bulk binary traffic. Detection still
  checks supported signatures; the optimizations do not skip whole bodies.
- Uses finite defaults of 1,024 batch slots and 128 MiB of captured bytes per
  worker. Existing explicit host settings require a reviewed config update.
- Reports queue-slot and byte-budget losses separately, along with peak queued
  bytes, outstanding batches and capture-loop time. Any analysis loss makes a
  live session incomplete. The independent raw ring is the recovery source.

The controlled Win11/Kali/Linode 48 MiB burst previously caused 70,538
analysis-queue drops in an eight-second window on the installed 0.1.6 service.
An isolated fixed-build live run ended with 87,144 captured and dispatched
packets, zero reported drops, zero parser errors, and a complete verdict. The
new test-flow findings matched replay of its independent PCAP. This qualifies
that bounded traffic mix only; the worker drain still took longer than the
burst, so sustained traffic at the same rate can exhaust the finite queue.

## What 0.1.6 changes

- Explicit short Bearer credentials are retained, while generic cookies and
  structurally invalid JWT-shaped text no longer claim a confirmed session or
  high-confidence token. JWT structure does not verify its signature or issuer.
- Bounded file-signature checks identify PNG, JPEG, GIF, WebP, PDF and ZIP
  prefixes in clear HTTP/1 bodies. The finding stores metadata and packet
  provenance, not file bytes; the separately configured raw ring is unchanged.
- Verified binary file bodies are excluded from credential-text scanning to
  avoid falsely treating incidental image bytes as an authentication exchange.

## What 0.1.5 changes

- Correlates a single zero-SessionId SMB2 NTLM challenge and response within
  one TCP connection, including delayed Type 2 reassembly. Competing challenges
  remain unpaired and visible as an incomplete-coverage condition.
- Offline replay waits for bounded worker queue capacity instead of dropping
  packets under artificial replay speed. Live capture still exposes overload
  through its loss counters and does not block the capture read loop.
- The default capture filter admits recognized outer VLAN tags for both the
  analyzer and independent raw ring. Existing explicit filters require a
  configuration update; tagged non-IP traffic may increase capture load.

## What 0.1.4 changes

- Capture uses bounded `next()` reads instead of native callback dispatch when
  available. A Kali Python 3.13 binding reproduced a callback argument error;
  the previous fallback could consume a packet and then silently skip it.
  Callback-only compatibility paths now fail visibly on errors or count
  disagreement instead of falling through after consuming data.
- A native libpcap offline regression checks every packet, byte and timestamp
  across multiple batch boundaries. Live acceptance must still be run on the
  actual sensor; mocked capture tests alone did not detect this binding fault.

## Reliability controls introduced in 0.1.3

- Live libpcap must support nonblocking mode. Idle reads wait at most 100ms
  between iterations instead of depending on a blocking packet-buffer timeout.
- The shipped systemd service is Type=notify with a 90-second watchdog. The
  main process sends progress only after a completed capture/read/dispatch and
  child-health iteration. There is no timer thread that can hide a wedged loop.
- systemd readiness follows initialization of capture, workers and writer;
  startup has a 90-second limit. Notify failures fail visibly.
- The external watchdog detects missing progress after 90 seconds. Actual
  termination/restart follows systemd stop/restart policy; do not interpret
  that as a promise to recover all packets or restart within 90 seconds.
- Existing worker/writer progress checks, bounded queues, loss counters, raw
  ring checks, crash-loop circuit breaker and durable shutdown acknowledgement
  remain. Standalone CLI execution does not have systemd's external watchdog.

On Linux, libpcap's `ps_recv` counts packets accepted by the capture filter;
`ps_drop` counts accepted packets dropped before delivery. The final live
summary reports `libpcap_received_minus_captured` and requires
`ps_recv - ps_drop == captured_packets` for a complete verdict. A difference
or missing receive/drop statistics makes the verdict incomplete. A positive
difference with zero reported drops may be packets buffered when capture
stopped; it is an unresolved delivery gap, not proof of a kernel drop.
The statistics are sampled immediately before closing the live handle, so
traffic arriving between that sample and close cannot be ruled out. A zero
gap also does not prove that all traffic on the wire reached the capture
interface, and `ps_ifdrop == 0` can mean the counter is unavailable. Offline
replay has no comparable native statistics and does not use this check.
See libpcap's [Linux statistics notes](https://github.com/the-tcpdump-group/libpcap/blob/master/doc/README.linux)
and [pcap_stats manual](https://github.com/the-tcpdump-group/libpcap/blob/master/pcap_stats.3pcap).

A restart loses in-memory reassembly state and can miss traffic during recovery.
It is a visible recovery mechanism, not seamless capture. A forced kill may not
write a final summary: absence of a completed session verdict is itself a gap.
Preserve journald/service events and the independent raw ring with JSONL evidence.

## Automated evidence

All fixtures use synthetic credentials and generated traffic; no assessment
captures are committed. The test suite includes:

- 1,500 repeated HTTP logins over five flows/two worker processes, 6,010 packets,
  reordered segments, retransmissions and a split final field; exactly 1,500
  expected credential events and reconciled worker/writer counts.
- NetNTLMv1/v2, raw/HTTP/SPNEGO wrappers, distinct retries, missing/wrong-flow
  challenges, connection epochs, and interleaved SMB2 session identifiers.
- Byte-by-byte and whole-buffer protocol tests, including repeated LDAP binds.
- Redis frame-cursor retention over 1,000 attempts and PostgreSQL method guards.
- Alive-but-stale workers, writer death, worker restarts/circuit breaking,
  bounded startup, injected ENOSPC write/fsync failures and a genuinely blocked
  synthetic capture read that cannot keep sending watchdog heartbeats.
- Real Unix datagram notification tests on Linux; these are skipped on Windows.

The synthetic benchmark is a regression comparison, not a live-NIC capacity
measurement. A short burst is not a long-duration soak. Unit fault injection is
not an actual full disk, interface disconnect or OS/kernel failure exercise.

## Required before depending on a sensor for an assessment

1. Verify the installed build, interface, capture filter, raw ring, free disk,
   permissions, systemd readiness and advancing capture/worker/writer counters.
2. With synthetic lab accounts and a known ground-truth count, exercise actual
   NTLM SMB and required cleartext applications across the approved sensor path.
   Count complete exchanges independently from preserved PCAP and compare both
   endpoints, challenges/responses, retries, JSONL records and dashboard entries.
3. Measure detection/export latency from the last required packet, at idle and
   under the expected traffic mix/load; record p50/p95/p99 and maximum latency.
4. Run a multi-hour representative soak. Record libpcap/interface/raw-ring
   losses, queue peaks, process RSS/CPU, parser/coverage counters, disk use and
   final acknowledgements. Missing counters are unknown, not zero.
5. In an isolated test instance, inject a blocked read, worker/writer failure,
   full disk and link interruption. Prove visible failure, service behaviour and
   evidence preservation; do not inject faults into the production assessment.

There is no universal pass rate or throughput figure without that host-specific
qualification. A final "complete" verdict means available accounting and
configured coverage checks reconciled; it does not certify every protocol or
prove that all network traffic reached the capture interface.
