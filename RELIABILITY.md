# Reliability and acceptance gate

## 0.1.10 bounded release qualification

The tested Kali host's same-interface forwarding path benefits from
`[capture] forwarded_duplicate_suppression = true`, four workers,
`queue_size = 2048`, and `max_worker_queue_bytes = 134217728`. The source
default keeps duplicate suppression off for other capture topologies; the
2,048-slot limit is the new bounded default. Existing `/etc` settings are
preserved on upgrade and must be reviewed explicitly.

In two isolated 2× replays of the preserved burst with these settings, the
independent raw ring contained every expected source frame, reported capture
and analysis drops were zero, and three synthetic authentication findings
matched lossless offline ground truth with exact packet provenance. The same
2× replay at 1,024 slots dropped 10,634 analysis packets; the 2,048-slot runs
stayed below the existing 128 MiB per-worker byte cap. Findings arrived
7.7–12.2 seconds after their final packet under backlog. See
[QUALIFICATION_2026-09-26.md](QUALIFICATION_2026-09-26.md) for methodology,
counts, rejected test runs, and the limits of this finite measurement. It is
not a sustained line-rate guarantee or a substitute for the real eth0 soak.

The dashboard now states reported loss and analysis backlog separately from
its connection state. A connected page or an emitted credential is not a
complete-session verdict; inspect the drop counters and final summary before
using absence of a finding as assessment evidence. Correctly encrypted and
unsupported formats remain outside extraction coverage.

Version 0.1.9 excludes syntactically valid HTTP byte-range offsets from the
payment-card candidate detector, after a historical capture showed Luhn-valid
offsets creating false alarms. Header parsing is bounded; other card-shaped
values remain subject to the ordinary detector. The first historical replay
still has incomplete HTTP/TCP coverage, so its findings require context.

## 26 September 2026 lab continuation on 0.1.9

The installed Kali build matched the 0.1.9 release source. The live `eth0`
service remained on PID 5584 with no restart while the checks below ran.
Synthetic usernames and passwords were compared with the restricted JSONL
findings; their values are deliberately omitted here. A complete finding means
the supported wire pattern was reconstructed, **not** that a login succeeded.

| Live path | Test | Result | Paired-finding event ID |
| --- | --- | --- | --- |
| Win11 `192.168.1.11` through the assessment path | Three separate clear HTTP browser forms (Zero Bank, ASP demo, ASP.NET demo) | Each paired the synthetic username and password; complete, high confidence | `c36e5306f379483cb5e85dbe21789d02`, `ce2bf76d5054433c8eaf45b8aba34038`, `2855fff5276b48109b4936295775261e` |
| Kali `eth0` egress | HTTP Basic | Both fields; complete, confirmed | `1ce7d82d1e8a42969d87004c326c69c6` |
| Kali `eth0` egress to [Rebex's public test server](https://test.rebex.net/) | FTP USER/PASS and IMAP LOGIN | Both fields in each paired finding; complete, confirmed | `92a6daf99ac9442487b827055b8c2a96`, `f68ce59dd3604efb8ddd5170d774f2ef` |
| Kali `eth0` egress | HTTP form with the body sent in three separated writes, including a split password | Both fields and three packet references; complete, high confidence | `6d5c397793db4801a13c4a4333bd7f58` |
| Windows host loopback forwarding into Kali `eth0` | SMTP AUTH PLAIN, SMTP AUTH LOGIN, POP3 USER/PASS against short-lived rejecting lab responders | Both fields in each paired finding; complete, confirmed | `5f85c98f61604361825e8901729b187f`, `401fc117d62a44b88d68e8f77877aa0d`, `187ec61ee600416aa91150fa42ccf648` |

FTP and POP3 also emitted an earlier username-only finding before the password
arrived; the paired findings above are the completed exchanges. The SMTP and
POP3 responders rejected authentication, accepted only the NAT gateway source,
and exited after the tests. Their two temporary host-loopback forwarding rules
were removed; the original SSH rule remained. An HTTPS Basic-header negative
control completed over TLS 1.3 and produced no matching plaintext finding.
Across the ten positive paired findings, packet-observation-to-emission delays
were 61.3–159.6 ms. This is a small, lightly loaded sample, not a latency
percentile or dashboard-delivery measurement.

At 22:44:47 SAST the ongoing live session had 105,886 captured and dispatched
packets, 105,886 libpcap-received packets, zero reported libpcap/interface/
userspace/operational drops, zero parser errors and worker restarts, and empty
worker queues. The independent raw ring remained active. These counters cover
the current observed period and do not establish that every packet on the wire
reached the interface.

**Later live-load failure in this same 0.1.9 session:** from 22:49:25.789 to
22:49:37.759 SAST, 529 `analysis_queue_drop` records accounted for 67,117
packets (70,599,676 captured bytes) that never reached an analysis worker.
One Win11 TLS flow to `oneclient.sfx.ms` dominated the burst and was routed
to worker 2. Its 128 MiB byte queue peaked at 134,217,214 of 134,217,728
bytes; the slot-drop counter remained zero. The four queues drained afterward,
and libpcap/interface drops, parser errors and worker restarts remained zero.
The independent raw PCAP ring contains readable files spanning the interval,
but that does not make the live JSONL complete: preserve and replay those
files, then reconcile findings before using this window as assessment evidence.
No port-80/8080 traffic was visible in the raw capture during the exact loss
window. This observation does not prove that every other authentication
pattern was seen. The earlier 22:44:47 zero-drop snapshot was only a
point-in-time result; the ongoing live session now has a documented analysis
coverage gap.

The contiguous ring segments were preserved and SHA-256 checked under the
restricted Kali directory
`/var/lib/packet-audit/eth0/evidence/recovery-20260926T2049Z`. An isolated,
low-priority replay analyzed 302,464 raw frames in 32.283 seconds with zero
replay queue drops and a `complete` replay verdict. Its nine findings matched
live findings by material and endpoint in private comparison; neither output
had a finding in the exact 12-second loss window. This recovers the available
raw evidence for review, but paced replay does not establish live burst
capacity or erase the recorded live analysis loss.

The same burst exposed an independent **false positive**: live event
`67020901bd784fa5bba0ed01482510f6` labeled encrypted TLS 1.3 server-to-
client bytes on port 443 as a confirmed `mssql_tds_login7` credential. Raw
handshake and flow context contradict the SQL classification. Exclude this
event from assessment evidence and treat it as a detector defect pending a
guarded fix and regression test. Its presence means that `confirmed` is not
currently a universal validity guarantee.

The working-tree parser fix now checks [MS-TDS packet-length limits](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/c1cddd03-b448-470a-946a-9b1b908f27a7)
and LOGIN7 structure, and avoids interpreting traffic after a recognized TLS
handshake as cleartext TDS. In a separate Kali source copy, the 302,464-frame
capture replayed with zero drops and eight findings: the false SQL event
disappeared and all eight other findings retained the same material in private
comparison. The initial isolated suite passed 610 tests and 30 subtests with no
skips. At this stage of the lab continuation, the source fix was not installed
in the running sensor and did not repair the separate live queue-loss
condition. Both findings informed the 0.1.10 candidate above.

### Experimental forwarded-copy queue suppression

Version 0.1.10 has an **opt-in, default-off** queue optimization under
`[capture] forwarded_duplicate_suppression = true`. It was not installed on
the live Kali sensor during the tests below. When a worker queue is
above 5% of its byte or batch capacity, the capture process may omit the
second Ethernet view of a forwarded TCP/UDP IP datagram from *analysis* only.
It first requires a complete same-datagram match, local-interface MAC
ingress/egress roles, a matching unchanged hop count/checksum (raw forwarding)
or a one-hop decrement with the corresponding IPv4 checksum change, capture
order within two seconds, and successful admission of the ingress to the
worker queue. It fails open on an unmatched, truncated, fragmented or
uncertain frame. The independent `dumpcap` raw ring remains unchanged. The
match cache is bounded to 16 MiB of keys, 16,384 entries and two seconds.
Captured, dispatched, intentionally skipped, parser-rejected, ignored and
actually queue-dropped packets have separate counters and a final accounting
check; failed ingress admission cannot turn its matching egress into a skip.

A read-only pass over the preserved 302,464-frame PCAP found **54,518
potential second copies** among 109,143 captured frames in the exact
22:49:25.789–22:49:37.759 SAST loss window, assuming the queue accepted every
ingress and suppression was active throughout. The dominant Win11 TLS flow
(`192.168.1.11:60245` to `2.17.165.12:443`) contributed 54,515 of those
matches among its 109,086 frames. Its forwarding path retained IPv4 TTL and
header checksum, so an initially stricter one-hop-only candidate matched
zero; the current matcher covers the observed exact-copy case. A heartbeat at
20:49:19 UTC already showed worker 2 carrying 35,665,324 queued bytes,
above the proposed 5% trigger (~6.7 MiB), before the first recorded queue
drop at 20:49:25.789 UTC. **These counts are an upper bound on possible live
skips, not a measured reduction in loss**: ingress admission under actual
pressure, worker processing, and competing traffic were not replayed as a
live-rate test.

A low-priority dispatcher microbenchmark over the same PCAP took 2.98 and
3.06 seconds with this option off versus 4.12 and 3.86 seconds with it on,
approximately **32% more capture-path CPU time**. It omits worker analysis and
raw-ring I/O. The isolated source copy passed all 626 collected tests,
including new admission-failure, local-origin authentication, one-to-one
pairing and bounded-cache regressions. The later isolated live-rate trial above
measured its net effect on queue loss, capture delivery and findings. Keep it
off on an unqualified capture topology, and check counters and raw-ring health
when enabling it on the tested Kali forwarding path.

A fresh isolated 0.1.9 acceptance run processed 188/188 qualification packets
and wrote 34/34 expected findings. Its verdict was intentionally `incomplete`
because one HTTP body used an unsupported content type. Two more replays
processed 85,656/85,656 packets with 35/35 findings in 10.421 seconds and
80,094/80,094 with 40/40 in 10.761 seconds; both returned `complete` with
zero reported queue drops, parser errors, or restarts. The replay source and
summary are retained privately at
`/root/packet-audit-acceptance-20260926/v019-continuation-20260926T203753Z/acceptance-summary.json`.
Replay can wait for queue capacity, so its packet-per-second wall rate is not
a sustained live-interface capacity claim.

A detector-path regression now covers segmented JSON password fields with
numeric `0` and an empty string, and verifies that JSON `null` and booleans
do not emit credential values. The focused HTTP form/pipeline suite passed
34 tests. This is a parser check, not proof that every application's JSON
login format is supported.

The earlier 251,933 analysis drops in a 542,076-packet live session came from
0.1.6, whose 64-slot worker queues saturated; the current 0.1.9 configuration
uses 1,024 slots and 128 MiB per worker. The old loss was a regression
baseline, and the new live burst demonstrates that the larger byte cap still
cannot absorb every concentrated flow. Actual on-path Win11 ground truth
here covers the three HTTP forms; the other live checks used Kali egress or
host-to-Kali forwarding. Actual SMB/NTLM and the other implemented protocol
families, representative sustained load, load-percentile latency, a multi-hour
soak, and isolated failure/recovery exercises remain qualification work. The
format boundaries in [COVERAGE.md](COVERAGE.md), including TLS and unsupported
HTTP encodings, also remain in force. Until those gates are met, use supported
positive findings as evidence but do not interpret an absent finding as proof
that no credential crossed the network.

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
