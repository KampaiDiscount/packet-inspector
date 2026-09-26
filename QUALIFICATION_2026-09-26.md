# Isolated burst qualification, 26 September 2026

This is a bounded performance and detection check for the candidate source
snapshot, not a universal loss-free or complete-protocol claim. No assessment
capture or unredacted finding is included in the repository.

The optional source-only helpers under `tools/` need `tcpreplay`, `scapy` and
`psutil` in an isolated qualification environment. They are not runtime
dependencies of Packet Audit and must not be replayed into an assessment
interface.

The initial candidate's Python-source manifest SHA-256 is
`bf6a20e8decb06341239c52a327c024c3f3c14155defc9d191146b2cdb3a15d8`.
The preserved 23-second source window contains 214,872 Ethernet/IP frames;
its PCAPNG SHA-256 is
`ba144a733cc7ca8a1bac8c5a93f85dd59838add94b16f4aae8c1e09d6393406b`.
The original packet content remains in a restricted Kali evidence directory.

## Method and acceptance criteria

The PCAP was replayed through a veth pair inside a separate Linux network
namespace on the same Kali VM. The sensor used four workers, a 128 MiB
per-worker queue byte cap, the shipped BPF, an independent dumpcap ring and
the same Python runtime family as the live sensor. The veth MTU was raised to
9,000 because the preserved capture contains offloaded frames up to 2,663
bytes; an initial 1,500-MTU trial omitted the tail of the replay and was
rejected. Eight non-IP trailer frames flushed tcpreplay's transmit ring and
were excluded by the sensor filter. Neither eth0 nor the installed Packet
Audit service, Ettercap or Win11 were changed.

For each accepted trial, full-frame SHA-256 multisets from the independent
dumpcap ring were compared with the expected PCAP. A pass required every
source frame in the raw ring, zero libpcap/interface/analysis-queue loss,
exact capture accounting, clean worker/writer acknowledgement and a complete
session verdict. A separate overlay inserted 11 synthetic frames representing
an HTTP Basic request, a URL-encoded login form, and a form whose password
field spanned TCP segments. All three flows were deliberately routed to the
busy worker. The forwarded flows had ingress/egress copies; the third was
locally originated and had no ingress copy. The lossless offline replay of the
overlay established exactly three expected findings and packet provenance.

## Results

| Trial | Queue slots | Source-window speed | Queue loss | Hot-worker peak | Findings | Verdict |
|---|---:|---:|---:|---:|---:|---|
| Suppression off, no overlay | 1,024 | 1× (~24.2 s) | 0 | 84.2 MiB | 0 | Complete |
| Suppression on, no overlay | 1,024 | 1× (~24.1 s) | 0 | 32.8 MiB | 0 | Complete |
| Suppression off, no overlay | 1,024 | 1.5× (~16.1 s) | 30,713 | 134.2 MiB | 0 | Incomplete |
| Suppression on, no overlay | 1,024 | 1.5× (~16.1 s) | 0 | 58.1 MiB | 0 | Complete |
| Suppression on, no overlay | 1,024 | 2× (~12.2 s) | 10,634 slot drops | 73.0 MiB | 0 | Incomplete |
| Suppression on, auth overlay | 1,024 | 1.5× (~16.2 s) | 0 | 55.6 MiB | 3/3 | Complete |
| Suppression on, auth overlay | 2,048 | 2× (~12.2 s) | 0 | 70.4 MiB | 3/3 | Complete |
| Suppression on, auth overlay, repeat | 2,048 | 2× (~12.2 s) | 0 | 69.2 MiB | 3/3 | Complete |

The 1.5× unsuppressed auth-overlay run also passed (hot-worker peak 112.0
MiB), illustrating run-to-run variability near the queue limit. The 2×
1,024-slot failure was slot exhaustion despite 73.0 MiB queued; the 2,048-slot
trials retained the same 128 MiB byte cap. This supports a bounded 2,048-slot
configuration for this host and traffic mix, not an unlimited queue or a
guarantee at higher sustained rates.

In the first passing 2×/2,048-slot trial, the sensor captured 214,884 packets:
all 214,883 expected source and synthetic frames plus one namespace background
frame. It dispatched 110,998, intentionally skipped 103,886 proven forwarded
copies, and dropped zero. In the repeat, all 214,883 expected frames were
captured; 110,935 were dispatched and 103,948 were intentionally skipped.
The raw rings independently matched all 214,883 expected frames in both
trials. No libpcap, interface or operational telemetry loss was reported.

The three live findings in both 2× trials had the exact detector/source-port/
packet-ID combinations from offline ground truth: HTTP Basic on port 49002
from packet 96605; URL-encoded form on port 49003 from packet 136701; and
segmented form on port 49004 from packets 189671 and 189672. Their provenance
lists were complete. The local-origin flow was not mistaken for a forwarded
duplicate. The extracted synthetic usernames and secrets also matched the
injected ground truth in offline replay and all passing overlay trials.
Detection latency from the final required packet to worker
emission was 7.7-12.2 seconds under the hot-worker backlog; this is a
material responsiveness limitation even though recall passed.

Peak measured process-tree RSS in the passing 2× trials was approximately
549-552 MiB. At 2× with 1,024 slots, capture delivery remained complete but
10,634 packets were dropped before analysis and the verdict was correctly
incomplete. Suppression protects this bounded burst, but finite workers and
queues still have a throughput limit. Qualification for a different host,
traffic mix or sustained duration requires its own independent ground truth,
raw-frame reconciliation, detection-latency distribution and soak/fault tests.

## Final 0.1.10 source snapshot

After the MQTT, opaque-TLS, dashboard and default-queue changes were
integrated, the complete Python source was copied to a separate restricted
qualification directory. Both `pyproject.toml` and `packet_audit.__version__`
reported `0.1.10`. The sorted Python-file SHA-256 manifest has SHA-256
`671528a8ac81aac670cb61f88d3ece15b47109272b7d941141acf888b0e89c58`.
This is distinct from the earlier candidate hash above.

One further 2× auth-overlay trial used that exact source snapshot with
suppression enabled, 2,048 queue slots and the unchanged 128 MiB per-worker
byte cap. The raw ring contained all 214,883 expected frames with exact
full-frame hash multiplicities: zero missing and zero unexpected. The sensor
captured 214,883, dispatched 111,120 and intentionally skipped 103,763
proven forwarded copies; these counts reconcile exactly. Userspace,
libpcap, interface and operational-telemetry drops were zero. Worker and
writer both reported three findings and the final verdict was complete.
The busy worker peaked at 1,068 outstanding batches and 70.5 MiB, while
measured process-tree RSS peaked near 553 MiB.

The three findings matched synthetic ground truth in detector, extracted
username/secret, complete provenance and source packet IDs: 96605 for HTTP
Basic, 136701 for the URL-encoded form and 189671/189672 for the segmented
form. Detection latencies were approximately 7.89, 9.51 and 12.26 seconds.
This validates the integrated 0.1.10 source for this one isolated traffic
mix at 2× timing; it does not remove the finite-throughput and latency
limits above.
