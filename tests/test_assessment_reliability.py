"""Assessment reliability gates: visible faults and bounded synthetic replay.

These tests demonstrate particular cases, not universal capture completeness.
All traffic and credentials in this module are synthetic.
"""
from __future__ import annotations

import errno
import json
from pathlib import Path
import queue
import struct
from types import SimpleNamespace

import pytest

from packet_audit.config import AuditConfig
from packet_audit.models import Finding, STOP_SENTINEL
from packet_audit.supervisor import AuditRuntimeError, AuditSupervisor
from packet_audit.writer import writer_process
from tests.pcap_builder import ethernet_ipv4_tcp


def _supervisor(tmp_path: Path) -> AuditSupervisor:
    return AuditSupervisor(AuditConfig(
        workers=1, heartbeat_seconds=1, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    ))


def _process(pid: int, *, alive: bool = True, exitcode=None):
    return SimpleNamespace(pid=pid, exitcode=exitcode, is_alive=lambda: alive)


@pytest.mark.parametrize("stale_role", ["writer", "worker"])
def test_alive_but_stale_child_is_a_visible_fatal_error(tmp_path, monkeypatch, stale_role):
    supervisor = _supervisor(tmp_path)
    supervisor.writer = _process(100)
    supervisor.workers = [_process(200)]
    supervisor.writer_last_seen = 100.0 if stale_role == "writer" else 120.0
    supervisor.worker_last_seen[(0, 200)] = 100.0 if stale_role == "worker" else 120.0
    monkeypatch.setattr(supervisor, "_drain_control", lambda: None)
    monkeypatch.setattr("packet_audit.supervisor.time.monotonic", lambda: 120.0)

    with pytest.raises(AuditRuntimeError, match=rf"{stale_role}.*heartbeat is stale"):
        supervisor._check_children()


def test_writer_exit_halts_before_silent_evidence_loss(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path)
    supervisor.writer = _process(100, alive=False, exitcode=1)
    monkeypatch.setattr(supervisor, "_drain_control", lambda: None)
    with pytest.raises(AuditRuntimeError, match="capture halted to prevent silent evidence loss"):
        supervisor._check_children()


def test_worker_restart_marks_flow_state_loss_and_circuit_breaks(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path)
    supervisor.writer = _process(100)
    supervisor.writer_last_seen = 120.0
    supervisor.workers = [_process(200, alive=False, exitcode=1)]
    supervisor.worker_last_seen[(0, 201)] = 120.0
    monkeypatch.setattr(supervisor, "_drain_control", lambda: None)
    monkeypatch.setattr(supervisor, "_spawn_worker", lambda _worker_id: _process(201))
    monkeypatch.setattr(supervisor, "_await_workers_ready", lambda _worker_ids: None)
    monkeypatch.setattr("packet_audit.supervisor.time.monotonic", lambda: 120.0)

    supervisor._check_children()

    assert supervisor.worker_restarts == 1
    assert any("flow state gap" in reason for reason in supervisor.incomplete_reasons)
    assert supervisor.workers[0].pid == 201
    supervisor.workers[0] = _process(201, alive=False, exitcode=1)
    supervisor.worker_restart_history[0] = [118.0, 119.0]
    with pytest.raises(AuditRuntimeError, match="failed 3 times within 60 seconds"):
        supervisor._check_children()


def test_writer_ready_timeout_is_bounded(tmp_path, monkeypatch):
    supervisor = _supervisor(tmp_path)
    supervisor.writer = _process(100)
    monkeypatch.setattr(supervisor, "_drain_control", lambda: None)
    with pytest.raises(AuditRuntimeError, match="did not acknowledge startup"):
        supervisor._await_writer_ready(timeout=0.01)


@pytest.mark.parametrize("failure_point", ["write", "fsync"])
def test_enospc_never_acknowledges_a_durable_writer_close(tmp_path, monkeypatch, failure_point):
    findings, operations, control = queue.Queue(), queue.Queue(), queue.Queue()
    findings.put(Finding(
        event_id="synthetic-e1", session_id="synthetic-s1",
        observed_timestamp_ns=1, emitted_timestamp_ns=2,
        category="authentication", protocol="HTTP", detector="synthetic",
        material_type="credential", material={"password": "SyntheticOnly!"},
        confidence="confirmed", completeness="complete", flow_id="synthetic-flow",
        direction=0, packet_ids=(1,), stream_offset=0, attempt_ordinal=1,
    ))
    findings.put(STOP_SENTINEL)
    operations.put(STOP_SENTINEL)
    if failure_point == "write":
        from packet_audit.writer import write_json_line

        def fail_finding_write(handle, record):
            if record.get("event_id") == "synthetic-e1":
                raise OSError(errno.ENOSPC, "synthetic disk full")
            return write_json_line(handle, record)

        monkeypatch.setattr("packet_audit.writer.write_json_line", fail_finding_write)
    else:
        def fail_fsync(_fd):
            raise OSError(errno.ENOSPC, "synthetic disk full")

        monkeypatch.setattr("packet_audit.writer.os.fsync", fail_fsync)

    with pytest.raises(OSError) as caught:
        writer_process(
            findings, operations, str(tmp_path / "findings.jsonl"),
            str(tmp_path / "operations.jsonl"), False, control_queue=control,
        )
    assert caught.value.errno == errno.ENOSPC
    reports = []
    while not control.empty():
        reports.append(control.get_nowait())
    assert any(report["state"] == "ready" for report in reports)
    assert not any(report["state"] == "stopped" for report in reports)


def _write_synthetic_capture(path: Path, packets: list[bytes]) -> None:
    # Normalize microseconds for captures longer than 1,000 records.
    with path.open("wb") as handle:
        handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, packet in enumerate(packets):
            handle.write(struct.pack(
                "<IIII", 1_700_000_000 + index // 1000, (index % 1000) * 1000,
                len(packet), len(packet),
            ))
            handle.write(packet)


def test_1500_split_reordered_repeated_logins_are_all_written_on_shutdown(tmp_path):
    """Exercise actual capture parser, two spawned workers and durable writer."""
    attempts, flows = 1500, 5
    body = b"uid=ReliabilityFakeUser&passw=ReliabilitySyntheticOnly"
    request = (
        b"POST /login HTTP/1.1\r\nHost: synthetic.invalid\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: "
        + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    sequences = [1001] * flows
    packets = [ethernet_ipv4_tcp(b"", seq=1000, flags=0x02, sport=50000 + flow)
               for flow in range(flows)]
    split = len(request) - 12
    for attempt in range(attempts):
        flow = attempt % flows
        seq, sport = sequences[flow], 50000 + flow
        # The middle segment arrives first. The final password crosses segments.
        packets.extend([
            ethernet_ipv4_tcp(request[37:split], seq=seq + 37, sport=sport),
            ethernet_ipv4_tcp(request[:37], seq=seq, sport=sport),
            ethernet_ipv4_tcp(request[37:split], seq=seq + 37, sport=sport),
            ethernet_ipv4_tcp(request[split:], seq=seq + split, sport=sport),
        ])
        sequences[flow] += len(request)
    packets.extend(ethernet_ipv4_tcp(b"", seq=seq, flags=0x04, sport=50000 + flow)
                   for flow, seq in enumerate(sequences))
    capture = tmp_path / "synthetic-reliability.pcap"
    _write_synthetic_capture(capture, packets)
    config = AuditConfig(
        interface="offline", workers=2, queue_size=512, heartbeat_seconds=1,
        raw_capture_enabled=False, output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )

    result = AuditSupervisor(config, offline_path=capture).run()

    assert result["verdict"] == "complete", result["incomplete_reasons"]
    assert result["captured_packets"] == len(packets) == 6010
    assert result["worker_packets_processed"] == result["dispatched_packets"] == len(packets)
    assert result["userspace_queue_drops"] == result["capture_parse_errors"] == 0
    assert result["worker_queue_byte_health"]["current_bytes"] == 0
    assert result["worker_findings_emitted"] == result["writer_findings_written"]
    records = [json.loads(line) for line in config.output_jsonl.read_text().splitlines()]
    logins = [record for record in records if record["detector"] == "sensitive_field"
              and record["material"].get("name") == "passw"]
    assert len(logins) == attempts
    assert len({record["event_id"] for record in logins}) == attempts
    assert {record["source_port"] for record in logins} == set(range(50000, 50000 + flows))
    assert all(record["material"]["username"] == "ReliabilityFakeUser" for record in logins)
    assert all(record["material"]["value"] == "ReliabilitySyntheticOnly" for record in logins)
    assert all(len(record["packet_ids"]) >= 2 for record in logins)
    assert all(record["fields"]["http_body_complete"] for record in logins)
