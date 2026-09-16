from __future__ import annotations

from pathlib import Path
import hashlib
import json
import os
import queue
import stat

import pytest

from packet_audit.models import Finding, STOP_SENTINEL
from packet_audit.writer import (
    _restricted_text_append,
    prepare_private_directory,
    prepare_private_parent,
    validate_evidence_paths,
    write_json_line,
    verify_export_permissions,
    writer_process,
)


def test_unredacted_material_is_written(tmp_path: Path):
    path = tmp_path / "findings.jsonl"
    finding = Finding(
        event_id="e1",
        session_id="s1",
        observed_timestamp_ns=1,
        emitted_timestamp_ns=2,
        category="authentication",
        protocol="HTTP",
        detector="test",
        material_type="password",
        material={"username": "alice", "password": "SyntheticSecret!"},
        confidence="confirmed",
        completeness="complete",
        flow_id="flow",
        direction=0,
        packet_ids=(1,),
        stream_offset=10,
        attempt_ordinal=1,
    )
    with _restricted_text_append(path) as handle:
        write_json_line(handle, finding.to_dict())
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["material"]["password"] == "SyntheticSecret!"
    ok, _ = verify_export_permissions(path)
    assert ok


def test_bytes_are_encoded_without_loss(tmp_path: Path):
    path = tmp_path / "bytes.jsonl"
    with _restricted_text_append(path) as handle:
        write_json_line(handle, {"value": b"\x00\xff"})
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["value"] == {"encoding": "hex", "value": "00ff"}


def test_export_validator_rejects_non_regular_path(tmp_path: Path):
    ok, detail = verify_export_permissions(tmp_path)
    assert not ok
    assert "regular file" in detail


def test_missing_evidence_parent_is_created_private_under_umask_0022(
    tmp_path: Path,
):
    path = tmp_path / "nested" / "evidence" / "findings.jsonl"
    previous_umask = os.umask(0o022)
    try:
        with _restricted_text_append(path) as handle:
            write_json_line(handle, {"event": "created"})
    finally:
        os.umask(previous_umask)

    assert path.parent.is_dir()
    assert prepare_private_parent(path) == path.parent.absolute()
    if os.name != "nt":
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE((tmp_path / "nested").stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode policy")
def test_existing_shared_evidence_parent_is_refused_without_chmod(tmp_path: Path):
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)

    with pytest.raises(PermissionError, match="insecure evidence directory"):
        _restricted_text_append(parent / "findings.jsonl")

    assert stat.S_IMODE(parent.stat().st_mode) == 0o755


def test_append_refuses_partial_jsonl_tail_without_modifying_content(tmp_path: Path):
    path = tmp_path / "findings.jsonl"
    partial = b'{"event":"interrupted"}'
    path.write_bytes(partial)

    with pytest.raises(OSError, match="non-newline partial tail"):
        _restricted_text_append(path)

    assert path.read_bytes() == partial
    if os.name != "nt":
        os.chmod(path, 0o600)
    ok, detail = validate_evidence_paths(path, tmp_path / "operations.jsonl")
    assert not ok
    assert "partial tail" in detail


def test_append_accepts_existing_newline_terminated_jsonl(tmp_path: Path):
    path = tmp_path / "findings.jsonl"
    path.write_bytes(b'{"event":"first"}\n')
    with _restricted_text_append(path) as handle:
        write_json_line(handle, {"event": "second"})
    assert path.read_bytes().splitlines() == [
        b'{"event":"first"}',
        b'{"event":"second"}',
    ]


def test_writer_rejects_findings_operations_hardlink_alias(tmp_path: Path):
    findings_path = tmp_path / "findings.jsonl"
    operations_path = tmp_path / "operations-alias.jsonl"
    findings_path.write_bytes(b"{}\n")
    try:
        os.link(findings_path, operations_path)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"hard links unavailable: {exc}")

    findings = queue.Queue()
    operations = queue.Queue()
    findings.put(STOP_SENTINEL)
    operations.put(STOP_SENTINEL)
    with pytest.raises(OSError, match="same file/inode"):
        writer_process(
            findings,
            operations,
            str(findings_path),
            str(operations_path),
            False,
        )
    assert findings_path.read_bytes() == b"{}\n"
    ok, detail = validate_evidence_paths(findings_path, operations_path)
    assert not ok
    assert "same file/inode" in detail


def test_read_only_evidence_validation_accepts_secure_missing_destinations(
    tmp_path: Path,
):
    evidence = tmp_path / "evidence"
    raw = evidence / "pcap-ring"
    prepare_private_directory(evidence)
    prepare_private_directory(raw)

    ok, detail = validate_evidence_paths(
        evidence / "findings.jsonl",
        evidence / "operations.jsonl",
        raw_capture_enabled=True,
        raw_capture_dir=raw,
    )
    assert ok, detail
    assert not (evidence / "findings.jsonl").exists()
    assert not (evidence / "operations.jsonl").exists()


def test_read_only_evidence_validation_rejects_same_missing_path(tmp_path: Path):
    evidence = tmp_path / "evidence"
    prepare_private_directory(evidence)
    destination = evidence / "shared.jsonl"

    ok, detail = validate_evidence_paths(
        destination,
        evidence / "." / "shared.jsonl",
    )

    assert not ok
    assert "same pathname" in detail
    assert not destination.exists()


def test_read_only_evidence_validation_rejects_symlink_destination(tmp_path: Path):
    target = tmp_path / "target.jsonl"
    alias = tmp_path / "findings.jsonl"
    target.write_bytes(b"{}\n")
    try:
        alias.symlink_to(target)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links unavailable: {exc}")

    ok, detail = validate_evidence_paths(alias, tmp_path / "operations.jsonl")
    assert not ok
    assert "symbolic link" in detail


def test_read_only_evidence_validation_requires_enabled_raw_directory(tmp_path: Path):
    ok, detail = validate_evidence_paths(
        tmp_path / "findings.jsonl",
        tmp_path / "operations.jsonl",
        raw_capture_enabled=True,
        raw_capture_dir=tmp_path / "missing-ring",
    )
    assert not ok
    assert "raw capture directory" in detail
    assert "does not exist" in detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode policy")
def test_read_only_evidence_validation_rejects_shared_existing_file(tmp_path: Path):
    findings = tmp_path / "findings.jsonl"
    findings.write_bytes(b"{}\n")
    os.chmod(findings, 0o640)

    ok, detail = validate_evidence_paths(findings, tmp_path / "operations.jsonl")
    assert not ok
    assert "expected 600" in detail


def test_read_only_evidence_validation_rejects_symlinked_raw_directory(
    tmp_path: Path,
):
    raw = tmp_path / "real-ring"
    alias = tmp_path / "ring-alias"
    prepare_private_directory(raw)
    try:
        alias.symlink_to(raw, target_is_directory=True)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"symbolic links unavailable: {exc}")

    ok, detail = validate_evidence_paths(
        tmp_path / "findings.jsonl",
        tmp_path / "operations.jsonl",
        raw_capture_enabled=True,
        raw_capture_dir=alias,
    )
    assert not ok
    assert "raw capture directory" in detail
    assert "symbolic link" in detail


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode policy")
def test_export_validator_rejects_insecure_immediate_parent(tmp_path: Path):
    parent = tmp_path / "shared-export"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)
    path = parent / "findings.jsonl"
    path.write_bytes(b"{}\n")
    os.chmod(path, 0o600)

    ok, detail = verify_export_permissions(path)
    assert not ok
    assert "insecure immediate parent" in detail


def test_writer_never_suppresses_repeated_attempts(tmp_path: Path):
    findings = queue.Queue()
    operations = queue.Queue()
    finding = Finding(
        event_id="repeat-1",
        session_id="s1",
        observed_timestamp_ns=1,
        emitted_timestamp_ns=2,
        category="authentication",
        protocol="FTP",
        detector="test",
        material_type="credential",
        material={"username": "alice", "password": "SyntheticSecret!"},
        confidence="confirmed",
        completeness="complete",
        flow_id="flow",
        direction=0,
        packet_ids=(1,),
        stream_offset=10,
        attempt_ordinal=1,
    )
    findings.put(finding)
    findings.put(finding)
    findings.put(STOP_SENTINEL)
    operations.put(STOP_SENTINEL)
    output = tmp_path / "findings.jsonl"
    operational = tmp_path / "operations.jsonl"
    writer_process(findings, operations, str(output), str(operational), False)
    records = output.read_text(encoding="utf-8").splitlines()
    assert len(records) == 2
    operation_records = [
        json.loads(line) for line in operational.read_text(encoding="utf-8").splitlines()
    ]
    stopped = next(record for record in operation_records if record["event"] == "writer_stopped")
    assert stopped["findings_written"] == 2
    assert stopped["session_findings_sha256"] == hashlib.sha256(output.read_bytes()).hexdigest()
