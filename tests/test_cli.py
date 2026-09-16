from pathlib import Path
import json
import os

import pytest

from packet_audit.cli import build_parser, doctor, main, _load_config
from packet_audit.config import AuditConfig


def write_config(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "packet-audit.toml"
    path.write_text(content, encoding="utf-8")
    return path


def test_live_overrides():
    args = build_parser().parse_args(
        [
            "live",
            "--interface",
            "eth7",
            "--workers",
            "3",
            "--output",
            "evidence/test.jsonl",
            "--console-unredacted",
            "--no-raw-ring",
        ]
    )
    config = _load_config(args)
    assert config.interface == "eth7"
    assert config.workers == 3
    assert config.output_jsonl == Path("evidence/test.jsonl")
    assert config.console_findings
    assert config.console_unredacted
    assert not config.raw_capture_enabled


def test_replay_contract():
    args = build_parser().parse_args(["replay", "sample.pcap"])
    assert args.command == "replay"
    assert args.capture == Path("sample.pcap")


@pytest.mark.parametrize(
    "overrides",
    [
        {"capture_batch_size": 0},
        {"max_worker_queue_bytes": 1024},
        {"heartbeat_seconds": 0},
        {"flow_idle_seconds": 0},
        {"max_out_of_order_bytes_per_direction": 0},
        {"raw_capture_files": 0},
        {"extra_sensitive_field_names": ("",)},
    ],
)
def test_config_rejects_pathological_runtime_values(overrides):
    with pytest.raises(ValueError):
        AuditConfig(**overrides).validate()


def test_config_rejects_shared_findings_and_operations_path(tmp_path: Path):
    shared = tmp_path / "shared.jsonl"
    with pytest.raises(ValueError, match="must be different"):
        AuditConfig(output_jsonl=shared, operational_jsonl=shared).validate()


def test_example_config_loads_with_strict_schema():
    example = Path(__file__).resolve().parents[1] / "config" / "example.toml"
    config = AuditConfig.from_toml(example)

    assert config.interface == "eth0"
    assert config.workers == 4
    assert config.max_reassembly_bytes_per_worker == 128 * 1024 * 1024
    assert config.output_jsonl == Path("./evidence/findings-unredacted.jsonl")
    assert config.extra_sensitive_field_names == ()
    assert config.stop_on_raw_capture_failure


def test_config_rejects_unknown_top_level_section(tmp_path: Path):
    path = write_config(
        tmp_path,
        """
[capture]
interface = "eth0"

[analysys]
heartbeat_seconds = 10
""",
    )

    with pytest.raises(ValueError, match=r"unknown top-level.*\[analysys\]"):
        AuditConfig.from_toml(path)


def test_config_rejects_unknown_key_in_valid_section(tmp_path: Path):
    path = write_config(
        tmp_path,
        """
[capture]
interface = "eth0"
workres = 4
""",
    )

    with pytest.raises(ValueError, match=r"unknown configuration key.*\[capture\].*workres"):
        AuditConfig.from_toml(path)


def test_config_rejects_key_repeated_across_sections(tmp_path: Path):
    path = write_config(
        tmp_path,
        """
[capture]
workers = 2

[analysis]
workers = 3
""",
    )

    with pytest.raises(
        ValueError,
        match=r"multiple sections.*'workers'.*\[analysis\].*\[capture\]",
    ):
        AuditConfig.from_toml(path)


def test_config_rejects_non_table_valid_section(tmp_path: Path):
    path = write_config(tmp_path, 'capture = "eth0"\n')

    with pytest.raises(ValueError, match=r"section \[capture\] must be a table"):
        AuditConfig.from_toml(path)


@pytest.mark.parametrize(
    "toml_value",
    [
        '"password"',
        "42",
        '[["password"]]',
    ],
)
def test_config_requires_sensitive_field_names_array_of_strings(
    tmp_path: Path, toml_value: str
):
    path = write_config(
        tmp_path,
        f"""
[analysis]
extra_sensitive_field_names = {toml_value}
""",
    )

    with pytest.raises(ValueError, match=r"TOML array of strings"):
        AuditConfig.from_toml(path)


@pytest.mark.parametrize(
    ("section", "key", "toml_value"),
    [
        ("output", "output_jsonl", "123"),
        ("output", "operational_jsonl", "true"),
        ("raw_capture", "raw_capture_dir", '["evidence"]'),
    ],
)
def test_config_requires_toml_string_paths(
    tmp_path: Path, section: str, key: str, toml_value: str
):
    path = write_config(
        tmp_path,
        f"""
[{section}]
{key} = {toml_value}
""",
    )

    with pytest.raises(ValueError, match=rf"{key} must be a TOML string path"):
        AuditConfig.from_toml(path)


@pytest.mark.parametrize("read_timeout_ms", [0, 5_001])
def test_config_rejects_capture_timeout_outside_watchdog_bounds(read_timeout_ms: int):
    with pytest.raises(ValueError, match=r"read_timeout_ms must be between 1 and 5000"):
        AuditConfig(read_timeout_ms=read_timeout_ms).validate()


def test_config_rejects_capture_timeout_longer_than_heartbeat_interval():
    with pytest.raises(ValueError, match=r"must not exceed the heartbeat interval"):
        AuditConfig(read_timeout_ms=1_001, heartbeat_seconds=1).validate()


def test_config_rejects_worker_queue_budget_smaller_than_one_batch():
    with pytest.raises(ValueError, match=r"hold one worst-case capture batch"):
        AuditConfig(max_worker_queue_bytes=16 * 1024 * 1024).validate()


def test_config_rejects_excessive_aggregate_worker_queue_budget():
    with pytest.raises(ValueError, match=r"aggregate worker queue byte budget"):
        AuditConfig(workers=8, max_worker_queue_bytes=512 * 1024 * 1024).validate()


def test_cli_reports_invalid_config_without_traceback(tmp_path: Path, capsys):
    config_path = write_config(tmp_path, "[analysys]\nworkers = 4\n")

    assert main(["doctor", "--config", str(config_path)]) == 2
    captured = capsys.readouterr()
    assert "configuration error:" in captured.err
    assert "unknown top-level" in captured.err
    assert "Traceback" not in captured.err


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode policy")
def test_validate_export_cli_rejects_insecure_immediate_parent(
    tmp_path: Path, capsys
):
    parent = tmp_path / "shared-export"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)
    path = parent / "findings.jsonl"
    path.write_bytes(b"{}\n")
    os.chmod(path, 0o600)

    assert main(["validate-export", str(path)]) == 1
    result = capsys.readouterr().out
    assert '"ok": false' in result
    assert "insecure immediate parent" in result


def _stub_doctor_runtime(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("packet_audit.cli._list_pcapy_interfaces", lambda: (["eth0"], None))
    monkeypatch.setattr(
        "packet_audit.cli.DumpcapRing.preflight",
        lambda _self: (True, "synthetic dumpcap preflight"),
    )


def test_doctor_uses_read_only_evidence_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    _stub_doctor_runtime(monkeypatch)
    config = AuditConfig(
        interface="eth0",
        raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )

    assert doctor(config) == 0
    result = json.loads(capsys.readouterr().out)
    evidence = next(
        check for check in result["checks"] if check["check"] == "evidence_paths"
    )
    assert evidence["ok"] is True
    assert not config.output_jsonl.exists()
    assert not config.operational_jsonl.exists()


def test_doctor_rejects_hardlinked_findings_and_operations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    _stub_doctor_runtime(monkeypatch)
    findings = tmp_path / "findings.jsonl"
    operations = tmp_path / "operations.jsonl"
    findings.write_bytes(b"{}\n")
    try:
        os.link(findings, operations)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"hard links unavailable: {exc}")
    if os.name != "nt":
        os.chmod(findings, 0o600)
    config = AuditConfig(
        interface="eth0",
        raw_capture_enabled=False,
        output_jsonl=findings,
        operational_jsonl=operations,
    )

    assert doctor(config) == 1
    result = json.loads(capsys.readouterr().out)
    evidence = next(
        check for check in result["checks"] if check["check"] == "evidence_paths"
    )
    assert evidence["ok"] is False
    assert "same file/inode" in evidence["detail"]


def test_doctor_rejects_missing_enabled_raw_capture_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    _stub_doctor_runtime(monkeypatch)
    config = AuditConfig(
        interface="eth0",
        raw_capture_enabled=True,
        raw_capture_dir=tmp_path / "missing-ring",
        output_jsonl=tmp_path / "findings.jsonl",
        operational_jsonl=tmp_path / "operations.jsonl",
    )

    assert doctor(config) == 1
    result = json.loads(capsys.readouterr().out)
    evidence = next(
        check for check in result["checks"] if check["check"] == "evidence_paths"
    )
    assert evidence["ok"] is False
    assert "raw capture directory" in evidence["detail"]
    assert "does not exist" in evidence["detail"]


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode policy")
def test_doctor_rejects_shared_evidence_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys
):
    _stub_doctor_runtime(monkeypatch)
    parent = tmp_path / "shared"
    parent.mkdir(mode=0o755)
    os.chmod(parent, 0o755)
    config = AuditConfig(
        interface="eth0",
        raw_capture_enabled=False,
        output_jsonl=parent / "findings.jsonl",
        operational_jsonl=parent / "operations.jsonl",
    )

    assert doctor(config) == 1
    result = json.loads(capsys.readouterr().out)
    evidence = next(
        check for check in result["checks"] if check["check"] == "evidence_paths"
    )
    assert evidence["ok"] is False
    assert "insecure immediate parent" in evidence["detail"]
