from pathlib import Path
import os

import pytest

from packet_audit.config import AuditConfig
from packet_audit.raw_capture import DumpcapRing, build_dumpcap_command


def test_dumpcap_ring_command(tmp_path: Path):
    cfg = AuditConfig(
        interface="eth9",
        bpf="tcp or udp",
        raw_capture_dir=tmp_path / "ring",
        raw_capture_file_mb=100,
        raw_capture_files=7,
        raw_capture_duration_seconds=30,
    )
    command = build_dumpcap_command(cfg)
    joined = " ".join(command)
    assert "-i eth9" in joined
    assert "filesize:100000" in command
    assert "files:7" in command
    assert "duration:30" in command
    assert "tcp or udp" in command


@pytest.mark.skipif(os.name == "nt", reason="POSIX directory mode policy")
def test_dumpcap_direct_start_refuses_shared_capture_directory(
    tmp_path: Path, monkeypatch
):
    capture_dir = tmp_path / "shared-ring"
    capture_dir.mkdir(mode=0o755)
    os.chmod(capture_dir, 0o755)
    cfg = AuditConfig(raw_capture_dir=capture_dir)
    ring = DumpcapRing(cfg)

    def unexpected_popen(*args, **kwargs):
        raise AssertionError("dumpcap must not start for an insecure destination")

    monkeypatch.setattr("packet_audit.raw_capture.subprocess.Popen", unexpected_popen)
    with pytest.raises(PermissionError, match="insecure evidence directory"):
        ring.start()
