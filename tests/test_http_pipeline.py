"""End-to-end fake login replay through capture, workers and private writer."""
import json
import pytest

from packet_audit.config import AuditConfig
from packet_audit.supervisor import AuditSupervisor
from tests.pcap_builder import ethernet_ipv4_tcp, write_pcap


@pytest.mark.parametrize("identity,secret", [("tfUName", "tfUPass"), ("uid", "passw"),
                                            ("log", "pwd"), ("name", "pass")])
def test_replay_final_password_split_and_repeated_with_directional_endpoints(tmp_path, identity, secret):
    body = f"{identity}=FakeUser&{secret}=FakePass".encode()
    request = (
        b"POST /Login.asp HTTP/1.1\r\nHost: synthetic.invalid\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
    )
    stream = request * 3
    packets = [ethernet_ipv4_tcp(b"", seq=1000, flags=0x02)]
    # Segment boundaries deliberately fall inside headers and credential values.
    for offset in range(0, len(stream), 11):
        packets.append(ethernet_ipv4_tcp(stream[offset:offset + 11], seq=1001 + offset))
    packets.append(ethernet_ipv4_tcp(b"", seq=1001 + len(stream), flags=0x04))
    capture = tmp_path / "synthetic-asp-repeat.pcap"
    write_pcap(capture, packets)
    config = AuditConfig(
        interface="offline", workers=1, queue_size=128, raw_capture_enabled=False,
        output_jsonl=tmp_path / "findings.jsonl", operational_jsonl=tmp_path / "operations.jsonl",
        heartbeat_seconds=1,
    )
    result = AuditSupervisor(config, offline_path=capture).run()
    assert result["verdict"] == "complete", result["incomplete_reasons"]
    records = [json.loads(line) for line in config.output_jsonl.read_text().splitlines()]
    logins = [r for r in records if r["detector"] == "sensitive_field" and r["material"]["name"] == secret]
    assert len(logins) == 3
    assert len({r["event_id"] for r in logins}) == 3
    for record in logins:
        assert record["material"]["value"] == "FakePass"
        assert record["material"]["username"] == "FakeUser"
        assert record["fields"]["http_body_complete"] is True
        assert record["source_ip"] == "10.0.0.10"
        assert record["source_port"] == 50000
        assert record["destination_ip"] == "10.0.0.20"
        assert record["destination_port"] == 80
        assert len(record["packet_ids"]) > 1
    assert result["worker_findings_emitted"] == result["writer_findings_written"]
