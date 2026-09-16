from dataclasses import replace

import pytest

from packet_audit.models import Finding, finding_endpoints


@pytest.mark.parametrize("direction,source,destination", [(0, "192.0.2.10", "192.0.2.20"), (1, "192.0.2.20", "192.0.2.10")])
def test_directional_ipv4_endpoints(direction, source, destination):
    finding = Finding(
        event_id="test", session_id="test", observed_timestamp_ns=1,
        emitted_timestamp_ns=2, category="credential", protocol="http",
        detector="test", material_type="test", material={}, confidence="confirmed",
        completeness="complete", flow_id="eth0|-|6|192.0.2.10:34567|192.0.2.20:80|epoch=42",
        direction=direction, packet_ids=(1,), stream_offset=0, attempt_ordinal=1,
    )
    result = finding.to_dict()
    assert result["source_ip"] == source
    assert result["destination_ip"] == destination
    assert result["source"] == {"address": source, "port": 34567 if direction == 0 else 80}
    assert result["destination"]["port"] == (80 if direction == 0 else 34567)
    assert replace(finding, direction=None).to_dict()["source"] is None


def test_ipv6_endpoint_port_separation():
    source, destination = finding_endpoints("eth0|-|6|2001:db8::1:12345|2001:db8::2:443", 1)
    assert source.address == "2001:db8::2" and source.port == 443
    assert destination.address == "2001:db8::1" and destination.port == 12345


@pytest.mark.parametrize("flow,direction", [
    ("legacy-unstructured", 0),
    ("eth0|-|6|invalid:80|192.0.2.1:12", 0),
    ("eth0|-|6|192.0.2.2:70000|192.0.2.1:12", 0),
    ("eth0|-|6|192.0.2.2:80|192.0.2.1:12", None),
])
def test_malformed_or_unknown_endpoints_not_invented(flow, direction):
    assert finding_endpoints(flow, direction) == (None, None)
