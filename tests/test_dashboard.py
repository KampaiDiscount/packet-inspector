from __future__ import annotations

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import stat
import threading

import pytest

from packet_audit.dashboard import (
    CSP, HTML, JS, MAX_JSON_DEPTH, MAX_READ_BYTES, MAX_RECORDS, create_server, normalize_finding, read_page,
)


def write_private(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


@contextmanager
def live_server(tmp_path: Path, require_token=True):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    token_path = tmp_path / "runtime" / "token"
    server = create_server(evidence, port=0, token_file=token_path if require_token else None,
                           require_token=require_token)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
    thread.start()
    try:
        yield server, evidence, token_path
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def request(server, path="/api/findings", token=None, **headers):
    connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
    if token:
        headers["Authorization"] = "Bearer " + token
    connection.request("GET", path, headers=headers)
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


@pytest.mark.parametrize("direction,source,destination", [(0,"10.0.0.1:50000","10.0.0.2:80"), (1,"10.0.0.2:80","10.0.0.1:50000"), (None,None,None)])
def test_legacy_direction(direction, source, destination):
    result = normalize_finding({"flow_id": "eth0|-|6|10.0.0.1:50000|10.0.0.2:80|epoch=2", "direction": direction})
    assert result["source_endpoint"] == source
    assert result["destination_endpoint"] == destination


def test_explicit_endpoints_override_legacy():
    result = normalize_finding({"source": {"address":"2001:db8::1","port":80},
                                "destination_ip":"10.0.0.2", "destination_port":4567,
                                "flow_id":"eth0|-|6|wrong:1|wrong:2", "direction":0})
    assert result["source_endpoint"] == "[2001:db8::1]:80"
    assert result["destination_endpoint"] == "10.0.0.2:4567"


def test_partial_tail_malformed_and_incremental_pagination(tmp_path):
    path = tmp_path / "test.jsonl"
    write_private(path, b'{"n":1}\nmalformed\n[]\n{"n":')
    first = read_page(path)
    assert first["records"] == [{"n":1}]
    assert first["skipped"] == 2
    with path.open("ab") as stream:
        stream.write(b'2}\n{"n":3}\n')
    second = read_page(path, first["cursor"], limit=1)
    assert second["records"] == [{"n":2}]
    assert second["more"]
    third = read_page(path, second["cursor"], limit=1)
    assert third["records"] == [{"n":3}]
    assert not third["more"]
    assert read_page(path, third["cursor"])["records"] == []


def test_initial_tail_and_limits_are_bounded(tmp_path):
    path = tmp_path / "test.jsonl"
    write_private(path, b'{"padding":"' + b'x' * (2 * MAX_READ_BYTES) + b'"}\n' + b'{"ok":true}\n' * 800)
    page = read_page(path, limit=99999)
    assert len(page["records"]) == MAX_RECORDS
    assert page["bytes_read"] == MAX_READ_BYTES
    assert page["window_limited"]
    assert all(row == {"ok":True} for row in page["records"])


def test_oversized_incremental_line_does_not_stall_reader(tmp_path):
    path = tmp_path / "test.jsonl"
    write_private(path, b'{"n":1}\n')
    first = read_page(path)
    with path.open("ab") as stream:
        stream.write(b'{"padding":"' + b'x' * (MAX_READ_BYTES + 300) + b'"}\n{"n":2}\n')
    second = read_page(path, first["cursor"])
    assert second["skipped"] == 1
    assert second["records"] == []
    third = read_page(path, second["cursor"])
    assert third["records"] == [{"n":2}]


def test_rotation_and_truncation_reset_cursor(tmp_path):
    path = tmp_path / "test.jsonl"
    write_private(path, b'{"padding":"long data for size change"}\n')
    first = read_page(path)
    write_private(path, b'{"n":2}\n')
    second = read_page(path, first["cursor"])
    assert second["reset"]
    assert second["records"] == [{"n":2}]
    path.rename(tmp_path / "old.jsonl")
    write_private(path, b'{"n":3}\n')
    third = read_page(path, second["cursor"])
    assert third["reset"]
    assert third["records"] == [{"n":3}]


def test_missing_file_and_invalid_cursor(tmp_path):
    assert read_page(tmp_path / "missing")["missing"]
    with pytest.raises(ValueError, match="cursor"):
        read_page(tmp_path / "missing", "not:a:cursor")


def test_invalid_evidence_numbers_and_depth_are_skipped(tmp_path):
    path = tmp_path / "test.jsonl"
    write_private(path, b'{"x":NaN}\n{"x":1e999}\n' + b'{"x":' + b'[' * 3000 + b'0' + b']' * 3000 + b'}\n{"ok":1}\n')
    page = read_page(path)
    assert page["skipped"] == 3
    assert page["records"] == [{"ok":1}]


def test_explicit_json_depth_limit_and_quoted_delimiters(tmp_path):
    path = tmp_path / "test.jsonl"
    allowed = b'{"x":' + b'[' * (MAX_JSON_DEPTH - 1) + b'0' + b']' * (MAX_JSON_DEPTH - 1) + b'}\n'
    too_deep = b'{"x":' + b'[' * MAX_JSON_DEPTH + b'0' + b']' * MAX_JSON_DEPTH + b'}\n'
    # Quotes, escaped quotes/backslashes and thousands of literal brackets
    # inside strings must not increase the structural depth.
    quoted = {"material": '[' * 3000 + '{' * 3000 + '\\"\\\\' + '}' * 3000 + ']' * 3000,
              "nested": {"key": "quoted \\\" [ { text"}}
    write_private(path, allowed + too_deep + (json.dumps(quoted) + "\n").encode())
    page = read_page(path)
    assert page["skipped"] == 1
    assert len(page["records"]) == 2
    assert page["records"][1] == quoted
    assert json.dumps(page, allow_nan=False)


def test_auth_headers_sensitive_content_and_no_logs(tmp_path, capsys):
    with live_server(tmp_path) as (server, evidence, token_path):
        payload = '<img src=x onerror="alert(1)"></script><script>secret</script>'
        write_private(evidence / "findings-unredacted.jsonl", (json.dumps({"material":payload}) + "\n").encode())
        token = token_path.read_text().strip()
        assert len(token) >= 40
        if os.name != "nt":
            assert stat.S_IMODE(token_path.stat().st_mode) == 0o600
        assert request(server)[0] == 401
        assert request(server, token="wrong")[0] == 401
        status, headers, body = request(server, token=token)
        assert status == 200
        assert json.loads(body)["records"][0]["material"] == payload
        assert headers["Content-Security-Policy"] == CSP
        assert headers["Cache-Control"].startswith("no-store")
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert headers["X-Frame-Options"] == "DENY"
        assert not any(name.lower().startswith("access-control-") for name in headers)
        assert request(server, "/?token=" + token)[0] == 404
        assert request(server, "/api/findings?token=" + token)[0] == 401
    captured = capsys.readouterr()
    assert token not in captured.out + captured.err
    assert payload not in captured.out + captured.err


@pytest.mark.parametrize("require_token", [True, False])
def test_host_origin_and_absolute_target_rejection(tmp_path, require_token):
    with live_server(tmp_path, require_token) as (server, _, token_path):
        token = token_path.read_text().strip() if require_token else None
        assert request(server, token=token, Host="attacker.test")[0] == 403
        assert request(server, token=token, Origin="http://attacker.test")[0] == 403
        assert request(server, token=token, Origin="null")[0] == 403
        assert request(server, token=token, Origin="http://127.0.0.1:1")[0] == 403
        assert request(server, token=token, **{"Sec-Fetch-Site":"cross-site"})[0] == 403
        assert request(server, token=token, Origin=f"http://127.0.0.1:{server.server_port}")[0] == 200
        assert request(server, "http://attacker.test/api/findings", token=token, Host=f"127.0.0.1:{server.server_port}")[0] == 400


def test_static_assets_cannot_execute_captured_html(tmp_path):
    with live_server(tmp_path) as (server, _, _):
        for path in ("/", "/app.js", "/app.css"):
            assert request(server, path)[0] == 200
    assert "innerHTML" not in JS
    assert "textContent" in JS
    assert "localStorage" not in JS
    assert "sessionStorage" not in JS
    assert "history.replaceState" in JS
    assert "https://" not in HTML + JS
    assert "unsafe-inline" not in CSP


@pytest.mark.parametrize("require_token", [True, False])
def test_non_loopback_binding_rejected_before_token_write(tmp_path, require_token):
    for host in ("0.0.0.0", "192.0.2.189", "::"):
        with pytest.raises(ValueError, match="loopback"):
            create_server(tmp_path, host=host, require_token=require_token)
    assert not (tmp_path / "token").exists()


@pytest.mark.parametrize("require_token", [True, False])
def test_bad_query_and_mutation_endpoints(tmp_path, require_token):
    with live_server(tmp_path, require_token) as (server, _, token_path):
        token = token_path.read_text().strip() if require_token else None
        for suffix in ("?limit=bad", "?cursor=bad", "?limit=1&limit=2", "?path=/etc/passwd"):
            assert request(server, "/api/findings" + suffix, token=token)[0] == 400
        assert request(server, "/api/../../etc/passwd", token=token)[0] == 404
        connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
        connection.request("POST", "/api/findings", headers={"Authorization":"Bearer " + token} if token else {})
        response = connection.getresponse()
        assert response.status == 405
        response.read()
        connection.close()


def test_token_free_mode_connects_without_creating_token(tmp_path):
    with live_server(tmp_path, require_token=False) as (server, evidence, token_path):
        write_private(evidence / "findings-unredacted.jsonl", b'{"material":"synthetic"}\n')
        status, headers, body = request(server)
        assert status == 200
        assert json.loads(body)["records"][0]["material"] == "synthetic"
        assert headers["Cache-Control"].startswith("no-store")
        assert not any(name.lower().startswith("access-control-") for name in headers)
        assert not token_path.exists()
        assert not (evidence / ".dashboard-token").exists()
        assert request(server, "/api/findings?token=unused")[0] == 400
        html = request(server, "/")[2].decode()
        assert 'id="login"' not in html
        assert 'id="token"' not in html
        assert "Waiting for access token" not in html
        javascript = request(server, "/app.js")[2].decode()
        assert "const requireToken = false;" in javascript
        assert "(requireToken && !token)" in javascript
        assert "setInterval(poll,2000);poll();" in javascript


def test_no_auth_and_token_file_conflict(tmp_path):
    from packet_audit.cli import build_parser

    args = build_parser().parse_args(["serve", "--evidence-dir", str(tmp_path), "--no-auth"])
    assert args.no_auth and args.token_file is None
    with pytest.raises(SystemExit):
        build_parser().parse_args(["serve", "--evidence-dir", str(tmp_path),
                                   "--no-auth", "--token-file", str(tmp_path / "token")])
    with pytest.raises(ValueError, match="token-free"):
        create_server(tmp_path, port=0, require_token=False, token_file=tmp_path / "token")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_shared_evidence_and_symlinks_rejected(tmp_path):
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    path = evidence / "findings-unredacted.jsonl"
    write_private(path, b'{}\n')
    path.chmod(0o644)
    with pytest.raises(PermissionError, match="owner-private"):
        read_page(path)
    path.unlink()
    target = tmp_path / "target"
    write_private(target, b'{}\n')
    path.symlink_to(target)
    with pytest.raises(PermissionError, match="regular"):
        read_page(path)
    evidence.chmod(0o755)
    with pytest.raises(PermissionError, match="owner-private"):
        create_server(evidence, port=0)
