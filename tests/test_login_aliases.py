"""Primary-source login families and bounded alias normalization, fake data only."""
import json
from urllib.parse import urlencode

import pytest

from packet_audit.detectors import SensitiveDetector
from packet_audit.http_forms import field_role
from tests.test_http_forms import chunk, fields, request


PAIRS = [
    ("wordpress", "log", "pwd"),
    ("django", "username", "password"),
    ("spring", "username", "password"),
    ("spring-legacy", "j_username", "j_password"),
    ("keycloak", "username", "password"),
    ("aspnet", "Input.Email", "Input.Password"),
    ("aspnet-username", "Input.UserName", "Input.Password"),
    ("drupal", "name", "pass"),
    ("phpmyadmin", "pma_username", "pma_password"),
    ("roundcube", "_user", "_pass"),
    ("symfony", "_username", "_password"),
    ("testfire", "uid", "passw"),
    ("vulnweb-asp", "tfUName", "tfUPass"),
    ("nested", "credentials[user_name]", "credentials[password_confirmation]"),
    ("nested-weak", "credentials[login]", "credentials[passw]"),
    ("controls", "ctl00$Main$txtUserName", "ctl00$Main$txtPassword"),
    ("camelcase", "loginEmail", "accountPassword"),
]


@pytest.mark.parametrize("label,identity,secret", PAIRS, ids=[p[0] for p in PAIRS])
@pytest.mark.parametrize("encoding", ["form", "json"])
def test_source_backed_pairs_split_and_repeated(label, identity, secret, encoding):
    data = {identity: "Fake User", secret: "Fake+Pass&Only!"}
    if encoding == "form":
        body, content_type = urlencode(data).encode(), b"application/x-www-form-urlencoded"
    else:
        body, content_type = json.dumps(data).encode(), b"application/json"
    payload = request(body, content_type)
    detector = SensitiveDetector("synthetic-alias-matrix")
    found = []
    stream = payload * 3
    for offset in range(0, len(stream), 7):
        found.extend(detector.process_stream(chunk(stream[offset:offset + 7], offset, offset + 1)))
    found = fields(found)
    assert len(found) == 3
    assert len({finding.event_id for finding in found}) == 3
    for finding in found:
        assert finding.material["name"] == secret
        assert finding.material["value"] == data[secret]
        assert finding.material["username"] == data[identity]
        assert finding.material["username_field"] == identity
        assert finding.fields["http_body_complete"] is True
        assert finding.packet_ids_complete
        assert finding.to_dict()["source_ip"] == "192.0.2.10"


@pytest.mark.parametrize("name", [
    "passw", "PASSWORD", "old_password", "new_password1", "new_password2",
    "password_confirmation", "currentPassword", "confirmPassword", "password3",
    "credentials[password_confirmation]", "auth[txtPassword]", "payrollPassword",
    "otp", "totp", "one_time_code", "mfaCode", "accessToken", "clientSecret",
])
def test_secret_variants(name):
    found = fields(SensitiveDetector("test").process_stream(chunk(request(
        urlencode({name: "FakeOnly123"}).encode()
    ))))
    assert len(found) == 1
    assert found[0].material["name"] == name


@pytest.mark.parametrize("name", ["uid", "name", "log", "_user", "Input.Email", "username", "login"])
def test_identity_alone_is_not_a_secret(name):
    assert fields(SensitiveDetector("test").process_stream(chunk(request(
        urlencode({name: "FakeIdentity"}).encode()
    )))) == []


@pytest.mark.parametrize("name", [
    "bypass", "compass", "passenger", "password_policy", "password_enabled",
    "passwordLength", "password[metadata]", "secret[description]", "token_count",
    "uid_count", "username_label", "displayName", "display_name", "code", "id", "query", "btnSubmit",
])
def test_unrelated_names_are_not_credential_values(name):
    assert field_role(name, {"password", "pass", "token", "secret"}) is None
    assert fields(SensitiveDetector("test").process_stream(chunk(request(
        urlencode({name: "UnrelatedValue"}).encode()
    )))) == []


def test_submit_control_does_not_mask_stronger_username():
    found = fields(SensitiveDetector("test").process_stream(chunk(request(
        b"username=FakeUser&password=FakePass&login=Sign+In&name=DisplayName"
    ))))
    assert len(found) == 1
    assert found[0].material["username_field"] == "username"
    assert found[0].material["username"] == "FakeUser"


def test_ambiguous_strong_identities_remain_unpaired():
    found = fields(SensitiveDetector("test").process_stream(chunk(request(
        b"uid=First&email=Second&passw=FakePass&name=Third"
    ))))
    assert len(found) == 1
    assert "username" not in found[0].material
    assert "not inferred" in found[0].fields["username_context"]


def test_configured_exact_alias_remains_authoritative():
    assert field_role("PASSWORD_POLICY", {"password_policy"}) == "sensitive"
    found = fields(SensitiveDetector("test", extra_sensitive_field_names=("unusual_field",))
                   .process_stream(chunk(request(b"uid=FakeUser&unusual_field=FakePass"))))
    assert len(found) == 1
    assert found[0].material["username"] == "FakeUser"


def test_testfire_complete_request_at_every_packet_split():
    payload = request(b"uid=FakeUser&passw=FakePass&btnSubmit=Login")
    for split in range(1, len(payload)):
        detector = SensitiveDetector("test")
        assert not fields(detector.process_stream(chunk(payload[:split])))
        found = fields(detector.process_stream(chunk(payload[split:], split, 2)))
        assert len(found) == 1
        assert found[0].material["username_field"] == "uid"
        assert found[0].material["name"] == "passw"
