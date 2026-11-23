"""Contract tests for the ortie boundary.

Ortie 3 dropped ORTIE_CONFIG and renamed every `--json` key, so these tests pin the
translation layer rather than the tool bodies: the same server.py must keep working
with the ortie 2 and ortie 3 binaries.
"""

import json

import pytest

import server

# Real payload shapes, taken from `ortie json-schema` for each tag.
GRANT_V2 = {
    "authorization_uri": "https://accounts.google.com/o/oauth2/v2/auth?x=1",
    "state": "state-abc",
    "pkce_code_verifier": "verifier-abc",
    "interactive": True,
}
GRANT_V3 = {
    "authorizationUri": "https://accounts.google.com/o/oauth2/v2/auth?x=1",
    "state": "state-abc",
    "pkceCodeVerifier": "verifier-abc",
    "redirectUri": "http://localhost:18081/",
}
DEVICE_V2 = {
    "device_code": "device-abc",
    "user_code": "USER-123",
    "verification_uri": "https://microsoft.com/devicelogin",
    "expires_in": 900,
    "interval": 5,
    "interactive": False,
}
DEVICE_V3 = {
    "deviceCode": "device-abc",
    "userCode": "USER-123",
    "verificationUri": "https://microsoft.com/devicelogin",
    "expiresIn": 900,
    "interval": 5,
}


# --------------------------------------------------------------------- command lines


def test_ortie_args_always_name_the_config(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "CONFIG", tmp_path)
    args = server._ortie_args("token", "show", "-a", "gmail")
    assert args[:3] == [server.ORTIE, "-c", str(tmp_path / "ortie.toml")]
    assert args[3:] == ["token", "show", "-a", "gmail"]


def test_himalaya_token_commands_name_the_config(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "CONFIG", tmp_path)
    monkeypatch.setattr(server, "TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(server, "ATTACHMENTS", tmp_path / "attachments")
    server.render_configs()

    hima = (tmp_path / "himalaya.toml").read_text()
    assert hima.count('"-c"') == 2, hima
    assert hima.count("ortie.toml") == 2, hima


# --------------------------------------------------------------------- grant payloads


@pytest.mark.parametrize("payload", [GRANT_V2, GRANT_V3], ids=["v2", "v3"])
def test_authorize_start_reads_either_grant_shape(payload, tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ACCOUNT", "gmail")
    monkeypatch.setattr(server, "PENDING", tmp_path / "pending-auth.json")
    monkeypatch.setattr(server, "_json_or_error", lambda *a, **k: (payload, None))

    result = server.mail_authorize_start()

    assert result["ok"] is True
    assert result["url"] == "https://accounts.google.com/o/oauth2/v2/auth?x=1"
    pending = json.loads((tmp_path / "pending-auth.json").read_text())
    assert pending["state"] == "state-abc"
    assert pending["verifier"] == "verifier-abc"
    # v2 has no redirectUri; the configured callback is the fallback either way.
    assert pending["redirect"].startswith("http://localhost:18081")


@pytest.mark.parametrize("payload", [DEVICE_V2, DEVICE_V3], ids=["v2", "v3"])
def test_grant_start_fields_read_either_device_shape(payload):
    fields = server._grant_start_fields(payload)
    assert fields["device_code"] == "device-abc"
    assert fields["user_code"] == "USER-123"
    assert fields["verification_uri"] == "https://microsoft.com/devicelogin"
    assert fields["expires_in"] == 900
    assert fields["interval"] == 5


def test_authorize_start_refuses_incomplete_device_payload(monkeypatch):
    monkeypatch.setattr(server, "ACCOUNT", "m365")
    monkeypatch.setattr(server, "_json_or_error", lambda *a, **k: ({}, None))

    result = server.mail_authorize_start()

    assert result["ok"] is False
    assert "device code" in result["error"]


def test_authorize_start_refuses_incomplete_authorization_payload(monkeypatch):
    monkeypatch.setattr(server, "ACCOUNT", "gmail")
    monkeypatch.setattr(server, "_json_or_error", lambda *a, **k: ({}, None))

    result = server.mail_authorize_start()

    assert result["ok"] is False
    assert "incomplete" in result["error"]


# --------------------------------------------------------------------- token inspect


def test_token_expiry_reads_v2_shape(monkeypatch):
    payload = {
        "token_type": "Bearer",
        "issued_at": 1700000000,
        "expires_in": 3599,
        "scope": "https://mail.google.com/",
        "with_refresh_token": True,
    }
    monkeypatch.setattr(server, "_run", lambda *a, **k: (0, json.dumps(payload), ""))

    assert server._token_expiry() == {
        "token_type": "Bearer",
        "scope": "https://mail.google.com/",
        "expires_in": 3599,
    }


def test_token_expiry_derives_lifetime_from_v3_instants(monkeypatch):
    payload = {
        "tokenType": "Bearer",
        "issuedAt": "2026-11-22T14:00:00Z",
        "expiresAt": "2026-11-22T14:59:59Z",
        "withRefreshToken": True,
        "scope": "https://mail.google.com/",
    }
    monkeypatch.setattr(server, "_run", lambda *a, **k: (0, json.dumps(payload), ""))

    assert server._token_expiry() == {
        "token_type": "Bearer",
        "scope": "https://mail.google.com/",
        "expires_in": 3599,
    }


def test_token_expiry_stays_empty_when_ortie_fails(monkeypatch):
    monkeypatch.setattr(server, "_run", lambda *a, **k: (1, '{"code":"token-missing","error":"x"}', ""))
    assert server._token_expiry() == {}


# --------------------------------------------------------------------- failures


def test_error_object_reads_the_stable_code():
    code, message = server._error_object(
        '{"code":"grant-invalid","error":"Refresh access token error","sources":["invalid_grant"]}'
    )
    assert code == "grant-invalid"
    assert "invalid_grant" in message


def test_json_or_error_surfaces_the_code(monkeypatch):
    monkeypatch.setattr(
        server, "_run", lambda *a, **k: (2, '{"code":"usage-invalid","error":"bad flag"}', "")
    )
    data, err = server._json_or_error([server.ORTIE, "-c", "x", "token", "bogus"])
    assert data is None
    assert err is not None and err.startswith("usage-invalid: bad flag")


def test_classify_grant_invalid_asks_for_reauth():
    status, detail = server._classify_failure(
        1, '{"code":"grant-invalid","error":"Refresh access token error"}', ""
    )
    assert status == "reauth-required"
    assert "grant-invalid" in detail


def test_classify_v2_text_failure_still_asks_for_reauth():
    status, _ = server._classify_failure(1, "", "invalid_grant: token has been expired or revoked")
    assert status == "reauth-required"


def test_classify_rate_limit_is_upstream():
    status, _ = server._classify_failure(1, '{"code":"rate-limited","error":"HTTP 429"}', "")
    assert status == "upstream-error"


def test_classify_unreadable_token_file_asks_for_reauth():
    status, _ = server._classify_failure(
        1,
        "",
        "Error: Parse access token from command error\nCaused by: missing field `access_token`",
    )
    assert status == "reauth-required"


def test_classify_config_missing_names_the_configuration():
    status, detail = server._classify_failure(
        1,
        '{"code":null,"error":"No configuration found at /data/config/ortie.toml, start from the sample"}',
        "",
    )
    assert status == "upstream-error"
    assert detail.startswith("configuration error:")
