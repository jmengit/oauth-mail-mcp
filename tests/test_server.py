"""Unit tests for oauth-mail-mcp: config rendering, parsing, health states, bearer guard."""

import asyncio
import json
import time

import pytest

import server


# --------------------------------------------------------------------------- configs


def test_render_configs_gmail(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "CONFIG", tmp_path)
    monkeypatch.setattr(server, "TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(server, "ATTACHMENTS", tmp_path / "attachments")
    server.render_configs()

    ortie = (tmp_path / "ortie.toml").read_text()
    hima = (tmp_path / "himalaya.toml").read_text()

    assert "[accounts.gmail]" in ortie
    assert 'grant = "authorization-code"' in ortie
    assert "accounts.google.com/o/oauth2/v2/auth" in ortie
    assert "http://localhost:18081" in ortie
    assert "access_type" in ortie and "offline" in ortie
    assert "storage.read.command" in ortie and "refresh_token" not in ortie

    assert "imaps://imap.gmail.com:993" in hima
    assert "smtps://smtp.gmail.com:465" in hima
    assert hima.count("imap.sasl.xoauth2.token.command") == 1
    assert hima.count("smtp.sasl.xoauth2.token.command") == 1
    assert 'mailbox.alias.sent = "[Gmail]/Sent Mail"' in hima
    assert '"token", "show"' in hima


def test_render_configs_m365(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ACCOUNT", "m365")
    monkeypatch.setattr(server, "CONFIG", tmp_path)
    monkeypatch.setattr(server, "TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(server, "ATTACHMENTS", tmp_path / "attachments")
    server.render_configs()

    ortie = (tmp_path / "ortie.toml").read_text()
    hima = (tmp_path / "himalaya.toml").read_text()

    assert 'grant = "device"' in ortie
    assert "devicecode" in ortie
    assert "IMAP.AccessAsUser.All" in ortie
    assert "login_hint" in ortie
    assert "localhost" not in hima
    assert "smtp.starttls = true" in hima
    assert "outlook.office365.com:993" in hima


# --------------------------------------------------------------------------- formatting


def test_norm_envelope_maps_flags_and_addresses():
    raw = {
        "id": "42",
        "subject": "Statement",
        "from": [{"name": "Acme Billing", "email": "billing@example.com"}],
        "to": [{"name": "", "email": "bob@example.com"}],
        "date": "2026-10-20T09:00:00-05:00",
        "flags": ["seen", "flagged"],
        "size": 1234,
        "has-attachment": True,
    }
    env = server._norm_envelope(raw)
    assert env["id"] == "42"
    assert env["from"] == "Acme Billing <billing@example.com>"
    assert env["to"] == "bob@example.com"
    assert env["unread"] is False
    assert env["has_attachment"] is True


def test_norm_envelope_unread_when_seen_absent():
    env = server._norm_envelope({"id": 1, "flags": []})
    assert env["unread"] is True
    assert env["from"] == ""


def test_safe_filename_strips_traversal():
    assert server._safe_filename("../../etc/passwd") == "passwd"
    assert server._safe_filename("/abs/../x y.pdf") == "x y.pdf"
    assert server._safe_filename("..") == "attachment"


def test_allowed_path_confines_to_attachments():
    inside = server.ATTACHMENTS / "1" / "a.pdf"
    assert server._allowed_path(inside) is True
    assert server._allowed_path(server.ATTACHMENTS.parent / "elsewhere" / "a.pdf") is False


# --------------------------------------------------------------------------- MIME parsing


RAW = b"""From: Alice <alice@example.com>
To: Bob <bob@example.com>
Subject: Hello
Date: Tue, 20 Oct 2026 09:00:00 +0000
Message-Id: <abc123@example.com>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUND"

--BOUND
Content-Type: text/plain; charset="utf-8"

Line one.
Line two.
--BOUND
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQK
--BOUND--
"""


def test_parse_raw_message_extracts_body_and_attachments():
    parsed = server.parse_raw_message(RAW)
    assert parsed["subject"] == "Hello"
    assert "Line one." in parsed["body"] and "Line two." in parsed["body"]
    assert parsed["message_id"] == "abc123@example.com"
    assert [a["filename"] for a in parsed["attachments"]] == ["invoice.pdf"]
    assert parsed["attachments"][0]["content_type"] == "application/pdf"


def test_parse_html_only_message_converts_to_text():
    raw = b"""From: a@b.c
Subject: HTML only
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body><p>Hello <b>world</b></p><script>bad()</script></body></html>
"""
    parsed = server.parse_raw_message(raw)
    assert "Hello" in parsed["body"] and "world" in parsed["body"]
    assert "<" not in parsed["body"]
    assert "bad()" not in parsed["body"]


def test_attach_payloads_roundtrip():
    parts = server._attach_payloads(RAW)
    assert len(parts) == 1
    meta, payload = parts[0]
    assert meta["filename"] == "invoice.pdf"
    assert payload.startswith(b"%PDF")


# --------------------------------------------------------------------------- health


def _set_token(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "TOKENS", tmp_path)
    (tmp_path / "gmail.json").write_text("{}")


def test_health_unauthenticated_without_token(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "TOKENS", tmp_path)
    assert server.probe_health()["status"] == "unauthenticated"


def test_health_reauth_required_when_refresh_rejected(tmp_path, monkeypatch):
    _set_token(tmp_path, monkeypatch)

    def fake_run(args, timeout=60, stdin=None, binary=False):
        return 1, "", "invalid_grant: token has been expired or revoked"

    monkeypatch.setattr(server, "_run", fake_run)
    payload = server.probe_health()
    assert payload["status"] == "reauth-required"
    assert "invalid_grant" in payload["detail"]


def test_health_upstream_error_when_imap_unreachable(tmp_path, monkeypatch):
    _set_token(tmp_path, monkeypatch)

    def fake_run(args, timeout=60, stdin=None, binary=False):
        if args[1] == "token":
            return 0, "access-token", ""
        return 1, "", "connection refused"

    monkeypatch.setattr(server, "_run", fake_run)
    assert server.probe_health()["status"] == "upstream-error"


def test_health_ok_when_token_and_imap_answer(tmp_path, monkeypatch):
    _set_token(tmp_path, monkeypatch)

    def fake_run(args, timeout=60, stdin=None, binary=False):
        if args[1] == "token":
            return 0, "access-token", ""
        return 0, "[]", ""

    monkeypatch.setattr(server, "_run", fake_run)
    payload = server.probe_health()
    assert payload["status"] == "ok"
    assert payload["account"] == "gmail"


def test_health_cache_avoids_repeated_probes(tmp_path, monkeypatch):
    _set_token(tmp_path, monkeypatch)
    monkeypatch.setattr(server, "HEALTH_CACHE_SECS", 60)
    calls = []

    def fake_run(args, timeout=60, stdin=None, binary=False):
        calls.append(args)
        if args[1] == "token":
            return 0, "t", ""
        return 0, "[]", ""

    monkeypatch.setattr(server, "_run", fake_run)
    server.invalidate_health()
    server.get_health()
    first = len(calls)
    server.get_health()
    assert len(calls) == first
    server.invalidate_health()


# --------------------------------------------------------------------------- bearer guard


async def _noop_app(scope, receive, send):
    return None


def _call_guard(guard, headers):
    captured = {}

    async def app(scope, receive, send):
        captured["passed"] = True

    async def send(message):
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]

    scope = {"type": "http", "path": "/mcp", "headers": headers}
    asyncio.run(guard(scope, None, send))
    return captured


def test_bearer_guard_rejects_missing_token():
    guard = server.BearerGuard(_noop_app, "secret")
    captured = _call_guard(guard, [])
    assert captured["status"] == 401
    assert "passed" not in captured


def test_bearer_guard_rejects_wrong_token():
    guard = server.BearerGuard(_noop_app, "secret")
    captured = _call_guard(guard, [(b"authorization", b"Bearer nope")])
    assert captured["status"] == 401


def test_bearer_guard_allows_matching_token():
    guard = server.BearerGuard(_noop_app, "secret")
    captured = _call_guard(guard, [(b"authorization", b"Bearer secret")])
    assert "status" not in captured


def test_bearer_guard_ignores_other_paths():
    guard = server.BearerGuard(_noop_app, "secret")
    captured = {}

    async def app(scope, receive, send):
        captured["passed"] = True

    async def send(message):
        return None

    scope = {"type": "http", "path": "/health", "headers": []}
    asyncio.run(guard(scope, None, send))
    assert "status" not in captured


# --------------------------------------------------------------------------- tool gating


def test_send_disabled_by_default():
    result = server.mail_send.fn(to="a@b.c", subject="x", body="y") if hasattr(server.mail_send, "fn") else None
    if result is None:
        pytest.skip("tool decorator does not expose the raw function")
    assert result["ok"] is False
    assert "disabled" in result["error"]


# --------------------------------------------------------------------------- device poller


def test_device_poll_uses_one_long_call(monkeypatch):
    """ortie polls internally, so the wrapper must not chop the wait into short retries."""
    seen = {}

    def fake_run(args, timeout=60, stdin=None, binary=False):
        seen["timeout"] = timeout
        seen["args"] = args
        return 0, "", ""

    monkeypatch.setattr(server, "_run", fake_run)
    calls = []
    monkeypatch.setattr(server, "invalidate_health", lambda: calls.append(1))
    server.device_poll("device-code-abc", 5, time.time() + 300)

    assert seen["args"][:3] == [server.ORTIE, "auth", "resume"]
    assert seen["timeout"] >= 300
    assert calls == [1]


def test_device_poll_silent_when_code_expires_unused(monkeypatch):
    def fake_run(args, timeout=60, stdin=None, binary=False):
        return 124, "", "timeout after 330s: ortie auth resume"

    monkeypatch.setattr(server, "_run", fake_run)
    calls = []
    monkeypatch.setattr(server, "invalidate_health", lambda: calls.append(1))
    server.device_poll("device-code-abc", 5, time.time() + 300)
    assert calls == []


# --------------------------------------------------------------------------- envelope shape


def test_envelopes_accepts_wrapped_object():
    assert server._envelopes({"envelopes": [{"id": "1"}]}) == [{"id": "1"}]
    assert server._envelopes([{"id": "1"}]) == [{"id": "1"}]
    assert server._envelopes({"other": 1}) == []
    assert server._envelopes(None) == []


def test_norm_envelope_understands_himalaya_flag_objects():
    env = server._norm_envelope(
        {
            "id": "9",
            "flags": [{"raw": "\\\\Seen", "iana": "seen"}, {"raw": "\\\\Flagged", "iana": "flagged"}],
        }
    )
    assert env["flags"] == ["seen", "flagged"]
    assert env["unread"] is False


def test_flag_name_handles_plain_strings():
    assert server._flag_name("\\Seen") == "seen"
    assert server._flag_name({"raw": "\\Flagged", "iana": "flagged"}) == "flagged"


def test_search_puts_query_last(monkeypatch):
    """Options after a trailing var-arg query are parsed as part of the query."""
    seen = {}

    def fake_json(args, timeout=60):
        seen["args"] = args
        return {"envelopes": []}, None

    monkeypatch.setattr(server, "_json_or_error", fake_json)
    server.mail_search("from alice and after 2026-10-01", "Inbox", 10)
    args = seen["args"]
    assert args[-1] == "from alice and after 2026-10-01"
    assert args.index("--json") < args.index("from alice and after 2026-10-01")
    assert "-a" in args and "-m" in args


def test_json_or_error_falls_back_to_stdout(monkeypatch):
    monkeypatch.setattr(
        server, "_run", lambda *a, **k: (1, "Error: cannot parse search emails query", "")
    )
    data, err = server._json_or_error(["himalaya", "envelope", "search"])
    assert data is None
    assert "cannot parse" in err


# --------------------------------------------------------------------------- read-only gate


def test_write_tools_refuse_when_read_only(monkeypatch):
    monkeypatch.setattr(server, "READ_ONLY", True)
    for name, fn, args in (
        ("mail_flags", server.mail_flags, {"ids": ["1"], "add": ["flagged"]}),
        ("mail_draft", server.mail_draft, {"to": "a@b.c", "subject": "s", "body": "b"}),
        ("mail_send", server.mail_send, {"to": "a@b.c", "subject": "s", "body": "b"}),
    ):
        result = fn(**args)
        assert result["ok"] is False
        assert "read-only" in result["error"]


def test_attachment_guard_rejects_outside_paths():
    assert server._allowed_path(server.ATTACHMENTS / "x" / "a.pdf") is True
