#!/usr/bin/env python3
"""oauth-mail-mcp — OAuth-only mail MCP server for Gmail and Microsoft 365.

One container per mailbox. himalaya does IMAP/SMTP, ortie owns OAuth and refreshes the
access token, and this process exposes the pair over MCP (streamable HTTP, bearer auth)
plus a link-aware /health endpoint for Uptime Kuma.

No token or mailbox password is ever returned by a tool. Sending is disabled unless
MAIL_ALLOW_SEND=true is set in the container environment.

See the project design: 2026-10-24-oauth-mail-mcp-design.md
"""

from __future__ import annotations

import contextlib
import fcntl
import hmac
import html
import json
import os
import re
import subprocess
import sys
import threading
import time
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import uvicorn
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings

VERSION = "0.1.0"

# --------------------------------------------------------------------------------------
# Environment
# --------------------------------------------------------------------------------------

ACCOUNT = os.environ.get("MAIL_ACCOUNT", "").strip()
ADDRESS = os.environ.get("MAIL_ADDRESS", "").strip()
DISPLAY_NAME = os.environ.get("MAIL_DISPLAY_NAME", "").strip()
MCP_TOKEN = os.environ.get("MAIL_MCP_TOKEN", "").strip()
ALLOW_SEND = os.environ.get("MAIL_ALLOW_SEND", "false").lower() == "true"
# Read-only by default: a container that is never told otherwise must not be able to change
# mailbox state. Writes (flags, drafts, sending) require MAIL_READ_ONLY=false as well.
READ_ONLY = os.environ.get("MAIL_READ_ONLY", "true").lower() == "true"
HEALTH_CACHE_SECS = int(os.environ.get("MAIL_HEALTH_CACHE_SECS", "60"))
MAX_BODY_CHARS = int(os.environ.get("MAIL_MAX_BODY_CHARS", "20000"))
MCP_PORT = int(os.environ.get("MAIL_MCP_PORT", "8080"))
HEALTH_PORT = int(os.environ.get("MAIL_HEALTH_PORT", "8081"))
CALLBACK_PORT = int(os.environ.get("MAIL_CALLBACK_PORT", "8082"))
PUBLIC_CALLBACK_PORT = int(os.environ.get("MAIL_PUBLIC_CALLBACK_PORT", "18081"))

DATA = Path(os.environ.get("MAIL_DATA_DIR", "/data"))
TOKENS = DATA / "tokens"
CONFIG = DATA / "config"
ATTACHMENTS = DATA / "attachments"
PENDING = DATA / "pending-auth.json"
LOCK_FILE = DATA / "mail.lock"

HIMALAYA = os.environ.get("HIMALAYA_BIN", "/usr/local/bin/himalaya")
ORTIE = os.environ.get("ORTIE_BIN", "/usr/local/bin/ortie")

# Public OAuth clients shipped by Mozilla in Thunderbird. Using them is the whole point:
# no Google Cloud project, no Azure app registration, no admin consent.
THUNDERBIRD_GOOGLE_CLIENT_ID = "406964657835-aq8lmia8j95dhl1a2bvharmfk3t1hgqj.apps.googleusercontent.com"
THUNDERBIRD_M365_CLIENT_ID = "9e5f94bc-e8a4-4e73-b8be-63364c29d753"

PROVIDERS = {
    "gmail": {
        "imap": "imaps://imap.gmail.com:993",
        "smtp": "smtps://smtp.gmail.com:465",
        "smtp_starttls": False,
        "grant": "authorization-code",
        "client_id": os.environ.get("GOOGLE_CLIENT_ID", THUNDERBIRD_GOOGLE_CLIENT_ID),
        "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "scopes": ["https://mail.google.com/"],
        "extras": {"access_type": "offline", "prompt": "consent"},
        "aliases": {
            "inbox": "INBOX",
            "sent": "[Gmail]/Sent Mail",
            "drafts": "[Gmail]/Drafts",
            "trash": "[Gmail]/Trash",
        },
    },
    "m365": {
        "imap": "imaps://outlook.office365.com:993",
        "smtp": "smtp://smtp.office365.com:587",
        "smtp_starttls": True,
        "grant": "device",
        "client_id": os.environ.get("M365_CLIENT_ID", THUNDERBIRD_M365_CLIENT_ID),
        "client_secret": "",
        "authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "device_authorization_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode",
        "token_endpoint": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "scopes": [
            "https://outlook.office.com/IMAP.AccessAsUser.All",
            "https://outlook.office.com/SMTP.Send",
            "offline_access",
        ],
        "extras": {},
        "aliases": {
            "inbox": "INBOX",
            "sent": "Sent Items",
            "drafts": "Drafts",
            "trash": "Deleted Items",
        },
    },
}

AUTH_ERROR_RE = re.compile(
    r"invalid_grant|invalid_client|unauthorized|authentication failed|authenticate failed|"
    r"authenticationfailed|login failed|401|token has expired|revoked|interaction_required",
    re.IGNORECASE,
)

_health_cache: dict[str, object] = {"ts": 0.0, "payload": None}
_health_lock = threading.Lock()
_pending_lock = threading.Lock()
_poller: dict[str, object] = {"thread": None, "expires": 0.0}


def _read_only_refusal(tool: str) -> dict:
    return {
        "ok": False,
        "error": f"{tool} is disabled: this container is read-only",
        "hint": "set MAIL_READ_ONLY=false (and MAIL_ALLOW_SEND=true to send) on the service",
    }


def log(message: str) -> None:
    print(f"oauth-mail-mcp: {message}", flush=True)


# --------------------------------------------------------------------------------------
# Config rendering
# --------------------------------------------------------------------------------------


def _toml_str(value: str) -> str:
    return json.dumps(value)


def render_configs() -> None:
    """Write ortie + himalaya configs from env. Configs contain no secrets."""
    provider = PROVIDERS[ACCOUNT]
    CONFIG.mkdir(parents=True, exist_ok=True)
    TOKENS.mkdir(parents=True, exist_ok=True)
    ATTACHMENTS.mkdir(parents=True, exist_ok=True)
    for path in (DATA, TOKENS, CONFIG, ATTACHMENTS):
        with contextlib.suppress(OSError):
            path.chmod(0o700)

    token_file = TOKENS / f"{ACCOUNT}.json"
    ortie_lines = [
        "# Generated at container start by oauth-mail-mcp. Contains no secrets.",
        f"[accounts.{ACCOUNT}]",
        "default = true",
        f"grant = {_toml_str(provider['grant'])}",
        f"client-id = {_toml_str(provider['client_id'])}",
    ]
    if provider["client_secret"]:
        ortie_lines.append(f"client-secret.raw = {_toml_str(provider['client_secret'])}")
    ortie_lines += [
        f"endpoints.authorization = {_toml_str(provider['authorization_endpoint'])}",
    ]
    if provider.get("device_authorization_endpoint"):
        ortie_lines.append(
            f"endpoints.device-authorization = {_toml_str(provider['device_authorization_endpoint'])}"
        )
    ortie_lines.append(f"endpoints.token = {_toml_str(provider['token_endpoint'])}")
    if provider["grant"] == "authorization-code":
        redirect = f"http://localhost:{PUBLIC_CALLBACK_PORT}"
        ortie_lines.append(f"endpoints.redirection = {_toml_str(redirect)}")
        for key, value in provider["extras"].items():
            ortie_lines.append(f"extras.{key} = {_toml_str(value)}")
    ortie_lines.append("scopes = [" + ", ".join(_toml_str(s) for s in provider["scopes"]) + "]")
    if ADDRESS and ACCOUNT == "m365":
        ortie_lines.append(f"extras.login_hint = {_toml_str(ADDRESS)}")
    ortie_lines += [
        "auto-refresh = true",
        f"storage.read.command = [\"cat\", {_toml_str(str(token_file))}]",
        f"storage.write.command = \"umask 077 && cat > {token_file}\"",
    ]
    (CONFIG / "ortie.toml").write_text("\n".join(ortie_lines) + "\n", encoding="utf-8")

    hima = [
        "# Generated at container start by oauth-mail-mcp. Contains no secrets.",
        f"[accounts.{ACCOUNT}]",
        "default = true",
        f"email = {_toml_str(ADDRESS)}",
    ]
    if DISPLAY_NAME:
        hima.append(f"display-name = {_toml_str(DISPLAY_NAME)}")
    hima += [
        f"imap.server = {_toml_str(provider['imap'])}",
        f"imap.sasl.xoauth2.username = {_toml_str(ADDRESS)}",
        "imap.sasl.xoauth2.token.command = ["
        + ", ".join(_toml_str(x) for x in (ORTIE, "token", "show", "-a", ACCOUNT))
        + "]",
        f"smtp.server = {_toml_str(provider['smtp'])}",
    ]
    if provider["smtp_starttls"]:
        hima.append("smtp.starttls = true")
    hima += [
        f"smtp.sasl.xoauth2.username = {_toml_str(ADDRESS)}",
        "smtp.sasl.xoauth2.token.command = ["
        + ", ".join(_toml_str(x) for x in (ORTIE, "token", "show", "-a", ACCOUNT))
        + "]",
    ]
    for role, mailbox in provider["aliases"].items():
        hima.append(f"mailbox.alias.{role} = {_toml_str(mailbox)}")
    (CONFIG / "himalaya.toml").write_text("\n".join(hima) + "\n", encoding="utf-8")

    for path in (CONFIG / "ortie.toml", CONFIG / "himalaya.toml"):
        with contextlib.suppress(OSError):
            path.chmod(0o600)


def child_env() -> dict[str, str]:
    env = dict(os.environ)
    env["HIMALAYA_CONFIG"] = str(CONFIG / "himalaya.toml")
    env["ORTIE_CONFIG"] = str(CONFIG / "ortie.toml")
    env.setdefault("HOME", str(DATA))
    env["TMPDIR"] = str(DATA / "tmp")
    (DATA / "tmp").mkdir(parents=True, exist_ok=True)
    return env


# --------------------------------------------------------------------------------------
# Subprocess helpers — serialised, because Microsoft rotates refresh tokens on use and two
# concurrent refreshes would invalidate each other.
# --------------------------------------------------------------------------------------


def _run(args: list[str], timeout: int = 60, stdin: str | None = None, binary: bool = False):
    DATA.mkdir(parents=True, exist_ok=True)
    with open(LOCK_FILE, "a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            import subprocess

            proc = subprocess.run(
                args,
                input=stdin.encode() if (stdin is not None and binary) else stdin,
                capture_output=True,
                text=not binary,
                timeout=timeout,
                env=child_env(),
            )
            out = proc.stdout if binary else (proc.stdout or "")
            err = proc.stderr.decode(errors="replace") if binary else (proc.stderr or "")
            return proc.returncode, out, err
        except subprocess.TimeoutExpired:
            return 124, b"" if binary else "", f"timeout after {timeout}s: {' '.join(args[:3])}"
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _json_or_error(args: list[str], timeout: int = 60):
    rc, out, err = _run(args, timeout=timeout)
    if rc != 0:
        # himalaya reports failures on stdout, not stderr, so fall back to it.
        return None, _error_text(rc, err or out)
    try:
        return json.loads(out), None
    except json.JSONDecodeError:
        return None, f"unparseable output from {' '.join(args[:2])}"


def _error_text(rc: int, err: str) -> str:
    err = (err or "").strip()
    err = re.sub(r"\s+", " ", err)
    return err[:400] if err else f"command failed with exit code {rc}"


# --------------------------------------------------------------------------------------
# Formatting helpers
# --------------------------------------------------------------------------------------


def _fmt_addresses(value) -> str:
    if not value:
        return ""
    if isinstance(value, str):
        return value
    parts = []
    for item in value:
        if isinstance(item, dict):
            name = (item.get("name") or "").strip()
            addr = (item.get("email") or item.get("addr") or "").strip()
            parts.append(f"{name} <{addr}>" if name else addr)
        else:
            parts.append(str(item))
    return ", ".join(p for p in parts if p)


def _envelopes(data) -> list:
    """himalaya wraps envelope pages in an object (`{"envelopes": [...]}`), while mailbox
    listings are bare arrays; accept both shapes so a backend change cannot silently
    return an empty inbox."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("envelopes", "items", "data"):
            value = data.get(key)
            if isinstance(value, list):
                return value
    return []


def _flag_name(flag) -> str:
    """himalaya serialises a flag as `{"raw": "\\Seen", "iana": "seen"}`; older shapes are
    bare strings. Normalise to the IANA name so callers can compare plainly."""
    if isinstance(flag, dict):
        name = flag.get("iana") or flag.get("raw") or ""
    else:
        name = str(flag)
    return str(name).strip().lstrip("\\").lower()


def _norm_envelope(raw: dict) -> dict:
    flags = raw.get("flags") or []
    if isinstance(flags, (str, dict)):
        flags = [flags]
    names = [n for n in (_flag_name(f) for f in flags) if n]
    return {
        "id": str(raw.get("id", "")),
        "subject": raw.get("subject") or "",
        "from": _fmt_addresses(raw.get("from")),
        "to": _fmt_addresses(raw.get("to")),
        "date": raw.get("date"),
        "flags": names,
        "unread": "seen" not in names,
        "size": raw.get("size"),
        "has_attachment": raw.get("has-attachment", raw.get("has_attachment")),
    }


def _safe_filename(name: str, fallback: str = "attachment") -> str:
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    name = re.sub(r"[^A-Za-z0-9._ ()-]", "_", name)
    name = name.lstrip(".") or fallback
    return name[:120]


def _allowed_path(path: Path) -> bool:
    try:
        return ATTACHMENTS.resolve() in path.resolve().parents or path.resolve().parent == ATTACHMENTS.resolve()
    except OSError:
        return False


def _html_to_text(markup: str) -> str:
    markup = re.sub(r"(?is)<(script|style).*?</\1>", " ", markup)
    markup = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", markup)
    text = re.sub(r"<[^>]+>", " ", markup)
    text = html.unescape(text)
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
    return text.strip()


def parse_raw_message(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    plain: list[str] = []
    html_parts: list[str] = []
    attachments: list[dict] = []
    index = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        index += 1
        ctype = part.get_content_type()
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                {
                    "part": str(index),
                    "filename": _safe_filename(filename or f"part-{index}"),
                    "content_type": ctype,
                    "size": len(payload),
                }
            )
            continue
        try:
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            text = (payload or b"").decode(charset, errors="replace")
        except Exception:
            continue
        if ctype == "text/plain":
            plain.append(text)
        elif ctype == "text/html":
            html_parts.append(text)
    body = "\n\n".join(t for t in plain if t.strip())
    if not body.strip() and html_parts:
        body = _html_to_text("\n".join(html_parts))
    return {
        "subject": msg.get("Subject", "") or "",
        "from": msg.get("From", "") or "",
        "to": msg.get("To", "") or "",
        "cc": msg.get("Cc", "") or "",
        "date": msg.get("Date", "") or "",
        "message_id": (msg.get("Message-Id", "") or "").strip("<>"),
        "in_reply_to": (msg.get("In-Reply-To", "") or "").strip("<>"),
        "body": body,
        "attachments": attachments,
    }


def _attach_payloads(raw: bytes) -> list[tuple[dict, bytes]]:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    out: list[tuple[dict, bytes]] = []
    index = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        index += 1
        filename = part.get_filename()
        disposition = (part.get_content_disposition() or "").lower()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            out.append(
                (
                    {
                        "part": str(index),
                        "filename": _safe_filename(filename or f"part-{index}"),
                        "content_type": part.get_content_type(),
                        "size": len(payload),
                    },
                    payload,
                )
            )
    return out


# --------------------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------------------


def _state(status: str, detail: str = "") -> dict:
    payload = {
        "status": status,
        "account": ACCOUNT,
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    if detail:
        payload["detail"] = detail
    return payload


def _token_expiry() -> dict:
    rc, out, err = _run([ORTIE, "token", "inspect", "-a", ACCOUNT, "--json"], timeout=30)
    if rc != 0:
        return {}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    keep = {}
    for key, value in data.items():
        low = key.lower()
        if isinstance(value, (str, int, float, bool)) and any(k in low for k in ("expire", "scope", "type")):
            if "token" in low and "type" not in low:
                continue
            keep[key] = value
    return keep


def probe_health() -> dict:
    token_file = TOKENS / f"{ACCOUNT}.json"
    if not token_file.exists():
        return _state("unauthenticated", "no token granted yet")

    rc, _out, err = _run([ORTIE, "token", "show", "-a", ACCOUNT], timeout=45)
    if rc != 0:
        if AUTH_ERROR_RE.search(err or ""):
            return _state("reauth-required", _error_text(rc, err))
        return _state("upstream-error", _error_text(rc, err))

    rc, out, err = _run(
        [HIMALAYA, "envelope", "list", "-a", ACCOUNT, "-s", "1", "--json"], timeout=45
    )
    if rc != 0:
        if AUTH_ERROR_RE.search(err or ""):
            return _state("reauth-required", _error_text(rc, err))
        return _state("upstream-error", _error_text(rc, err))

    payload = _state("ok")
    payload["token"] = _token_expiry()
    return payload


def get_health(force: bool = False) -> dict:
    now = time.time()
    with _health_lock:
        cached = _health_cache.get("payload")
        if (
            not force
            and isinstance(cached, dict)
            and now - float(_health_cache.get("ts") or 0) < HEALTH_CACHE_SECS
        ):
            return cached
        try:
            payload = probe_health()
        except Exception as exc:  # never let health take the process down
            payload = _state("upstream-error", f"probe failed: {exc}"[:300])
        _health_cache["ts"] = now
        _health_cache["payload"] = payload
        return payload


def invalidate_health() -> None:
    with _health_lock:
        _health_cache["ts"] = 0.0
        _health_cache["payload"] = None


class HealthHandler(BaseHTTPRequestHandler):
    server_version = "oauth-mail-mcp-health"

    def do_GET(self):  # noqa: N802
        path = self.path.split("?")[0]
        if path not in ("/health", "/healthz", "/"):
            self.send_response(404)
            self.end_headers()
            return
        payload = get_health()
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200 if payload.get("status") == "ok" else 503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # keep the container log quiet from Kuma polling
        return


# --------------------------------------------------------------------------------------
# OAuth: pending state + callback listener (Gmail) + device poller (M365)
# --------------------------------------------------------------------------------------


def save_pending(data: dict | None) -> None:
    with _pending_lock:
        if data is None:
            with contextlib.suppress(FileNotFoundError):
                PENDING.unlink()
            return
        PENDING.write_text(json.dumps(data), encoding="utf-8")
        with contextlib.suppress(OSError):
            PENDING.chmod(0o600)


def load_pending() -> dict:
    with _pending_lock:
        with contextlib.suppress(FileNotFoundError, json.JSONDecodeError):
            return json.loads(PENDING.read_text(encoding="utf-8"))
        return {}


def complete_grant(redirect_url: str) -> tuple[bool, str]:
    pending = load_pending()
    args = [ORTIE, "auth", "resume", redirect_url, "-a", ACCOUNT]
    if pending.get("state"):
        args += ["-s", pending["state"]]
    if pending.get("verifier"):
        args += ["-p", pending["verifier"]]
    if pending.get("redirect"):
        args += ["-r", pending["redirect"]]
    rc, out, err = _run(args, timeout=90)
    if rc != 0:
        return False, _error_text(rc, err)
    save_pending(None)
    invalidate_health()
    return True, "authorised"


class CallbackHandler(BaseHTTPRequestHandler):
    server_version = "oauth-mail-mcp-callback"

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        if "code" not in params:
            self._send(400, "No authorisation code in this URL.")
            return
        ok, detail = complete_grant(f"http://localhost:{PUBLIC_CALLBACK_PORT}/{('?' + parsed.query) if parsed.query else ''}")
        self._send(200 if ok else 500, "Authorisation complete — you can close this tab." if ok else f"Authorisation failed: {detail}")

    def _send(self, code: int, text: str):
        body = (text + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def device_poll(device_code: str, interval: int, expires_at: float) -> None:
    """Wait for the tenant to approve a device code.

    `ortie auth resume <device_code>` blocks and polls internally until the code is approved
    or expires, so this issues one long call rather than a tight retry loop. A timeout here
    means the code lapsed unused, which is not an error worth logging loudly.
    """
    remaining = max(60.0, expires_at - time.time())
    rc, _out, err = _run(
        [ORTIE, "auth", "resume", device_code, "-a", ACCOUNT], timeout=int(remaining) + 30
    )
    if rc == 0:
        invalidate_health()
        return
    # 124 is our own timeout expiring: the tenant never approved.
    if rc == 124:
        return
    log(f"device grant did not complete: {_error_text(rc, err)}")


def start_callback_listener() -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", CALLBACK_PORT), CallbackHandler)
    thread = threading.Thread(target=server.serve_forever, name="callback", daemon=True)
    thread.start()
    return server


# --------------------------------------------------------------------------------------
# MCP tools
# --------------------------------------------------------------------------------------

mcp = MCPServer(
    name="oauth-mail-mcp",
    version=VERSION,
    description="OAuth-only mail access for one mailbox, backed by himalaya and ortie.",
)


@mcp.tool()
def mail_status() -> dict:
    """Account, health state, token expiry and whether sending is enabled."""
    health = get_health(force=True)
    return {
        "ok": health.get("status") == "ok",
        "account": ACCOUNT,
        "address": ADDRESS,
        "health": health.get("status"),
        "detail": health.get("detail", ""),
        "token": health.get("token", {}),
        "send_enabled": ALLOW_SEND,
        "provider": ACCOUNT,
    }


@mcp.tool()
def mail_mailboxes() -> dict:
    """List mailboxes (folders) with message and unread counts."""
    data, err = _json_or_error([HIMALAYA, "mailbox", "list", "-a", ACCOUNT, "--json"])
    if err:
        return {"ok": False, "error": err}
    boxes = []
    for item in data if isinstance(data, list) else data.get("mailboxes", []):
        entry = {
            "id": item.get("id") or item.get("name"),
            "name": item.get("name"),
            "role": item.get("role"),
        }
        for key in ("total", "unread", "unread-count", "unread_count"):
            if item.get(key) is not None:
                entry["unread" if "unread" in key else "total"] = item[key]
        boxes.append(entry)
    return {"ok": True, "mailboxes": boxes}


@mcp.tool()
def mail_list(mailbox: str = "INBOX", page: int = 1, page_size: int = 25, unread_only: bool = False) -> dict:
    """List envelopes newest first. mailbox accepts a role (inbox/sent/drafts/trash) or a name."""
    data, err = _json_or_error(
        [
            HIMALAYA,
            "envelope",
            "list",
            "-a",
            ACCOUNT,
            "-m",
            mailbox,
            "-p",
            str(max(1, page)),
            "-s",
            str(max(1, min(page_size, 100))),
            "--json",
        ]
    )
    if err:
        return {"ok": False, "error": err}
    envelopes = [_norm_envelope(e) for e in _envelopes(data)]
    if unread_only:
        envelopes = [e for e in envelopes if e["unread"]]
    return {"ok": True, "mailbox": mailbox, "page": page, "envelopes": envelopes}


@mcp.tool()
def mail_search(query: str, mailbox: str = "INBOX", page_size: int = 25) -> dict:
    """Search envelopes with himalaya's query language, e.g.
    'from accounts and after 2026-10-01', 'subject invoice', 'body statement'."""
    if not query or not query.strip():
        return {"ok": False, "error": "query is required"}
    # The query is a trailing var-arg and would swallow any option placed after it,
    # so every flag comes first and the query goes last.
    data, err = _json_or_error(
        [
            HIMALAYA,
            "envelope",
            "search",
            "-a",
            ACCOUNT,
            "-m",
            mailbox,
            "-s",
            str(max(1, min(page_size, 100))),
            "--json",
            query,
        ]
    )
    if err:
        return {"ok": False, "error": err}
    return {
        "ok": True,
        "mailbox": mailbox,
        "query": query,
        "envelopes": [_norm_envelope(e) for e in _envelopes(data)],
    }


@mcp.tool()
def mail_read(id: str, mailbox: str = "INBOX", max_chars: int = 0) -> dict:
    """Read one message: headers, plain-text body (HTML converted when needed) and attachment list."""
    rc, raw, err = _run(
        [HIMALAYA, "message", "read", str(id), "-a", ACCOUNT, "-m", mailbox, "--raw"],
        timeout=120,
        binary=True,
    )
    if rc != 0:
        return {"ok": False, "error": _error_text(rc, err)}
    try:
        parsed = parse_raw_message(raw)
    except Exception as exc:
        return {"ok": False, "error": f"could not parse message: {exc}"}
    limit = max_chars if max_chars and max_chars > 0 else MAX_BODY_CHARS
    body = parsed.pop("body")
    truncated = len(body) > limit
    parsed["body"] = body[:limit]
    parsed["truncated"] = truncated
    parsed["total_chars"] = len(body)
    return {"ok": True, "mailbox": mailbox, "id": str(id), **parsed}


@mcp.tool()
def mail_attachment(id: str, name: str = "", mailbox: str = "INBOX") -> dict:
    """Save one message's attachments inside the container and return their paths."""
    rc, raw, err = _run(
        [HIMALAYA, "message", "read", str(id), "-a", ACCOUNT, "-m", mailbox, "--raw"],
        timeout=120,
        binary=True,
    )
    if rc != 0:
        return {"ok": False, "error": _error_text(rc, err)}
    dest = ATTACHMENTS / _safe_filename(str(id), "message")
    dest.mkdir(parents=True, exist_ok=True)
    saved = []
    for meta, payload in _attach_payloads(raw):
        if name and name.lower() not in meta["filename"].lower():
            continue
        target = dest / meta["filename"]
        if not _allowed_path(target):
            continue
        target.write_bytes(payload)
        saved.append({"filename": meta["filename"], "path": str(target), "size": meta["size"]})
    if not saved:
        return {"ok": False, "error": "no matching attachment found"}
    return {"ok": True, "attachments": saved}


@mcp.tool()
def mail_flags(ids: list[str], add: list[str] | None = None, remove: list[str] | None = None, mailbox: str = "INBOX") -> dict:
    """Add or remove flags on messages. Allowed flags: seen, flagged, answered, draft."""
    if READ_ONLY:
        return _read_only_refusal("mail_flags")
    if not ids:
        return {"ok": False, "error": "ids is required"}
    add = [f for f in (add or []) if f]
    remove = [f for f in (remove or []) if f]
    if not add and not remove:
        return {"ok": False, "error": "nothing to do: pass add and/or remove"}
    actions = []
    for verb, flags in (("add", add), ("remove", remove)):
        if not flags:
            continue
        args = [HIMALAYA, "flag", verb, *[str(i) for i in ids], "-a", ACCOUNT, "-m", mailbox]
        for flag in flags:
            args += ["--flag", flag]
        rc, _out, err = _run(args, timeout=60)
        if rc != 0:
            return {"ok": False, "error": _error_text(rc, err), "completed": actions}
        actions.append({"action": verb, "flags": flags})
    return {"ok": True, "ids": ids, "actions": actions}


@mcp.tool()
def mail_draft(to: str, subject: str, body: str, cc: str = "") -> dict:
    """Save a draft (never sends). Use for anything the user should review first."""
    if READ_ONLY:
        return _read_only_refusal("mail_draft")
    args = [
        HIMALAYA,
        "message",
        "compose",
        "-a",
        ACCOUNT,
        "--to",
        to,
        "--subject",
        subject,
        "--body",
        body,
        "--save",
        "drafts",
    ]
    if cc:
        args += ["--cc", cc]
    rc, _out, err = _run(args, timeout=90)
    if rc != 0:
        return {"ok": False, "error": _error_text(rc, err)}
    return {"ok": True, "saved_to": "drafts", "to": to, "subject": subject}


@mcp.tool()
def mail_send(to: str, subject: str, body: str, cc: str = "", attachments: list[str] | None = None) -> dict:
    """Send a message. Refused unless MAIL_ALLOW_SEND=true is set on the container."""
    if READ_ONLY:
        return _read_only_refusal("mail_send")
    if not ALLOW_SEND:
        return {
            "ok": False,
            "error": "sending is disabled on this container",
            "hint": "use mail_draft, or set MAIL_ALLOW_SEND=true and restart the service",
        }
    args = [
        HIMALAYA,
        "message",
        "compose",
        "-a",
        ACCOUNT,
        "--to",
        to,
        "--subject",
        subject,
        "--body",
        body,
        "--send",
    ]
    if cc:
        args += ["--cc", cc]
    for path in attachments or []:
        if not _allowed_path(Path(path)):
            return {"ok": False, "error": f"attachment outside {ATTACHMENTS}: {path}"}
        args += ["--attach", path]
    rc, _out, err = _run(args, timeout=180)
    if rc != 0:
        return {"ok": False, "error": _error_text(rc, err)}
    return {"ok": True, "sent": True, "to": to, "subject": subject}


@mcp.tool()
def mail_authorize_start() -> dict:
    """Start an OAuth grant. Returns a URL to open (Gmail) or a device code plus URL (Microsoft 365)."""
    if ACCOUNT == "m365" and _poller.get("thread") and float(_poller.get("expires") or 0) > time.time():
        return {"ok": True, "flow": "device_code", "note": "a device code is already active; waiting for approval"}

    data, err = _json_or_error([ORTIE, "auth", "get", "-a", ACCOUNT, "--json"], timeout=60)
    if err:
        return {"ok": False, "error": err}

    if ACCOUNT == "m365":
        expires = float(data.get("expires_in") or 900)
        interval = int(data.get("interval") or 5)
        _poller["expires"] = time.time() + expires
        thread = threading.Thread(
            target=device_poll,
            args=(data.get("device_code", ""), interval, time.time() + expires),
            name="device-poll",
            daemon=True,
        )
        thread.start()
        _poller["thread"] = thread
        return {
            "ok": True,
            "flow": "device_code",
            "url": data.get("verification_uri") or "https://login.microsoft.com/device",
            "code": data.get("user_code"),
            "device_code": data.get("device_code"),
            "expires_in": int(expires),
            "instructions": "Open the URL on any device, enter the code, approve. No callback needed.",
        }

    save_pending(
        {
            "state": data.get("state"),
            "verifier": data.get("pkce_code_verifier"),
            "redirect": f"http://localhost:{PUBLIC_CALLBACK_PORT}",
            "created": time.time(),
        }
    )
    return {
        "ok": True,
        "flow": "authorization_code",
        "url": data.get("authorization_uri"),
        "callback": f"http://localhost:{PUBLIC_CALLBACK_PORT}/",
        "instructions": (
            "Open the URL, approve. The redirect must load on the same machine as the browser: "
            "if it fails (phone or another computer), paste the address-bar URL into mail_authorize_resume."
        ),
    }


@mcp.tool()
def mail_authorize_resume(url_or_code: str) -> dict:
    """Complete a grant by hand. Accepts the full redirected URL or just the code value."""
    value = (url_or_code or "").strip()
    if not value:
        return {"ok": False, "error": "pass the redirected URL or the code"}
    if ACCOUNT == "m365" and not value.lower().startswith("http"):
        ok, detail = complete_grant_device(value)
        return {"ok": ok, "detail": detail} if ok else {"ok": False, "error": detail}

    redirect = value
    if not value.lower().startswith("http"):
        redirect = f"http://localhost:{PUBLIC_CALLBACK_PORT}/?code={value}"
    ok, detail = complete_grant(redirect)
    if not ok:
        return {"ok": False, "error": detail}
    health = get_health(force=True)
    return {"ok": True, "detail": detail, "health": health.get("status")}


def complete_grant_device(device_code: str) -> tuple[bool, str]:
    rc, _out, err = _run([ORTIE, "auth", "resume", device_code, "-a", ACCOUNT], timeout=120)
    if rc != 0:
        return False, _error_text(rc, err)
    invalidate_health()
    return True, "authorised"


# --------------------------------------------------------------------------------------
# Bearer auth for /mcp
# --------------------------------------------------------------------------------------


class BearerGuard:
    """Reject /mcp requests that do not carry the container's bearer token."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not str(scope.get("path", "")).startswith("/mcp"):
            return await self.app(scope, receive, send)
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        supplied = headers.get("authorization", "")
        expected = f"Bearer {self.token}"
        if not hmac.compare_digest(supplied, expected):
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        return await self.app(scope, receive, send)


# --------------------------------------------------------------------------------------
# CLI subcommands, for authorising by hand inside the container:
#   docker exec -it <container> python /app/server.py auth-start
#   docker exec -it <container> python /app/server.py auth-resume '<redirect url or code>'
#   docker exec -it <container> python /app/server.py status
# --------------------------------------------------------------------------------------


def cli_auth_start() -> int:
    data, err = _json_or_error([ORTIE, "auth", "get", "-a", ACCOUNT, "--json"], timeout=60)
    if err:
        print(f"error: {err}")
        return 1
    if ACCOUNT == "m365":
        save_pending({"device_code": data.get("device_code"), "created": time.time()})
        print(f"Open: {data.get('verification_uri') or 'https://login.microsoft.com/device'}")
        print(f"Code: {data.get('user_code')}")
        print(f"Expires in: {int(data.get('expires_in') or 900)}s")
        print("")
        print("Then run:  python /app/server.py auth-resume        (waits for approval)")
        return 0
    save_pending(
        {
            "state": data.get("state"),
            "verifier": data.get("pkce_code_verifier"),
            "redirect": f"http://localhost:{PUBLIC_CALLBACK_PORT}",
            "created": time.time(),
        }
    )
    print(data.get("authorization_uri"))
    print("")
    print(f"Open it on a machine where http://localhost:{PUBLIC_CALLBACK_PORT} reaches this container.")
    print("If the redirect fails, copy the address-bar URL and run:")
    print("  python /app/server.py auth-resume '<url>'")
    return 0


def cli_auth_resume(value: str | None) -> int:
    pending = load_pending()
    if not value:
        if ACCOUNT == "m365" and pending.get("device_code"):
            print("Waiting for approval (Ctrl-C to stop)...")
            ok, detail = complete_grant_device(pending["device_code"])
            print("authorised" if ok else f"error: {detail}")
            return 0 if ok else 1
        print("error: pass the redirected URL (or the device code)")
        return 1
    if ACCOUNT == "m365" and not value.lower().startswith("http"):
        ok, detail = complete_grant_device(value)
    else:
        redirect = value
        if not value.lower().startswith("http"):
            redirect = f"http://localhost:{PUBLIC_CALLBACK_PORT}/?code={value}"
        ok, detail = complete_grant(redirect)
    print("authorised" if ok else f"error: {detail}")
    return 0 if ok else 1


def run_cli(argv: list[str]) -> int:
    if ACCOUNT not in PROVIDERS:
        print(f"MAIL_ACCOUNT must be one of {sorted(PROVIDERS)}")
        return 2
    render_configs()
    cmd = argv[0]
    if cmd == "auth-start":
        return cli_auth_start()
    if cmd == "auth-resume":
        return cli_auth_resume(argv[1] if len(argv) > 1 else None)
    if cmd in ("status", "health"):
        print(json.dumps(get_health(force=True), indent=2))
        return 0
    print(__doc__)
    return 2


# --------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> None:
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        raise SystemExit(run_cli(argv))
    if ACCOUNT not in PROVIDERS:
        raise SystemExit(f"MAIL_ACCOUNT must be one of {sorted(PROVIDERS)}, got {ACCOUNT!r}")
    if not ADDRESS:
        raise SystemExit("MAIL_ADDRESS is required")
    if not MCP_TOKEN:
        raise SystemExit("MAIL_MCP_TOKEN is required")

    render_configs()

    health_server = ThreadingHTTPServer(("0.0.0.0", HEALTH_PORT), HealthHandler)
    threading.Thread(target=health_server.serve_forever, name="health", daemon=True).start()

    if ACCOUNT == "gmail":
        start_callback_listener()

    app = mcp.streamable_http_app(
        streamable_http_path="/mcp",
        stateless_http=True,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
        host="0.0.0.0",
    )
    uvicorn.run(BearerGuard(app, MCP_TOKEN), host="0.0.0.0", port=MCP_PORT, log_level="info")


if __name__ == "__main__":
    main()
