# oauth-mail-mcp

OAuth-only mail access for one mailbox per container, exposed as a remote MCP server.

Gmail and Microsoft 365 both killed password auth for mail clients, so an agent that wants
real mailbox access needs a browser-approved OAuth grant that survives restarts. Doing that
usually means registering your own Google Cloud or Entra application — which for a work
tenant means an admin request, and for Gmail in "Testing" status means a refresh token that
dies every seven days.

This project takes a different route: it reuses the **public OAuth clients Mozilla ships in
Thunderbird**, so the consent screen reads "Thunderbird", no application registration exists
on either side, and the refresh token is long-lived. himalaya does the IMAP/SMTP work, ortie
owns the OAuth grant and refreshes it on read, and this server exposes the result over
MCP — one container, one account, one bearer token.

## Why not an existing project

| Project | Gap |
|---|---|
| `tecnologicachile/mail-mcp` | Closest by capability (OAuth2, IMAP/SMTP/Graph/EWS). No published image, unauthenticated HTTP transport, no health endpoint, refresh tokens must be provisioned by hand |
| `rumbitopi/mail-cal-drive-mcp` | Requires your own Azure app registration and Google Cloud OAuth client — the admin approval this project avoids |
| `psyb0t/docker-mailbox` | Published image, but password/app-password auth only; Exchange Online rejects basic auth |
| `ai-zerolab/mcp-email-server` | IMAP passwords only, so Microsoft 365 cannot connect |
| Google Workspace / Microsoft 365 official MCP servers | Developer preview or tenant-admin provisioning, own Cloud project, 7-day tokens in Testing |

None of them combine an unauthenticated-free HTTP MCP surface, a health signal, in-container
OAuth and no app registration. That combination is what this repo is.

## Quick start

```bash
cp .env.example .env      # fill MAIL_ADDRESS, MAIL_MCP_TOKEN, GOOGLE_CLIENT_SECRET
docker compose up -d
curl http://localhost:18080/health
```

First run reports `unauthenticated` — no token exists yet. Authorise through an MCP client
by calling `mail_authorize_start`, or run ortie inside the container:

```bash
docker exec -it oauth-mail-mcp-gmail sh -lc 'ORTIE_CONFIG=/data/config/ortie.toml ortie auth get -a gmail'
```

## Environment

| Variable | Required | Meaning |
|---|---|---|
| `MAIL_ACCOUNT` | yes | `gmail` or `m365` — selects endpoints, grant and folder aliases |
| `MAIL_ADDRESS` | yes | mailbox address, used as the SASL username and `From` |
| `MAIL_MCP_TOKEN` | yes | bearer token the MCP client must present (`openssl rand -hex 32`) |
| `MAIL_ALLOW_SEND` | no | `true` enables `mail_send`; default `false` |
| `GOOGLE_CLIENT_SECRET` | gmail | Mozilla's public Thunderbird client secret |
| `MAIL_HEALTH_CACHE_SECS` | no | health probe cache, default 60 |
| `MAIL_MAX_BODY_CHARS` | no | body truncation for `mail_read`, default 20000 |

## Tools

`mail_status`, `mail_mailboxes`, `mail_list`, `mail_search`, `mail_read`, `mail_attachment`,
`mail_flags`, `mail_draft`, `mail_send`, `mail_authorize_start`, `mail_authorize_resume`.

No delete, no move, no folder creation. `mail_send` refuses unless `MAIL_ALLOW_SEND=true`.
Drafts are the intended write path: an injected mail body can at worst create a draft.

## OAuth flows

**Gmail — authorisation code with a loopback redirect.** `mail_authorize_start` returns a
Google URL. Approve it on the machine where `http://localhost:18081` reaches this container
(the Mac); the callback listens on `8082`, published only on loopback, and writes the token.
From a phone or another computer, the redirect dies on that device — paste the address-bar
URL into `mail_authorize_resume` and the exchange completes server-side. Google offers no
device-code flow for the Thunderbird client (`invalid_client: Invalid client type`), which
is why the paste path exists.

**Microsoft 365 — device code.** `mail_authorize_start` returns a code and
`https://login.microsoft.com/device`. Type it on any device; the container polls and stores
the token. No callback, no LAN dependency, no paste.

## Health

`GET /health` (port 8081, published to the LAN for Uptime Kuma):

| Status | HTTP | Meaning |
|---|---|---|
| `ok` | 200 | token resolved and IMAP answered |
| `unauthenticated` | 503 | no token granted yet |
| `reauth-required` | 503 | grant revoked, expired or rejected |
| `upstream-error` | 503 | token fine, provider unreachable |
| `starting` | 503 | first probe not finished |

Probes are cached 60 s. The container has a `HEALTHCHECK` on the same endpoint but **no
auto-restart**: restarting cannot fix a dead grant, and a crash loop would hide the red state
that monitoring is supposed to show.

Kuma: HTTP keyword monitor on `http://<host>:18080/health`, keyword `"status":"ok"`.

## Security

- Refresh tokens live only in the container's `/data` volume, mode 0600. No tool returns them.
- `/mcp` requires the bearer token and is not published to the LAN — only `/health` is.
- Config files are rendered at start from environment variables and contain no secrets.
- All himalaya/ortie invocations are serialised with a file lock, because Microsoft rotates
  refresh tokens on use and two concurrent refreshes would invalidate each other.

## Build

GitHub Actions builds multi-arch images to `ghcr.io/jmengit/oauth-mail-mcp`, tagged
`latest`, `sha-<short>`, and `YYYY.MM.DD-<short>`. Pin the dated tag in production so
rollback is a tag change. `upstream.yml` checks daily for new himalaya/ortie releases and
opens a PR bumping `versions.env`.

## Licence

MIT
