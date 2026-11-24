# lm-bridge (`lmbridge`)

Sidecar for a lightningmail relay (CONCEPT §14, Etappe B1–B3): lets any
classic mail client use an LM account over plain IMAP + SMTP — no plugin,
no per-client integration, no changes to relayd.

## What it does

- **Smart-SMTP router (port 1025).** Clients submit with mandatory AUTH.
  Every recipient is checked against the relay (`GET /v1/profile/{addr}`):
  LM accounts get an end-to-end encrypted LM letter, everyone else a classic
  SMTP copy via the optional `upstream_smtp` relay. Mixed mail is split into
  both deliveries, and the classic copy gets a `Reply-To` stamped
  (`upstream_smtp.from_address`) so replies find the bridge-managed mailbox.
- **LM-IMAP mirror (port 1143).** Serves the LM inbox from a local SQLite
  cache (`state_dir`, stable UIDs across restarts) and round-trips
  seen/flagged state with the relay through `/v1/state`.
- **Auto-unlock.** The bridge authenticates to the relay at startup with the
  account's LM key (challenge-signature, same as the desktop client); a
  wrapped key is unlocked once via `key_pass_file`. No interactive login,
  and no secrets are persisted in the cache.

## Trust boundary

The bridge decrypts E2E mail and serves it as plaintext IMAP/SMTP, so it
**belongs on the LAN or a VPN** — never expose ports 1025/1143 through a
Cloudflare tunnel or any public ingress. Plaintext LOGIN is only offered
while `tls_cert`/`tls_key` are unset, which is acceptable on a trusted
network only.

## Setup (docker compose)

The compose files under `deploy/` ship an opt-in `bridge` profile that runs
next to relayd (light and full relay alike):

1. `cp bridge/bridge.yaml.example deploy/bridge.yaml` and edit it — relay
   URL/account and upstream SMTP; the paths already match the container
   layout. Inside the compose network use `relay_url: http://relayd:8443`,
   so bridge↔relay traffic never leaves the host.
2. Put the secrets referenced by `bridge.yaml` into `deploy/bridge-secrets/`
   (LM key file + pass files). The directory is mounted read-only at
   `/secrets` — never commit it.
3. Start: `docker compose -f deploy/docker-compose.light-relay.yml --profile bridge up -d`
4. Configure your mail client (below).

### Coexistence with lm.domain

The relay's public face (web UI, OIDC login, postage/balance, Drive) stays
at `https://lm.<domain>` behind Cloudflare exactly as before; the bridge
only adds LAN-local ports on the same host. Convention: tunnel → relayd
(HTTP 8443, TLS terminated in front), bridge → LAN/VPN IP only — e.g. a
split-horizon DNS record `mail.<domain>` pointing at the private address,
or simply the host's LAN IP in the client config.

## Mail client settings

| Setting  | Value                                                        |
| -------- | ------------------------------------------------------------ |
| IMAP     | bridge host, port `1143`, no TLS (STARTTLS if `tls_cert` set) |
| SMTP     | bridge host, port `1025`, no TLS (STARTTLS if `tls_cert` set), AUTH on |
| User     | `bridge_auth.user`                                           |
| Password | contents of `bridge_auth.pass_file`                          |
| Identity | your LM address (`account`) — routing is automatic           |

Any client with plain IMAP4rev1 + SMTP submission works (Thunderbird,
Apple Mail, …). New Outlook does not: it forces cloud sync and refuses
local IMAP servers (same limitation as Proton Mail Bridge).

## Configuration

See [`bridge.yaml.example`](bridge.yaml.example) — every field is documented
there. Validation is fail-closed: unknown YAML keys, missing secret files or
malformed listen addresses stop startup instead of degrading delivery later.

## Deliberate trade-offs

- **The relay web UI stays the home of bmail specifics**: OIDC login
  ("Sign in with lightningmail"), balance/postage, hold-accept, Drive. The
  bridge does not re-implement them and mail clients cannot render them —
  plain send/receive needs no sidebar/plugin, bmail features live at `lm.<domain>`.
- **IMAP only, no JMAP/CalDAV**: the smallest protocol every major client
  already speaks.
- **Zero relayd changes**: the bridge is a pure API consumer (`/v1/auth`,
  `/v1/profile`, `/v1/blob`, `/v1/send`, `/v1/inbox`, `/v1/state`), so relay
  and bridge evolve independently.

## Development

```bash
cd bridge
CGO_ENABLED=0 go test ./...   # pure-Go sqlite (modernc), no C toolchain needed
CGO_ENABLED=0 go run ./cmd/lmbridge -config bridge.yaml
```
