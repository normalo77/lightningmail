# Contributing to lightningmail

You don't need permission to fork — this is MIT. A short map before you start.

## What this is

E-mail where every message carries a small Lightning postage paid to the
*recipient's* mailbox balance. Spam becomes a business loss; conversations net
out to zero. No public directory, no conversation window, one `secp256k1` key
per mailbox that does both mail decryption (ECIES + XChaCha20-Poly1305) and
passwordless login (built-in OIDC provider). The protocol spec lives in
[`docs/spec.md`](docs/spec.md), design decisions and their "why" in
[`docs/CONCEPT.md`](docs/CONCEPT.md) (§-numbers are cited throughout the code
comments).

## Repository map

| Path | What | Language |
|------|------|----------|
| `relay/` | The relay server (`relayd`), CLI (`lmcli`), ledger (SQLite), LM1 envelope crypto | Go |
| `client/` | PWA webmail (`client/app` + `client/src`), Thunderbird add-on, Android wrapper | TypeScript |
| `desktop/` | Native Linux client (GTK4 + libadwaita + WebKitGTK, pure-Go bindings) | Go |
| `site/` | Public landing page, forum/paywall demos, `serve.py` | Python |
| `test/`, `Makefile` | regtest docker-compose (bitcoind + 2x LND), e2e/interop/smoke suites | shell |
| `docs/` | spec, concept, design notes, stage specs | mostly German |

## Ground rules for code

- **Comments in English.** Code comments, docstrings and TODOs are English
  throughout — this repo is meant to be read by strangers. UI strings are
  German/multilingual and stay that way; don't "fix" those.
- **Money is sacred.** Anything touching `relay/internal/ledger` changes a
  hash-chained transaction log. Run `go test ./internal/...` — all tests, no
  skips — before you propose anything there.
- **Wire formats are versioned.** The LM1 envelope (`relay/internal/envelope`)
  and the state-doc merge rules (`client/src/state.ts`, byte-compatible Go
  port planned) have exactly one encoding; changes need a spec section.
- **E2E means the server never sees plaintext.** If your feature stores
  user-readable data server-side, stop and open an issue first.

## Building & testing locally

```bash
cd relay && go test ./internal/... ./cmd/...     # server unit tests (no deps)
make e2e                                          # full 2-relay regtest stack (needs docker)
cd client/app && npm install && npm run build     # PWA bundle
cd desktop && go build ./...                      # native client (runtime needs GTK>=4.10,
                                                  # libadwaita>=1.2, WebKitGTK-6.0)
```

Regression gates for refactors (they prove "comments-only" or "no behavior"
edits mechanically): `tools/comment_audit.go` (Go string-literal inventory)
and `tools/esb-bundle.sh` (TS bundle byte-identity).

## Getting a playground relay

The regtest relays in `relay-alpha.yaml` / `relay-beta.yaml` run via
`test/smoke.sh`. Real funds never enter any test config; all fixtures are
public on purpose.

## Style of working

Small commits, each carrying its test. Cite the concept section (`§`) when a
change implements one. If something in the docs contradicts the code, the
code is right and the docs are a bug — fix both in one commit.
