# bmail v0.1 — Pre-Coding-Entscheidungen
Erstellt 11.11.2026 · Quelle: Hermes + DeepSeek-v4-Pro (Subagent), konsolidiert.
Status: ⬚ = wartet auf Bernds Entscheidung, ✓ = empfohlen/kann so laufen.

## A. Muss Bernd entscheiden

1. ✓ **Lizenz: MIT** (Bernd, 13.11.2026 — ersetzt AGPLv3-Entscheid vom 11.11.) —
   jeder soll forken und verwenden können wie er will; Ziel = Inspiration, nicht Kontrolle.
2. ✓ **Infra: nur Leverkusen (PVE)**, 2 Relays lokal (regtest); QNAP Frechen =
   M2+. CGNAT/Tailscale damit vom Tisch. Repo: **lokal + Backup-Bare-Repo auf
   NAS; GitHub bewusst noch nicht** (Nähe zu LNemail; Org lightningmail wäre
   noch frei — Registrierung/Öffnung erst ab M1-Erfolg oder Hosted-Phase).
3. ✓ QNAP: Docker-fähig (notiert für M2).
4. ✓ Testperson: nur Bernd, 2 Postfächer unter eigener Regie.
5. ✓ **Arbeitstitel: lightningmail** — Kollisionscheck: GitHub-Org/npm/PyPI
   frei, lightningmail.com/.net registriert aber brachliegend, 1 totes
   MS-Store-App „Lightning Mail". Domainfrage vor öffentlichem Hosted-Betrieb
   klären (M3+). Repo zunächst lokal/privat.
6. ⬚ **Scope-Liste C** — gilt als angenommen, sofern kein Widerspruch.
7. ✓ BIP-353-Anbindung: JA (§4.2 zahlt-seitig andocken, _bmail/-lightningmail-
   TXT nur fürs Postamt-Layout).

## B. Technische Setzungen (DeepSeek-Empfehlung, Hermes einverstanden,
   Widerspruch vorbehalten)

| Thema | Entscheidung v0.1 | Begründung |
|---|---|---|
| Testnetz | **regtest** (2× LND + 1× bitcoind, manual mine) | deterministisch, kein Faucet; signet erst fürs „echte Gefühl"-Deployment |
| Relay↔Relay | HTTP/2 + mTLS über Tunnel (WG/Tailscale) — NICHT Onion in v0.1 | Onion/Mix ist M2+; mTLS gibt Identität |
| Krypto | btcec + Go-stdlib + chacha20poly1305 (x/crypto) | kein CGO, ARM-Build sauber |
| Porto | **Receipt-Modell**: Invoice mit description_hash=msg_hash, Preimage = Quittung | Hold-Invoice (HTLC-Debug-Hölle) ist M3 |
| Attachments | content-addressierter FS-Blob-Store, Limit 10 MB | 100 Zeilen Go, keine Infra |
| Push | WebSocket (client-initiiert, 30s Keepalive) + Polling-Fallback | NAT-freundlich; FCM/PWA-Push M2 |
| Discovery | statische relays.yaml (Parser wie späterer DNS-TXT!) | DNS ist Drop-in-Upgrade in M2 |
| Ledger | SQLite (WAL, optimistic locking) | wie LNbits/pay2email bewährt |
| Dev-Umgebung | Phase 1: docker-compose lokal (2×LND/2×Relay/bitcoind), Phase 2 Deployment QNAP+PVE | Code→Test-Zyklus Faktor 10 schneller |
| Clients v0.1 | CLI (Go) + minimales Web-UI; Android = Browser/PWA ohne Push; Debian = alles | native App nie vor M4 |
| MCP-Server | M2: stdio/HTTP-Adapter auf Relay-API, gescopte Budget-Tokens | §15 CONCEPT; Hermes = erster Host |
| Version | SemVer v0.1.0 | |

## C. Out of Scope v0.1 (DeepSeek-Liste, konsolidiert)
DNS-Records & BIP353-Lookup · Onion-Routing Relay↔Relay · LSP/Bootstrap-Credit ·
Preisprofile/Whitelist/Konversationsfenster · Hold-Invoice · SMTP/IMAP-Bridge ·
TB/Outlook-Extension · Multi-Relay-Routing (>2) · LNURL-Auszahlung · Attachments
>10 MB · Fiat · CC/Gruppen · Service-Worker-Push · LNC · IDN/Homoglyph ·
Key-Rotation-UI · Report/Block · Newsletter-Modell · Rechtsform/Markencheck.

## D. M0-Liefergegenstände (Spec + Gerüst, Repo-Monorepo)
relay/{cmd/relayd,internal/{ledger,mailbox,postage,relay,config,crypto,lnclient}},
proto/bmail/v1/envelope.proto (Single Source of Truth, Go+TS-Generate),
client/{cli,web}, test/{docker,integration,fixtures}, docs/{spec.md,CONCEPT.md},
Makefile + CI. E2E-Test: „Bernd→Gisela, +10 sats Saldo, Anhang 5 MB roundtrip".
DeepSeek als Coding-Worker: 1 Spec-Item = 1 PR, testify-Assertions, gofmt/vet
Pflicht, alles über Makefile.

## E. Fund BIP 353 (Subagent-Recherche)
BIP 353 „User Addresses for Bitcoin Payments" (2024/25, Teinturier/Corallo):
DNS-TXT `<user>.user._bitcoin-payment.<domain>`, DNSSEC, BOLT12-Offer;
Phoenix/LDK/Bitcoin Core implementiert; löst LUD-16 für Zahlungsidentität ab.
→ bmail-Adressen können Zahlebenen-seitig 1:1 mitregistriert werden
(Ein-Record-Doppelverwendung), _bmail._tcp bleibt fürs Postamt-Layout.
