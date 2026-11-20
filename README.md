# ⚡ lightningmail

**E-Mail mit eigenem Lightning-Porto & passwortlosem Login (OpenID Connect) / E-mail with Lightning postage & passwordless OIDC login.**

- 🌐 **Live-Webseite & Prototyp:** [https://lightningmail.app](https://lightningmail.app)
- 🏛️ **Architekturentscheidungen & Client-Portierung:** [https://lightningmail.app/architecture](https://lightningmail.app/architecture)
- 📬 **Web-App (PWA):** [https://lightningmail.app/app/](https://lightningmail.app/app/)
- 📜 **Protokoll-Spezifikation (`LM1`):** [`docs/spec.md`](docs/spec.md) · **Gesamtkonzept:** [`docs/CONCEPT.md`](docs/CONCEPT.md)
- ⚖️ **Lizenz:** [MIT](LICENSE)

---

## Deutsch — Überblick (v1.0)

Die Idee hinter **lightningmail**: Jede Nachricht kostet den Absender ein kleines Porto (einige Satoshis per Lightning-Keysend), das direkt dem Postfach-Guthaben des Empfängers gutgeschrieben wird.
- **Spam wird zum Verlustgeschäft:** Einseitige Massenpost kostet ab dem ersten Brief echtes Geld.
- **Gespräche kosten netto null:** Antworten schicken das Porto einfach mit der Antwort zurück.
- **Kein öffentliches Adressbuch, kein Konversationsfenster:** Die Empfängeradresse (`name@domain`) reicht. Ein DNS-Eintrag (`_bmail._tcp.<domain>`) verrät das Ziel-Relay, und `GET /v1/profile/{name}` liefert kostenlos Public Key und Portosatz.
- **Ein Schlüssel, zwei Aufgaben (Mail + Login):** Jedes Postfach ist ein `secp256k1`-Schlüsselpaar (abgeleitet aus 24 BIP39-Wörtern). Es entschlüsselt Ende-zu-Ende-verschlüsselte Briefe (`ECIES + XChaCha20-Poly1305`) und dient gleichzeitig über den im Relay eingebauten **OpenID-Connect-Provider (OIDC)** als passwortloser Login (*„Sign in with lightningmail"*). Bei Neuanmeldungen mit Bestätigungsbrief zahlt der Nutzer einen **Porto-Vorschuss** (Tag `0x0A`), aus dem der **Service-Connector** (`client/src/connector.ts`) die Bestätigungsmail bezahlt.
- **Zwei Relay-Betriebsmodi:**
  - **Light-Relay:** `relayd` + `lnd` im **Neutrino-Modus** (BIP 157/158 Compact Block Filters über öffentliche Bitcoin-Nodes, ~10 GB Speicher, kein eigener `bitcoind` nötig).
  - **Full-Relay:** `relayd` + `lnd` + eigener `bitcoind`.

### Fertige Downloads & Clients

- 🐧 **Nativer Linux-Client (x86_64 Desktop-GUI für 1080p/4K + CLI):** [https://lightningmail.app/lightningmail-linux-amd64](https://lightningmail.app/lightningmail-linux-amd64)
- 🤖 **Native Android-App (`.apk`, Portrait/Landscape Touch + Hardware-Keystore):** [https://lightningmail.app/lightningmail.apk](https://lightningmail.app/lightningmail.apk)
- 🦅 **Thunderbird Tab-Add-on (`.xpi`):** [https://lightningmail.app/lightningmail-thunderbird.xpi](https://lightningmail.app/lightningmail-thunderbird.xpi)
- 🌐 **Web-App (PWA):** [https://lightningmail.app/app/](https://lightningmail.app/app/)

### Eigenes Relay betreiben (Etappe O)

```bash
# 1. Config + DNS-Anleitung erzeugen (Light = Neutrino ohne bitcoind, Full = mit)
./deploy/install-relay.sh --mode light --domain relay.example.org
docker compose -f deploy/docker-compose.light-relay.yml up -d lnd
docker compose -f deploy/docker-compose.light-relay.yml exec lnd lncli create   # einmalig, Seed sichern!
docker compose -f deploy/docker-compose.light-relay.yml up -d

# 2. Web-UI am Relay aktivieren (optional, aber empfohlen — relayd dann unter /app/)
cd client/app && npm install && npx vite build && cd ../..
mkdir -p deploy/ui && cp -r client/app/dist/. deploy/ui/
docker compose -f deploy/docker-compose.light-relay.yml up -d relayd
```

- **App am eigenen Relay:** einfach `https://relay.example.org:8443/app/` öffnen — die App erkennt ihr Relay selbst, keine einzige Einstellung; Login wie gewohnt (`.lmkey`-Datei, 24 Wörter oder Passkey).
- **Von außen aufschalten:** in jeder lightningmail-App beim Login „⚙️ Eigenes Relay (URL)…" wählen und die eigene Adresse eintippen — die App wechselt dorthin, die Android-App merkt sich das Heim-Relay dauerhaft.
- **Post von anderen Relays empfangen:** ein DNS-TXT-Eintrag `_bmail._tcp.relay.example.org` = `v=bmail1; relay=https://relay.example.org:8443; node=<NODE_PUBKEY>` genügt — dann findet jedes lightningmail-Relay `name@relay.example.org`.
- Hinweis: relayd spricht HTTP; für Produktivbetrieb TLS-Terminierung (Caddy/nginx) davorsetzen, dann ist die Adresse `https://relay.example.org/app/`.

### Aus dem Quellcode bauen & testen

```bash
# 1. Go-Relay & Linux-Client bauen (Go >= 1.22, kein CGO nötig)
cd relay
go test ./...
CGO_ENABLED=0 go build -o ../bin/relayd ./cmd/relayd
CGO_ENABLED=0 go build -o ../bin/lightningmail-linux ./cmd/lmcli

# 2. Web-PWA & Thunderbird-Add-on bauen
cd ../client
npm install
cd app && npx vite build
bash ../thunderbird/build-xpi.sh
```

---

## English — Overview (v1.0)

**lightningmail** attaches a small Bitcoin Lightning postage payment (via keysend) to every message and credits it directly to the recipient’s mailbox balance:
- **Spam becomes unprofitable:** One-way bulk mail costs real money from message one.
- **Conversations net out to zero:** Replies carry the postage back to the original sender.
- **No public directory, no conversation window:** Knowing `name@domain` is enough. A `_bmail._tcp.<domain>` DNS TXT record locates the destination relay, and `GET /v1/profile/{name}` returns the recipient’s public encryption key and postage rates for free.
- **Dual function (Mailbox + Passwordless Login):** Every mailbox is a `secp256k1` keypair backed up by 24 BIP39 recovery words. That single key decrypts end-to-end encrypted letters (`LM1` envelope: `ECIES + XChaCha20-Poly1305` + 1 MiB chunked attachments) and powers passwordless **OpenID Connect (OIDC)** logins (*“Sign in with lightningmail”* — including zero-registration stateless HTTPS origins). For service registrations requiring a confirmation letter, the user sends a **postage advance** (tag `0x0A`), funding the reply via our headless **Service Connector** (`client/src/connector.ts`).
- **Star-topology device sync (`/v1/state`):** Inbox, sent folder, drafts, read flags and the private address book sync encrypted across all devices via the user’s own relay; large attachments expire on the relay 7 days after first download and are cached locally on the client (`IndexedDB`).

### Running your own relay (Etappe O)

```bash
./deploy/install-relay.sh --mode light --domain relay.example.org   # writes relay.yaml + DNS how-to
docker compose -f deploy/docker-compose.light-relay.yml up -d        # light = LND Neutrino, no bitcoind
cd client/app && npm install && npx vite build && cd ../..
mkdir -p deploy/ui && cp -r client/app/dist/. deploy/ui/ && docker compose -f deploy/docker-compose.light-relay.yml up -d relayd
```

The relay then serves the whole web app itself at `https://relay.example.org:8443/app/` — clients need **zero settings** there (login via `.lmkey` file, 24 words or passkey as usual). Users coming from another relay pick the third entry in the relay dropdown (UI label in German: „⚙️ Eigenes Relay (URL)…"); the Android app remembers that home relay across starts. One `_bmail._tcp.relay.example.org` TXT record makes `name@relay.example.org` reachable from every other lightningmail relay.

See [https://lightningmail.app/architecture](https://lightningmail.app/architecture) and [`docs/spec.md`](docs/spec.md) for the 10 core architecture decisions and the 4-step guide to building native clients for iOS, macOS or Windows.
