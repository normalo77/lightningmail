# HISTORIE — lightningmail im Bogen der Internetgeschichte

> Arbeitsdokument für Inszenierung/Marketing (13.11.2026). Kein Spec-Teil.
> Kernthese: **Hashcash hat 1997 die digitale Briefmarke erfunden, um E-Mail
> zu retten. Die Marke kostete nur — sie zahlte nie. Lightning macht daraus
> 2026 Porto, das beim Empfänger ankommt. lightningmail schließt den Kreis.**

## Zeitachse (12 Stationen)

| Jahr | Ereignis | Bedeutung für uns |
|------|----------|-------------------|
| 1971 | Tomlinson, erste E-Mail, das @ | Offenes Protokoll: jeder mit jedem, kein Türsteher |
| 1980 | Usenet/Netnews | Dezentrale Diskussionskultur; Mail-Clients hatten News eingebaut |
| 1985 | „Ender's Game" (Card) | Literarische Blaupause: Autorität durch Inhalt, nicht Ausweis (Locke/Demosthenes = Pseudonym-Identität per Argument) |
| 1992 | Cypherpunks-Liste | „Cypherpunks write code" — Krypto als Freiheitswerkzeug |
| 1993/94 | Ewiger September, Canter-&-Siegel-Spam | Die Ursünde: Spam ist gratis für den Sender, teuer für den Empfänger |
| 1997/02 | **Hashcash** (Adam Back) | Proof-of-Work als Briefmarke. Genial, aber asymmetrisch: die Marke *verbrennt* Wert, niemand bekommt ihn |
| 2008 | Bitcoin-Whitepaper | Zitiert Hashcash — PoW bekommt Geld |
| 2015/16 | Lightning Network | Micropayments real: Sub-Cent, in Sekunden final |
| 2022 | LUD-16 Lightning Address; MicroStrategy; pay2email; † Whatsat | `name@domain` wird Zahlungsziel. Whatsat stirbt an Endnutzer-Liquidität → Relays müssen die Kanäle halten |
| 2024 | BIP-353 | Zahlung per DNS-Record — Name und Geld verschmelzen |
| 2025 | LNemail lebt | Anonyme Wegwerf-Mailbox gegen LN-Porto. Beweis: Leute zahlen, UX funktioniert. Aber: Plattform kassiert, Identität wegwerfbar, Klartext beim Betreiber |
| 2026 | **lightningmail** | Porto landet beim Empfänger (Guthaben), Identität = Schlüssel (portabel, Passkey, OIDC-ready), E2E zwischen Relays, ✓✓-Semantik, MIT |

## Die fünf Inszenierungs-Botschaften

1. **Die Briefmarke, die endlich auszahlt.** Hashcash verbrannte Rechenarbeit;
   bei uns wird dasselbe Porto überwiesen. Spam wird vom Ärgernis zum Einkommen
   des Empfängers. Stille bleibt kostenlos (Kontakte = 0 Porto).
2. **Ein Schlüssel, ein Transport, ein Speicher.** Mail + Identität + Passkey
   + Anhänge: ein Primitiv statt fünf Systeme. Kein Feature-Zoo, eine Ökonomie.
3. **Zurück zu 1980, mit dem Wissen von 2026.** Das alte Netz: offene
   Protokolle, Self-Hosting, keine Plattformen. Wir bauen nicht noch eine
   Plattform — wir bauen das Protokoll + die Ökonomie für die nächste.
4. **Autorität durch Inhalt** (Ender's Game / Locke): pseudonyme
   Schlüssel-Identität mit portabler Reputation (BMRV) statt Klarnamenszwang
   oder Plattform-Verifizierung.
5. **Ehrliche Privacy statt Theater.** Wer-mit-wem sieht der Relay (wie heute
   bei jeder E-Mail); der Inhalt ist E2E; Receipts verraten nur den
   Sync-Zeitpunkt; Onion-Routing ist Etappe 5, kein Marketing-Versprechen.

## Zielgruppen-Hooks

- **Bitcoiner:** „Hashcash zu Ende gedacht — die Briefmarke aus dem
  Whitepaper-Stammbaum zahlt endlich aus." Keysend-TLV als zweites Leben.
- **Privacy-Leute:** E2E, Self-Hosting, ehrliche Metadaten-Grenzen, kein
  Plattform-Zwang.
- **Indie-Hacker / KI-Agenten:** API-first, llms.txt + SKILL.md (LNemail
  zeigt den Weg), MCP-Schnittstelle (§15), Pay-per-Mail für Agenten-Ökonomie.
- **Netz-Oldies (40+):** Usenet-Nostalgie — „als Mail-Clients noch News
  konnten" → §24-Denkskizze Gruppen/Netnews als Ausblick.

## Assets (docs/marketing/)

- `timeline.svg/png` — der 12-Stationen-Bogen 1971→2026
- `prinzip.svg/png` — drei Säulen: Schlüssel / Transport / Speicher
- `porto.svg/png` — Geldfluss-Vergleich: E-Mail (Spam gratis) vs. lightningmail (Spam = Einkommen)
- `titel.svg`, `era1.svg`, `era2.svg`, `close.svg` — Videofolien
- `video.mp4` — Kurzfilm (~90 s, Folien + deutsche Erzählstimme)

## Pitch-Einzeiler (Kandidaten)

- „Deine Mails sind bares Geld wert — und die der anderen auch." (CONCEPT §19)
- „Die Briefmarke, die endlich auszahlt."
- „Selbstbestimmte, bezahlbare Identität — Mail ist nur die erste Anwendung."
- „Spam war gestern ein Ärgernis. Heute ist er dein Einkommen."
