# Etappe T: Tor-Betriebsstufen fuer Relay-Betreiber

Anhangs- und Mirror-Traffic zwischen Relays kann durch Tor laufen — als
Betriebsstufe, ohne das Protokoll anzufassen (CONCEPT §33). Drei Stufen:

1. **ohne** (Default): kein `tor:`-Block in relay.yaml — alles wie bisher
   per https.
2. **Empfang**: Hidden Service vor Port 8443 + optionales `onion=`-Feld im
   `_bmail._tcp`-DNS-TXT. Relay↔Relay-Rufe (Profile, Receipt-Mirror,
   Blob-Mirror) gehen dann über SOCKS5 zu `*.onion`-Peers; https bleibt
   Fallback. **Kein Exit.**
3. **Node** (optional): zusätzlich Teilnahme als normales Tor-Relay mit
   Bandbreiten-Limit (`torrc-or-relay.example`). **Exit bleibt
   ausgeschlossen.**

Stand: Stufe 2 ist am live regtest-Stack getestet (21.11.2026). Die
Bandbreiten-Werte in `torrc-or-relay.example` (Stufe 3) sind
Standard-Tor-Empfehlung, in diesem Stack nicht durchgemessen.

## Stufe 2: Hidden Service einrichten

### 1. Tor installieren

```
sudo apt update && sudo apt install tor
```

### 2. torrc-Snippet einsetzen

Inhalt von `torrc-hidden-service.example` in `/etc/tor/torrc` uebernehmen
(inkl. `SOCKSPort 9050`, dem Hidden-Service-Block und den Rechten fuer
`/var/lib/tor/bmail_relay`), dann:

```
sudo systemctl restart tor
```

### 3. Onion-Adresse lesen

Die Adresse entsteht beim ersten Start; der private Schluessel liegt im
selben Verzeichnis — mit sichern, eine Neuanlage erzwingt eine neue Adresse:

```
cat /var/lib/tor/bmail_relay/hostname
# -> abcdef...long...v3.onion
```

### 4. relay.yaml erweitern

```yaml
tor: {socks5: '127.0.0.1:9050'}
```

Ohne diesen Block ignoriert relayd ein `onion=`-Feld in DNS — es laeuft
dann alles weiter über https. Relay neu starten.

### 5. DNS-TXT um `onion=` erweitern

Feld in bestehende `_bmail._tcp`-Record eintragen (CONCEPT §4.2):

```
_bmail._tcp.example.org.  IN TXT  "v=bmail1; relay=https://relay.example.org; onion=abcdef...long...v3.onion; node=<hex>"
```

```
dig +short TXT _bmail._tcp.example.org
```

`onion=` akzeptiert nur **v3**-Adressen; ein ungueltiger Wert wird
ignoriert (reines https wie vorher) — die Discovery bleibt heil.

Pruefen, ob der Hidden Service erreichbar ist:

```
curl --socks5-hostname 127.0.0.1:9050 http://<hash>.onion/health
```

## Was das Relay danach tut

Mit gesetztem `tor.socks5` **bevorzugen** die Relay↔Relay-Rufe (Profil-Loop,
Receipt-Mirror, Blob-Mirror) die onion-URL aus dem TXT-Feld der Gegenseite
und dialen sie über SOCKS5; die https-URL bleibt Fallback, wenn die
Gegenseite kein gueltiges `onion=` publiziert oder Tor nicht mitlaeuft.
An einem request aendert sich nichts — Tor ist nur der Transport.

## Sicherheits-Hinweise

- **Niemals Exit.** Weder Stufe 2 noch Stufe 3 leiten fremden Klartext-
  Traffic ins normale Internet weiter (`ExitRelay 0`, `IPv4Policy reject
  *:*`). Das eigene Heimnetz bleibt aus der Fremd-Weiterleitung raus.
- **Onion-only-TXT bleibt SSRF-sicher:** wenn ein gueltiges onion-Feld
  existiert und `socks5` gesetzt ist, waehlt relayd die onion-URL — das
  (ggf. private) https-Feld wird dann **nie** gewaehlt und damit auch kein
  DNS-rebinding auf interne Adressen moeglich. Ohne onion-Feld gilt wie
  bisher der normale Public-IP-Check (`verifyPublicRelayURL`).
- **Der Hidden Service exponiert nichts ausser der Relay-HTTP-API** auf
  8443: kein SSH, kein LND-RPC, keine Web-UI-Pfade, die relayd nicht selbst
  schon ueber https haette.

## Stufe 3: als normaler Tor-Relay mitmachen

Zusaetzlich (kein Muss) kann der Knoten fremde Tor-Circuits mittragen:
Inhalt von `torrc-or-relay.example` dazunehmen, 9001/TCP weiterleiten,
`RelayBandwidthRate`/`RelayBandwidthBurst` an die eigene Leitung anpassen.
Kombination mit Stufe 2: beide Bloecke in einer torrc, dabei `SocksPort 0`
aus dem Node-Block streichen (der HS-Block setzt 9050).

## Lightning bleibt unberiuehrt

Porto und Kuvert laufen schon heute im Lightning-Onion (LNDs eigener
Tor-Block) — die Etappe-T-Konfiguration oben aendert daran nichts,
Anhänge waren und sind Lightning-egal.
