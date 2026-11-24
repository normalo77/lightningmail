// Etappe R: Versand-Spool (docs/spec-R-spool.md). Scheitert der Peer-Keysend
// in handleSend, wird die Mail in pending_send persistiert und vom 60s-Ticker
// mit Backoff erneut zugestellt (dieselselbe deliver()-Code-Pfad wie initial).
// Porto bleibt währenddessen abgebucht; nach Retention wird die Mail dead
// letter + Rückerstattung als fee-Buchung 'dead-refund:<msg_id>'.
package relaysrv

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lightningmail/lm1/crypto"
	"github.com/lightningmail/lm1/envelope"
	"github.com/lightningmail/relay/internal/ledger"
)

// First retry after 5m, then 30m, 2h, 6h, 12h, 24h, dann täglich (cap letzter Wert).
var spoolBackoffSec = []int64{300, 1800, 7200, 21600, 43200, 86400}

const (
	spoolRetentionSec = 14 * 86400 // shortcut: Konstante; config-Regler, wenn Retention je Relay nötig wird
	spoolDeadTTLSec   = 90 * 86400 // dead rows aus dem Outbox-Index raus nach 90 Tagen
	spoolDueLimit     = 50         // pro Tick — Ticker läuft sequentiell, kein Retry-Feuerwerk
)

// deliver: the keysend path shared between initial handleSend and spool retries.
func (s *Server) deliver(ctx context.Context, envBin []byte, destNode string, sats int64) (string, int64, error) {
	ts := make([]byte, 8)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().Unix()))

	// TLV 34349337 (spec §2): BIP340 sig of the relay transport key over
	// sha256(envelope binary).
	transportPriv, err := s.relayTransportKey()
	if err != nil {
		return "", 0, fmt.Errorf("transport key: %w", err)
	}
	transportSig, err := crypto.Sign(transportPriv, envBin)
	if err != nil {
		return "", 0, fmt.Errorf("transport sign: %w", err)
	}
	transportPub := crypto.PublicBytes(transportPriv)
	customRecords := map[uint64][]byte{
		34349334: envBin,
		34349337: transportSig,
		34349339: transportPub[:],
		34349343: ts,
	}
	send := s.keysendFn
	if send == nil {
		send = s.ln.SendKeysend
	}
	return send(ctx, destNode, sats, customRecords)
}

// enqueueSpool: persistent 'pending' fuer den Ticker (msg_id aus dem Envelope,
// existsiert schon — R0a). false zurueck, wenn der Ticker den Versuch bereits
// uebernimmt; ein Fehler bedeutet: Spool-DB nicht verfuegbar, alte 502-Refund-
// Logik greift im Caller.
func (s *Server) enqueueSpool(account, targetHint, destNode string, env *envelope.Envelope, envBin []byte, sats, nowUnix int64) error {
	refs := make([]string, 0, len(env.BlobRefs))
	for _, r := range env.BlobRefs {
		refs = append(refs, hex.EncodeToString(r[:]))
	}
	refsJSON, _ := json.Marshal(refs)
	_, err := s.ledger.SpoolEnqueue(&ledger.PendingSend{
		MsgID:     hex.EncodeToString(env.MsgID[:]),
		Account:   account,
		Recipient: targetHint,
		DestNode:  destNode,
		Envelope:  envBin,
		BlobRefs:  string(refsJSON),
		Sats:      sats,
		NextTry:   nowUnix + spoolBackoffSec[0],
	})
	return err
}

// TickSpool is exported so the unit test can drive one retry round directly
// without waiting for the 60s ticker.
func (s *Server) TickSpool(t time.Time) {
	nowUnix := t.Unix()
	if err := s.ledger.SpoolPurgeDead(nowUnix, spoolDeadTTLSec); err != nil {
		log.Printf("spool: purge: %v", err)
	}
	due, err := s.ledger.SpoolDue(nowUnix, spoolDueLimit)
	if err != nil || len(due) == 0 {
		if err != nil {
			log.Printf("spool: due: %v", err)
		}
		return
	}
	for _, p := range due {
		feeReserveMsat := MaxRoutingFeeMsat(p.Sats)
		// one retry per row per tick, singleflight
		if nowUnix-p.CreatedAt > spoolRetentionSec {
			refundMsat := p.Sats*1000 + feeReserveMsat
			dead, err := s.ledger.SpoolMarkDeadAndRefund(p.ID, p.Account, refundMsat, p.MsgID, s.ratePtr())
			if err != nil {
				log.Printf("spool: dead-refund %s: %v", p.MsgID, err)
			} else if dead {
				log.Printf("spool: dead letter %s %d msat refundiert", shortHex(p.MsgID, 16), refundMsat)
			}
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_, feeMsat, err := s.deliver(ctx, p.Envelope, p.DestNode, p.Sats)
		cancel()
		if err == nil {
			if unused := feeReserveMsat - feeMsat; unused > 0 {
				_ = s.ledger.ApplyDeltaMeta(p.Account, unused, ledger.KindPostageOut, "refund:fee:"+p.MsgID, "btc", s.ratePtr())
			}
			if err := s.ledger.SpoolDelivered(p.ID); err != nil {
				log.Printf("spool: delete: %v", err)
			} else {
				log.Printf("spool: delivered %s after %d attempts (%d msat fee)", shortHex(p.MsgID, 16), p.Attempts, feeMsat)
			}
			continue
		}
		next := nowUnix + spoolBackoffSec[min(p.Attempts, len(spoolBackoffSec)-1)]
		log.Printf("spool: retry %s attempt %d failed: %v", shortHex(p.MsgID, 16), p.Attempts+1, err)
		if err := s.ledger.SpoolFailed(p.ID, next); err != nil {
			log.Printf("spool: fail: %v", err)
		}
	}
}

// GET /v1/outbox (auth) — pending+dead sends of the account making the request.
func (s *Server) handleOutbox(w http.ResponseWriter, r *http.Request) {
	list, err := s.ledger.SpoolOutbox(r.Header.Get("X-Bmail-Account"))
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"outbox: %v"}`, err), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(list)
}
