// Etappe B — Oeffentliches Directory (CONCEPT §21, Beschluss 15.11.2026):
// signierte Profilkarten mit gdpr1-Consent, Kartenkauf mit Dedup pro card_hash.
//
// Grundsätze aus dem Beschluss:
//   - Karte = clientseitig gefilterte, mit dem Mailbox-Key signierte Projektion.
//     Der Server speichert EXAKT die signierten Bytes (kein Re-Serialisieren —
//     das würde die Signatur brechen) und prüft die Signatur beim PUT.
//   - Suche nur exakter Treffer; Key-Auflösung gratis, Karte bezahlt.
//   - Preis wertdefiniert in Milli-EUR (§26), Split Server-Fee + Kontaktpreis.
//   - Dedup pro card_hash: dieselbe Karte wird pro Käufer einmal bezahlt.
//   - DELETE = DSGVO-Löschung: Karte + Consent-Historie weg. Käufe bleiben als
//     Finanzfakten (§25: keine nachträgliche Buchungs-Kosmetik).
package ledger

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

var ErrNoProfile = errors.New("ledger: no published profile")

type Profile struct {
	AccountID int64
	Name      string
	Pubkey    []byte // 33B compressed mailbox key
	CardJSON  string // exakte signierte Bytes (Kanonikalität = Sache des Clients)
	CardHash  string // hex sha256(CardJSON)
	Sig       string // hex BIP340 über sha256(CardJSON)
	Consent   string // JSON {"v":"gdpr1","ts":…,"fields":[…],"purpose":"directory"}
	PriceMEur int64  // Kontaktpreis in Milli-EUR (Server-Fee kommt dazu)
	CreatedAt int64
	UpdatedAt int64
}

func CardHashOf(cardJSON []byte) string {
	h := sha256.Sum256(cardJSON)
	return hex.EncodeToString(h[:])
}

func (l *Ledger) ensureDirectory() error {
	_, err := l.db.Exec(`CREATE TABLE IF NOT EXISTS profiles (
		account_id INTEGER PRIMARY KEY REFERENCES account(id),
		card_json  TEXT    NOT NULL,
		card_hash  TEXT    NOT NULL,
		sig        TEXT    NOT NULL,
		consent    TEXT    NOT NULL,
		price_meur INTEGER NOT NULL DEFAULT 25,
		created_at INTEGER NOT NULL,
		updated_at INTEGER NOT NULL
	)`)
	if err != nil {
		return err
	}
	// Consent-Historie append-only (Nachweis der Einwilligung); DELETE loescht
	// sie mit — Löschrecht schlägt Audit (Beschluss 15.11.).
	_, err = l.db.Exec(`CREATE TABLE IF NOT EXISTS consent_log (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		account_id INTEGER NOT NULL REFERENCES account(id),
		card_hash  TEXT    NOT NULL,
		consent    TEXT    NOT NULL,
		op         TEXT    NOT NULL CHECK (op IN ('put')),
		ts         INTEGER NOT NULL
	)`)
	if err != nil {
		return err
	}
	// Kauf = Finanzfakt: ueberlebt Profil-Loeschung; PK dedupiert pro
	// (Kaeufer, Karteninhalt). eur_micro & Co stempeln den Erloes des Kontakts.
	_, err = l.db.Exec(`CREATE TABLE IF NOT EXISTS card_purchases (
		buyer_id    INTEGER NOT NULL REFERENCES account(id),
		card_hash   TEXT    NOT NULL,
		seller_id   INTEGER NOT NULL REFERENCES account(id),
		paid_msat   INTEGER NOT NULL,
		seller_msat INTEGER NOT NULL,
		fee_msat    INTEGER NOT NULL,
		currency    TEXT    NOT NULL DEFAULT 'btc',
		eur_micro   INTEGER,
		rate_ts     INTEGER,
		rate_src    TEXT,
		rate_meur_per_btc INTEGER,
		created_at  INTEGER NOT NULL,
		PRIMARY KEY (buyer_id, card_hash)
	)`)
	return err
}

// PutProfile veroeffentlicht oder aktualisiert die Karte (UPSERT); der
// Consent-Log waechst append-only mit.
func (l *Ledger) PutProfile(accountID int64, cardJSON, sig, consent string, priceMEur int64) (*Profile, error) {
	if err := l.ensureDirectory(); err != nil {
		return nil, err
	}
	hash := CardHashOf([]byte(cardJSON))
	t := now()
	_, err := l.db.Exec(
		`INSERT INTO profiles (account_id, card_json, card_hash, sig, consent, price_meur, created_at, updated_at)
     VALUES (?,?,?,?,?,?,?,?)
     ON CONFLICT(account_id) DO UPDATE SET
       card_json=excluded.card_json, card_hash=excluded.card_hash, sig=excluded.sig,
       consent=excluded.consent, price_meur=excluded.price_meur, updated_at=excluded.updated_at`,
		accountID, cardJSON, hash, sig, consent, priceMEur, t, t)
	if err != nil {
		return nil, err
	}
	if _, err := l.db.Exec(
		`INSERT INTO consent_log (account_id, card_hash, consent, op, ts) VALUES (?,?,?,'put',?)`,
		accountID, hash, consent, t); err != nil {
		return nil, err
	}
	return &Profile{AccountID: accountID, CardJSON: cardJSON, CardHash: hash,
		Sig: sig, Consent: consent, PriceMEur: priceMEur, CreatedAt: t, UpdatedAt: t}, nil
}

func (l *Ledger) GetProfileByName(name string) (*Profile, error) {
	if err := l.ensureDirectory(); err != nil {
		return nil, err
	}
	p := &Profile{}
	err := l.db.QueryRow(
		`SELECT p.account_id, a.name, a.mailbox_pubkey, p.card_json, p.card_hash, p.sig,
        p.consent, p.price_meur, p.created_at, p.updated_at
     FROM profiles p JOIN account a ON a.id=p.account_id WHERE a.name=?`, name).
		Scan(&p.AccountID, &p.Name, &p.Pubkey, &p.CardJSON, &p.CardHash, &p.Sig,
			&p.Consent, &p.PriceMEur, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (l *Ledger) HasProfile(accountID int64) (bool, error) {
	if err := l.ensureDirectory(); err != nil {
		return false, err
	}
	var n int
	err := l.db.QueryRow(`SELECT COUNT(*) FROM profiles WHERE account_id=?`, accountID).Scan(&n)
	return n > 0, err
}

// DeleteProfile = Auskunfts-/Loeschrecht: Karte und Consent-Historie weg,
// idempotent. card_purchases (Finanzfakten des Kaeufers) bleiben.
func (l *Ledger) DeleteProfile(accountID int64) error {
	if err := l.ensureDirectory(); err != nil {
		return err
	}
	if _, err := l.db.Exec(`DELETE FROM consent_log WHERE account_id=?`, accountID); err != nil {
		return err
	}
	_, err := l.db.Exec(`DELETE FROM profiles WHERE account_id=?`, accountID)
	return err
}

func (l *Ledger) HasPurchase(buyerName, cardHash string) (bool, error) {
	if err := l.ensureDirectory(); err != nil {
		return false, err
	}
	var n int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM card_purchases p JOIN account a ON a.id=p.buyer_id
     WHERE a.name=? AND p.card_hash=?`, buyerName, cardHash).Scan(&n)
	return n > 0, err
}

// BoughtFrom: hat der Kaeufer JE etwas von diesem Verkaeufer bezahlt?
// (Achtungs-Note 410 statt 404, wenn die Karte inzwischen geloescht ist.)
func (l *Ledger) BoughtFrom(buyerName, sellerName string) (bool, error) {
	if err := l.ensureDirectory(); err != nil {
		return false, err
	}
	var n int
	err := l.db.QueryRow(
		`SELECT COUNT(*) FROM card_purchases p
     JOIN account b2 ON b2.id=p.buyer_id JOIN account s2 ON s2.id=p.seller_id
     WHERE b2.name=? AND s2.name=?`, buyerName, sellerName).Scan(&n)
	return n > 0, err
}

// BuyCard atomar: Kaufeintrag (Dedup via PK), Debit Käufer (card_out),
// Kredit Kontakt (card_in, mit Steuerstempel). fresh=false → card_hash war
// schon gekauft, es wurde NICHTS gebucht (Dedup, Beschluss 15.11.).
// Optimistic Locking wie ApplyDelta: beide Konten in EINER Transaktion.
func (l *Ledger) BuyCard(buyerName, sellerName, cardHash string, paidMsat, sellerMsat, feeMsat int64, currency string, rate *RateStamp) (fresh bool, err error) {
	if err := l.ensureDirectory(); err != nil {
		return false, err
	}
	if currency == "" {
		currency = "btc"
	}
	for attempt := 0; attempt < maxRetries; attempt++ {
		var buyerID, sellerID, buyerBal, sellerBal, buyerVer, sellerVer int64
		if err := l.db.QueryRow(`SELECT id, balance_msat, version FROM account WHERE name=?`, buyerName).
			Scan(&buyerID, &buyerBal, &buyerVer); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, ErrNotFound
			}
			return false, err
		}
		if err := l.db.QueryRow(`SELECT id, balance_msat, version FROM account WHERE name=?`, sellerName).
			Scan(&sellerID, &sellerBal, &sellerVer); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, ErrNotFound
			}
			return false, err
		}
		if buyerID == sellerID {
			return false, errors.New("ledger: card self-purchase")
		}
		if buyerBal < paidMsat {
			return false, ErrInsufficient
		}
		tx, err := l.db.Begin()
		if err != nil {
			return false, err
		}
		t := now()
		var eurMicro, rateTs, rateMEur any
		var rateSrc any
		if rate != nil && rate.MEurPerBtc > 0 {
			eurMicro, rateTs, rateSrc, rateMEur = rate.EurMicro(sellerMsat), rate.Ts, rate.Src, rate.MEurPerBtc
		}
		res, err := tx.Exec(
			`INSERT OR IGNORE INTO card_purchases
       (buyer_id, card_hash, seller_id, paid_msat, seller_msat, fee_msat, currency,
        eur_micro, rate_ts, rate_src, rate_meur_per_btc, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
			buyerID, cardHash, sellerID, paidMsat, sellerMsat, feeMsat, currency,
			eurMicro, rateTs, rateSrc, rateMEur, t)
		if err != nil {
			tx.Rollback()
			return false, err
		}
		if n, _ := res.RowsAffected(); n == 0 {
			tx.Rollback()
			return false, nil // schon gekauft — Dedup, kein Geld bewegt
		}
		if err := l.moveInTx(tx, buyerID, buyerBal, -paidMsat, buyerVer, KindCardOut, cardHash, currency, rate, t); err != nil {
			tx.Rollback()
			if errors.Is(err, ErrConflict) {
				time.Sleep(time.Duration(attempt) * time.Millisecond / 4)
				continue
			}
			return false, err
		}
		if err := l.moveInTx(tx, sellerID, sellerBal, sellerMsat, sellerVer, KindCardIn, cardHash, currency, rate, t); err != nil {
			tx.Rollback()
			if errors.Is(err, ErrConflict) {
				time.Sleep(time.Duration(attempt) * time.Millisecond / 4)
				continue
			}
			return false, err
		}
		if err := tx.Commit(); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, ErrConflict
}

// moveInTx: eine Kontobewegung + txlog-Zeile innerhalb einer laufenden Transaktion.
// deltaMsat negativ = Ausgabe (Stempelbetrag bleibt vorzeichenrichtig ueber delta).
func (l *Ledger) moveInTx(tx *sql.Tx, accountID, bal, deltaMsat, ver int64, kind Kind, ref, currency string, rate *RateStamp, t int64) error {
	if bal+deltaMsat < 0 {
		return ErrInsufficient
	}
	res, err := tx.Exec(`UPDATE account SET balance_msat=?, version=?, updated_at=? WHERE id=? AND version=?`,
		bal+deltaMsat, ver+1, t, accountID, ver)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrConflict
	}
	var eurMicro, rateTs, rateMEur any
	var rateSrc any
	if rate != nil && rate.MEurPerBtc > 0 {
		eurMicro, rateTs, rateSrc, rateMEur = rate.EurMicro(deltaMsat), rate.Ts, rate.Src, rate.MEurPerBtc
	}
	_, err = tx.Exec(
		`INSERT INTO txlog (account_id, delta_msat, kind, ref, currency, eur_micro, rate_ts, rate_src, rate_meur_per_btc, created_at)
     VALUES (?,?,?,?,?,?,?,?,?,?)`,
		accountID, deltaMsat, string(kind), ref, currency, eurMicro, rateTs, rateSrc, rateMEur, t)
	return err
}
