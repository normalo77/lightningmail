// Etappe G2 — Statement-Export (§25): Konto- und Betreiber-Sichten als
// hash-verkettete Zeilen. Kette: hash_i = sha256(hash_{i-1} || kanonische
// Zeile_i), Genesis = sha256("bmail-statement-v1:"|<konto>). Monatsanfang =
// Anker: wer einen Export archiviert, kann spaetere Exporte als Fortsetzung
// pruefen — der Stapel kann bei der Pruefung nicht umfallen.
//
// Wichtig: Die Kette wird IMMER von Genesis an neu gerechnet (auch fuer
// Teilbereiche), sonst waeren from/to-Ausschnitte nicht verkettbar.
// Persoenliche Konten haben wenig Zeilen — O(n) pro Export ist fine.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// StmtRow = eine Statement-Zeile inkl. Ketten-Hashes. NULL-Spalten (ungeratet)
// bleiben Pointer — fuer die Kanon-Form relevant ("" vs "0").
type StmtRow struct {
	ID        int64
	CreatedAt int64
	Kind      string
	Currency  string
	DeltaMsat int64
	EurMicro  *int64
	RateTs    *int64
	RateSrc   *string
	RateMEur  *int64
	Ref       string
	PrevHash  string
	Hash      string
}

// CanonRow ist die kanonische Zeilenform fuer die Hash-Kette (auch von
// Clients/Prueftools reproduzierbar: Felder mit '|', NULL als Leerstring).
func (r StmtRow) CanonRow() string {
	return fmt.Sprintf("%d|%d|%s|%s|%d|%s|%s|%s|%s|%s",
		r.ID, r.CreatedAt, r.Kind, r.Currency, r.DeltaMsat,
		optI64(r.EurMicro), optI64(r.RateTs), optStr(r.RateSrc), optI64(r.RateMEur), r.Ref)
}

func optI64(p *int64) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%d", *p)
}
func optStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func shaHex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func GenesisHash(account string) string { return shaHex("bmail-statement-v1:" + account) }

func OperatorGenesisHash(relayName string) string { return shaHex("bmail-operator-v1:" + relayName) }

// StatementChain liefert die Zeilen in [from,to] (Unix-Sekunden, 0 = offen)
// plus die bis dahin durchgerechnete Kette. Alle Zeilen ASCENDING nach id.
func (l *Ledger) StatementChain(account string, from, to int64) (rows []StmtRow, head string, err error) {
	q := `SELECT t.id, t.created_at, t.kind, t.currency, t.delta_msat, t.eur_micro, t.rate_ts, t.rate_src, t.rate_meur_per_btc, COALESCE(t.ref,'')
      FROM txlog t JOIN account a ON a.id=t.account_id WHERE a.name=?`
	args := []any{account}
	if to > 0 {
		q += ` AND t.created_at<=?`
		args = append(args, to)
	}
	q += ` ORDER BY t.id ASC`
	rs, err := l.db.Query(q, args...)
	if err != nil {
		return nil, "", err
	}
	defer rs.Close()
	prev := GenesisHash(account)
	for rs.Next() {
		var r StmtRow
		if err := rs.Scan(&r.ID, &r.CreatedAt, &r.Kind, &r.Currency, &r.DeltaMsat,
			&r.EurMicro, &r.RateTs, &r.RateSrc, &r.RateMEur, &r.Ref); err != nil {
			return nil, "", err
		}
		r.PrevHash = prev
		r.Hash = shaHex(prev + r.CanonRow())
		prev = r.Hash
		if from > 0 && r.CreatedAt < from {
			continue // nur fuer die Kette mitrechnen, nicht ausgeben
		}
		rows = append(rows, r)
	}
	return rows, prev, rs.Err()
}

// OpRow = Betreiber-Zeile: Einnahmen des Relays (positive Betraege) bzw.
// Erstattungen (negativ). Quellen: txlog kind='fee' (Byte-Porto/Refunds,
// Vorzeichen gedreht: was der Nutzer zahlt, verdient der Betreiber) und
// card_purchases.fee_msat (Karten-Fee, Anteil aus dem Split).
type OpRow struct {
	Source    string // "txlog" | "card"
	ID        int64
	CreatedAt int64
	Account   string
	Label     string // "byte_porto" | "refund" | "card_fee"
	AmountMsat int64
	EurMicro  *int64
	RateTs    *int64
	RateSrc   *string
	RateMEur  *int64
	Ref       string
	PrevHash  string
	Hash      string
}

func (r OpRow) CanonRow() string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%d|%s|%s|%s|%s|%s",
		r.Source, r.ID, r.CreatedAt, r.Account, r.Label, r.AmountMsat,
		optI64(r.EurMicro), optI64(r.RateTs), optStr(r.RateSrc), optI64(r.RateMEur), r.Ref)
}

// OperatorChain: dieselbe Kettenkonstruktion ueber beide Quellen,
// aufsteigend nach (created_at, source, id) — deterministisch.
func (l *Ledger) OperatorChain(relayName string, from, to int64) (rows []OpRow, head string, err error) {
	if err := l.ensureDirectory(); err != nil {
		return nil, "", err
	}
	timeCond := func(col string) (string, []any) {
		s, a := "", []any{}
		if to > 0 {
			s += " AND " + col + "<=?"
			a = append(a, to)
		}
		return s, a
	}
	var all []OpRow
	// 1) txlog kind='fee': Betrag aus Nutzersicht negativ → Betreiber positiv
	extra, args := timeCond("t.created_at")
	q1 := `SELECT t.id, t.created_at, a.name, -t.delta_msat, t.eur_micro, t.rate_ts, t.rate_src, t.rate_meur_per_btc, COALESCE(t.ref,'')
       FROM txlog t JOIN account a ON a.id=t.account_id WHERE t.kind='fee'` + extra + ` ORDER BY t.id ASC`
	rs, err := l.db.Query(q1, args...)
	if err != nil {
		return nil, "", err
	}
	for rs.Next() {
		var r OpRow
		r.Source = "txlog"
		if err := rs.Scan(&r.ID, &r.CreatedAt, &r.Account, &r.AmountMsat, &r.EurMicro, &r.RateTs, &r.RateSrc, &r.RateMEur, &r.Ref); err != nil {
			rs.Close()
			return nil, "", err
		}
		// eur_micro der txlog-Zeile ist aus Nutzersicht (negativ) → drehen
		if r.EurMicro != nil {
			v := -(*r.EurMicro)
			r.EurMicro = &v
		}
		if len(r.Ref) > 5 && r.Ref[:5] == "blob:" {
			r.Label = "byte_porto"
		} else if len(r.Ref) > 7 && r.Ref[:7] == "refund:" {
			r.Label = "refund"
		} else {
			r.Label = "fee"
		}
		all = append(all, r)
	}
	rs.Close()
	if err := rs.Err(); err != nil {
		return nil, "", err
	}
	// 2) Karten-Fees aus card_purchases
	extra2, args2 := timeCond("p.created_at")
	q2 := `SELECT p.rowid, p.created_at, b2.name, p.fee_msat, p.eur_micro, p.rate_ts, p.rate_src, p.rate_meur_per_btc, p.card_hash
       FROM card_purchases p JOIN account b2 ON b2.id=p.buyer_id WHERE p.fee_msat>0` + extra2 + ` ORDER BY p.rowid ASC`
	rs2, err := l.db.Query(q2, args2...)
	if err != nil {
		return nil, "", err
	}
	for rs2.Next() {
		var r OpRow
		r.Source, r.Label = "card", "card_fee"
		if err := rs2.Scan(&r.ID, &r.CreatedAt, &r.Account, &r.AmountMsat, &r.EurMicro, &r.RateTs, &r.RateSrc, &r.RateMEur, &r.Ref); err != nil {
			rs2.Close()
			return nil, "", err
		}
		// eur_micro der Kaufzeile ist der Verkaeufer-Erloes; Betreiber-EUR
		// anteilig aus dem Kurs: fee_meur = fee_msat*rate/1e8
		if r.RateMEur != nil && *r.RateMEur > 0 {
			v := r.AmountMsat * (*r.RateMEur) / 100000000
			r.EurMicro = &v
		} else {
			r.EurMicro = nil
		}
		all = append(all, r)
	}
	rs2.Close()
	if err := rs2.Err(); err != nil {
		return nil, "", err
	}
	// deterministische Sortierung + Kette (ueber ALLE Zeilen bis `to` —
	// auch die vor `from`, sonst waeren Teilbereiche nicht verkettbar)
	sortOps(all)
	prev := OperatorGenesisHash(relayName)
	for i := range all {
		r := &all[i]
		r.PrevHash = prev
		r.Hash = shaHex(prev + r.CanonRow())
		prev = r.Hash
	}
	// Ausgabe filtern
	for i := range all {
		if from > 0 && all[i].CreatedAt < from {
			continue
		}
		rows = append(rows, all[i])
	}
	return rows, prev, nil
}

// sortOps: created_at, dann source, dann id (insertion-order-stabil).
func sortOps(rows []OpRow) {
	for i := 1; i < len(rows); i++ { // Insertion-Sort: Op-Listen bleiben klein
		for j := i; j > 0; j-- {
			a, b := rows[j], rows[j-1]
			if a.CreatedAt > b.CreatedAt || (a.CreatedAt == b.CreatedAt && (a.Source > b.Source || (a.Source == b.Source && a.ID >= b.ID))) {
				break
			}
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}
