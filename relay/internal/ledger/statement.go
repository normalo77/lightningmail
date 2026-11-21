// Etappe G2 — statement export (§25): account and operator views as
// hash-chained rows. Chain: hash_i = sha256(hash_{i-1} || canonical
// row_i), genesis = sha256("bmail-statement-v1:"|<account>). Month start =
// anchor: whoever archives an export can verify later exports as its
// continuation — the stack cannot topple during verification.
//
// Important: the chain is ALWAYS recomputed from genesis (even for
// partial ranges), otherwise from/to slices would not be chainable.
// Personal accounts have few rows — O(n) per export is fine.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// StmtRow = one statement row incl. chain hashes. NULL columns (unrated)
// stay pointers — relevant for the canonical form ("" vs "0").
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

// CanonRow is the canonical row form for the hash chain (reproducible by
// clients/verification tools too: fields joined with '|', NULL as empty string).
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

// StatementChain returns the rows in [from,to] (unix seconds, 0 = open)
// plus the chain computed up to that point. All rows ASCENDING by id.
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
			continue // compute for the chain only, don't emit
		}
		rows = append(rows, r)
	}
	return rows, prev, rs.Err()
}

// OpRow = operator row: relay income (positive amounts) or
// refunds (negative). Source: txlog kind='fee' (byte postage/refunds,
// sign flipped: what the user pays, the operator earns).
type OpRow struct {
	Source     string // "txlog"
	ID         int64
	CreatedAt  int64
	Account    string
	Label      string // "byte_porto" | "refund" | "fee"
	AmountMsat int64
	EurMicro   *int64
	RateTs     *int64
	RateSrc    *string
	RateMEur   *int64
	Ref        string
	PrevHash   string
	Hash       string
}

func (r OpRow) CanonRow() string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%d|%s|%s|%s|%s|%s",
		r.Source, r.ID, r.CreatedAt, r.Account, r.Label, r.AmountMsat,
		optI64(r.EurMicro), optI64(r.RateTs), optStr(r.RateSrc), optI64(r.RateMEur), r.Ref)
}

// OperatorChain: chain construction over all operator fees (txlog kind='fee'),
// ascending by id — deterministic.
func (l *Ledger) OperatorChain(relayName string, from, to int64) (rows []OpRow, head string, err error) {
	extra, args := "", []any{}
	if to > 0 {
		extra = " AND t.created_at<=?"
		args = append(args, to)
	}
	q1 := `SELECT t.id, t.created_at, a.name, -t.delta_msat, t.eur_micro, t.rate_ts, t.rate_src, t.rate_meur_per_btc, COALESCE(t.ref,'')
       FROM txlog t JOIN account a ON a.id=t.account_id WHERE t.kind='fee'` + extra + ` ORDER BY t.id ASC`
	rs, err := l.db.Query(q1, args...)
	if err != nil {
		return nil, "", err
	}
	defer rs.Close()
	var all []OpRow
	for rs.Next() {
		var r OpRow
		r.Source = "txlog"
		if err := rs.Scan(&r.ID, &r.CreatedAt, &r.Account, &r.AmountMsat, &r.EurMicro, &r.RateTs, &r.RateSrc, &r.RateMEur, &r.Ref); err != nil {
			return nil, "", err
		}
		// eur_micro of the txlog row is from the user's view (negative) → flip
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
	if err := rs.Err(); err != nil {
		return nil, "", err
	}
	prev := OperatorGenesisHash(relayName)
	for i := range all {
		r := &all[i]
		r.PrevHash = prev
		r.Hash = shaHex(prev + r.CanonRow())
		prev = r.Hash
		if from > 0 && r.CreatedAt < from {
			continue
		}
		rows = append(rows, *r)
	}
	return rows, prev, nil
}
