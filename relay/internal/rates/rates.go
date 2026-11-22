// Package rates: daily EUR/BTC rate for value-defined prices (§25 tax log,
// §26 multi-currency). One fetch per day (24h cache, checked hourly);
// manual_eur_per_btc from the config always wins (regtest/test marking
// rate_src="manual" — CONCEPT §25: regtest junk stays recognizable as test data).
// Without a rate (both empty / feed down and no snapshot) ok=false →
// the relay books unrated or cannot convert value-defined prices.
package rates

import (
	"encoding/json"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/lightningmail/relay/internal/ledger"
)

type Feed struct {
	mu     sync.Mutex
	snap   ledger.RateStamp
	url    string
	manual float64
}

func NewFeed(rateURL string, manualEurPerBtc float64) *Feed {
	f := &Feed{url: rateURL, manual: manualEurPerBtc}
	if manualEurPerBtc > 0 {
		f.refresh()
	}
	return f
}

// Load once at start, then check hourly; re-fetch feed snapshots only
// after 24h of age (daily rate). Runs as a goroutine in relayd.
func (f *Feed) Start() {
	f.refresh()
	for range time.Tick(time.Hour) {
		f.mu.Lock()
		age := time.Now().Unix() - f.snap.Ts
		f.mu.Unlock()
		if f.manual > 0 || age >= 24*3600 {
			f.refresh()
		}
	}
}

// Current returns the snapshot; ok=false → unrated.
func (f *Feed) Current() (ledger.RateStamp, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.snap.MEurPerBtc <= 0 {
		return ledger.RateStamp{}, false
	}
	return f.snap, true
}

func (f *Feed) refresh() {
	if f.manual > 0 {
		f.mu.Lock()
		f.snap = ledger.RateStamp{MEurPerBtc: int64(math.Round(f.manual * 1000)), Ts: time.Now().Unix(), Src: "manual"}
		f.mu.Unlock()
		return
	}
	if f.url == "" {
		return
	}
	// Binance/BSi format: {"price":"90123.45000000"} — ignore the rest.
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(f.url)
	if err != nil {
		log.Printf("rates: feed %s: %v (alter Snapshot bleibt)", f.url, err)
		return
	}
	defer resp.Body.Close()
	var out struct {
		Price string `json:"price"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		log.Printf("rates: feed %s: parse: %v", f.url, err)
		return
	}
	pf, err := strconv.ParseFloat(out.Price, 64)
	if err != nil || pf <= 0 || pf > 1e9 {
		log.Printf("rates: feed %s: unplausibler Kurs %q", f.url, out.Price)
		return
	}
	src := "feed"
	if u, e := url.Parse(f.url); e == nil && u.Host != "" {
		src = u.Host
	}
	f.mu.Lock()
	f.snap = ledger.RateStamp{MEurPerBtc: int64(math.Round(pf * 1000)), Ts: time.Now().Unix(), Src: src}
	f.mu.Unlock()
	log.Printf("rates: %s EUR/BTC (%s)", out.Price, src)
}
