// Package rates: Tageskurs EUR/BTC fuer wertdefinierte Preise (§25 Steuer-Log,
// §26 Multi-Waehrung). Ein Abruf pro Tag (24h-Cache, stuendlich geprueft);
// manual_eur_per_btc aus der Config gewinnt immer (Regtest/Testmarkierung
// rate_src="manual" — CONCEPT §25: Regtest-Muell bleibt als Testdaten erkennbar).
// Ohne Kurs (beides leer / Feed down und kein Snapshot) ist ok=false →
// Relay bucht ungeratet bzw. kann wertdefinierte Preise nicht umrechnen.
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
	return &Feed{url: rateURL, manual: manualEurPerBtc}
}

// Start einmal laden, dann stuendlich pruefen; Feed-Snapshots erst ab 24h
// Alter neu ziehen (Tageskurs). Laeuft als Goroutine im relayd.
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

// Current liefert den Snapshot; ok=false → ungeratet.
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
	// Format Binance/BSi: {"price":"90123.45000000"} — Rest ignorieren.
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
