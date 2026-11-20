// Etappe 7: Byte-Porto-Mathematik (§22) — wertdefiniert, aufgerundet, int64-sicher.
package relaysrv

import "testing"

func TestBytePortoMsat(t *testing.T) {
	// Referenz: 1 ct = 0,01 EUR; Kurs 50.000 EUR/BTC = 5e7 mEUR/BTC
	// → 1 ct kostet 0,01/50000 BTC = 2e-7 BTC = 20 sat = 20.000 msat.
	cases := []struct {
		size, bp, rate, want int64
		what                 string
	}{
		{1024 * 1024, 10, 50_000_000, 20_000, "1 MiB zu 1 ct/MiB = 20 sats"},
		{2621440, 10, 50_000_000, 50_000, "2,5 MiB = 2,5 ct = 50 sats"},
		{10 * 1024 * 1024, 10, 50_000_000, 200_000, "10 MiB = 10 ct = 200 sats"},
		{1, 10, 50_000_000, 2, "1 Byte rundet auf (x1000=1 → 2 msat)"},
		{1024, 0, 50_000_000, 0, "bp=0 → Byte-Porto aus"},
		{1024, 10, 0, 0, "kein Kurs → 0 (Handler blockiert vorher mit 503)"},
		{0, 10, 50_000_000, 0, "0 Bytes → 0"},
	}
	for _, c := range cases {
		if got := BytePortoMsat(c.size, c.bp, c.rate); got != c.want {
			t.Errorf("%s: BytePortoMsat(%d,%d,%d) = %d, want %d", c.what, c.size, c.bp, c.rate, got, c.want)
		}
	}
	// Overflow-Wache: 100 MiB zu 100 ct/MiB (= 10 EUR) muss int64 bleiben
	if got := BytePortoMsat(100*1024*1024, 100, 50_000_000); got != 20_000_000 { // 10 EUR = 2e4 sats
		t.Errorf("100MiB@10ct: %d, want 20000000 msat", got)
	}
}
