// Etappe 7 — Byte-Porto (§22): Storage-Preis pro Byte beim Blob-Upload.
// Wertdefiniert in Milli-EUR pro MiB (§26) → msat per Tageskurs (§25-Feed),
// aufgerundet (niemand speichert gratis). Buchung als kind='fee' mit
// ref='blob:<sha256>' — Betreiber-Einnahme, kein Schema-Migration nötig.
// Dedup: frische blob_refs-Zeile = erster Upload dieses Kontos → nur dann
// wird kassiert; derselbe Blob nochmal kostet nichts (Geld-Identität).
package relaysrv

// BytePortoMsat: msat-Preis fuer sizeBytes bei bp Milli-EUR/MiB und Kurs
// rateMEurPerBtc (EUR/BTC × 1000). Zweistufig gerundet, int64-sicher:
// cost_meur_x1000 = ceil(size*bp*1000/MiB); msat = ceil(x1000*1e8/rate).
func BytePortoMsat(sizeBytes, bp, rateMEurPerBtc int64) int64 {
	if bp <= 0 || rateMEurPerBtc <= 0 || sizeBytes <= 0 {
		return 0
	}
	const MiB = int64(1024 * 1024)
	x1000 := (sizeBytes*bp*1000 + MiB - 1) / MiB
	return (x1000*100000000 + rateMEurPerBtc - 1) / rateMEurPerBtc
}
