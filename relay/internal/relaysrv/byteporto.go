// Etappe 7 — byte postage (§22): storage price per byte at blob upload.
// Value-defined in milli-EUR per MiB (§26) → msat via daily rate (§25 feed),
// rounded up (nobody stores for free). Booked as kind='fee' with
// ref='blob:<sha256>' — operator income, no schema migration needed.
// Dedup: a fresh blob_refs row = this account's first upload → only then
// is it charged; uploading the same blob again costs nothing (money identity).
package relaysrv

// BytePortoMsat: msat price for sizeBytes at bp milli-EUR/MiB and rate
// rateMEurPerBtc (EUR/BTC × 1000). Rounded in two steps, int64-safe:
// cost_meur_x1000 = ceil(size*bp*1000/MiB); msat = ceil(x1000*1e8/rate).
func BytePortoMsat(sizeBytes, bp, rateMEurPerBtc int64) int64 {
	if bp <= 0 || rateMEurPerBtc <= 0 || sizeBytes <= 0 {
		return 0
	}
	const MiB = int64(1024 * 1024)
	x1000 := (sizeBytes*bp*1000 + MiB - 1) / MiB
	return (x1000*100000000 + rateMEurPerBtc - 1) / rateMEurPerBtc
}
