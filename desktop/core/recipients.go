package core

import "strings"

// ParseRecipients splits a comma/semicolon-separated address field, trims
// whitespace and dedupes case-insensitively (first-seen order wins) —
// identical semantics to client/src/recipients.ts.
func ParseRecipients(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ';' })
	out := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, f := range fields {
		a := strings.TrimSpace(f)
		if a == "" {
			continue
		}
		k := strings.ToLower(a)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
}

// UniqueRecipients merges To + CC into one fan-out list: To first, then the
// CC addresses not already present.
func UniqueRecipients(to, cc string) []string {
	toList := ParseRecipients(to)
	seen := make(map[string]bool, len(toList))
	for _, a := range toList {
		seen[strings.ToLower(a)] = true
	}
	for _, a := range ParseRecipients(cc) {
		if !seen[strings.ToLower(a)] {
			toList = append(toList, a)
		}
	}
	return toList
}

// localPart matches bare account names ("alice") against full addresses
// ("alice@relay") — clients know themselves under both forms.
func sameAddr(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	al, bl := strings.ToLower(a), strings.ToLower(b)
	return al == bl || strings.Split(al, "@")[0] == strings.Split(bl, "@")[0]
}

// ReplyAll collects the original sender plus all To/Cc addresses, drops self
// and puts the sender into To with everyone else in CC (no duplicates).
func ReplyAll(sender, toHdr, ccHdr, self string) (to, cc []string) {
	sender = strings.TrimSpace(sender)
	candidates := UniqueRecipients(
		strings.Join(append([]string{sender}, ParseRecipients(toHdr)...), ","), ccHdr)
	rest := make([]string, 0, len(candidates))
	for _, a := range candidates {
		if !sameAddr(a, self) {
			rest = append(rest, a)
		}
	}
	switch {
	case sender != "" && !sameAddr(sender, self):
		to = []string{sender}
	case len(rest) > 0:
		to = []string{rest[0]}
	}
	for _, a := range rest {
		if len(to) == 0 || !sameAddr(a, to[0]) {
			cc = append(cc, a)
		}
	}
	return to, cc
}

// HeaderCI looks a payload header up case-insensitively: canonical keys are
// "To"/"Cc"/"From", but bridge mail from before canonicalization (and old
// letters) may carry lowercase ones.
func HeaderCI(h map[string]string, key string) string {
	if v, ok := h[key]; ok {
		return v
	}
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}
