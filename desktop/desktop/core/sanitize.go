package core

import (
	"fmt"
	"html"
	"regexp"
	"strings"
	"time"

	"github.com/microcosm-cc/bluemonday"
)

// HTML sanitizing for the reader pane (Rotliste §2: allowlist-only).
// Everything not explicitly allowed (script, style, on*-attributes,
// javascript: URLs, iframes, forms, …) is dropped by bluemonday.

var (
	reHref = regexp.MustCompile(`^(?i)(https?:|mailto:)`)
	// img src: only our RAM-scheme and inline data-images — no remote pixels.
	reImgSrc = regexp.MustCompile(`^(?i)(lm-mail://blob/[0-9a-f]{64}|data:image/(png|jpe?g|gif|webp);base64,)`)
	// legacy presentational attributes (font/table markup common in mails)
	reLegacyAttr = regexp.MustCompile(`^(?i)[a-z0-9 #%.,()/+-]{0,32}$`)
	// heuristic: body is HTML when it contains at least one tag
	reLooksLikeHTML = regexp.MustCompile(`<[a-zA-Z/!][^>]*>`)
	// Go regexp has no backreferences -> one pattern per quote style
	reCIDdq = regexp.MustCompile(`(?i)(src|href)(\s*=\s*")cid:([^"]+)(")`)
	reCIDsq = regexp.MustCompile(`(?i)(src|href)(\s*=\s*')cid:([^']+)(')`)
)

// styleValueOK is the denylist for CSS property values: url()/expression/
// behavior/-moz-binding/javascript are absolutely out (spec M1b sanitize.go).
func styleValueOK(v string) bool {
	lv := strings.ToLower(strings.ReplaceAll(v, " ", ""))
	for _, bad := range []string{
		"url(", "expression(", "expression\\", "behavior:", "-moz-binding",
		"javascript:", "vbscript:", "data:", "@import", "\\",
	} {
		if strings.Contains(lv, bad) {
			return false
		}
	}
	return true
}

// mailPolicy builds the allowlist policy (spec: p,br,hr,i,b,u,em,strong,
// a[href http/mailto], img[src lm-mail://|data:image], lists, blockquote,
// pre/code, span/div/font with style whitelist, h1-h6, table chain, center).
func mailPolicy() *bluemonday.Policy {
	p := bluemonday.NewPolicy()
	p.AllowElements(
		"p", "br", "hr", "i", "b", "u", "em", "strong", "small", "big", "sub", "sup",
		"blockquote", "pre", "code", "span", "div", "font", "center",
		"h1", "h2", "h3", "h4", "h5", "h6",
		"ul", "ol", "li", "dl", "dt", "dd",
		"table", "thead", "tbody", "tfoot", "tr", "td", "th", "caption", "colgroup", "col",
		"a", "img",
	)
	// Never render the CONTENT of these (default skip list plus explicit):
	p.SkipElementsContent("style", "script", "iframe", "frame", "object", "embed",
		"form", "link", "meta", "base", "title", "svg", "math", "applet")
	p.AllowAttrs("href").Matching(reHref).OnElements("a")
	p.AllowAttrs("alt", "title", "width", "height").OnElements("img")
	// src is bound globally to the RAM-scheme / data-image allowlist
	p.AllowAttrs("src").Matching(reImgSrc).Globally()
	// legacy mail markup attributes
	p.AllowAttrs("color", "size", "face").Matching(regexp.MustCompile(`^(?i)[a-z0-9 ,#'%.+-]{0,64}$`)).OnElements("font")
	p.AllowAttrs("align", "valign").Matching(regexp.MustCompile(`(?i)^(left|right|center|justify|top|middle|bottom)$`)).Globally()
	p.AllowAttrs("width", "height", "bgcolor", "border", "cellpadding", "cellspacing",
		"colspan", "rowspan", "span", "start", "nowrap").Matching(reLegacyAttr).Globally()
	// CSS: property whitelist + value denylist (expression/behavior/url() out)
	p.AllowStyles(
		"color", "background-color",
		"font-family", "font-size", "font-style", "font-weight",
		"text-align", "text-decoration", "text-indent", "line-height", "letter-spacing",
		"width", "height", "max-width",
		"margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
		"padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
		"border", "border-top", "border-right", "border-bottom", "border-left",
		"border-color", "border-width", "border-style", "border-radius",
		"display", "list-style-type", "vertical-align", "float", "white-space",
	).MatchingHandler(styleValueOK).Globally()
	return p
}

var policy = mailPolicy()

// SanitizeMailHTML runs the allowlist sanitizer over untrusted mail HTML.
func SanitizeMailHTML(in string) string {
	return policy.Sanitize(in)
}

// rewriteCID maps cid:<name> references onto lm-mail://blob/<sha> using the
// attachment list (name match, case-insensitive) — the desktop pendant of
// the PWA attachment convention.
func rewriteCID(body string, atts []Attachment) string {
	byName := map[string]string{}
	for _, a := range atts {
		byName[strings.ToLower(a.Name)] = a.SHA256
	}
	replace := func(re *regexp.Regexp, s string) string {
		return re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			if sha, ok := byName[strings.ToLower(sub[3])]; ok {
				return sub[1] + sub[2] + "lm-mail://blob/" + sha + sub[4]
			}
			return m // unknown cid: left as-is, renders as broken image placeholder
		})
	}
	body = replace(reCIDdq, body)
	return replace(reCIDsq, body)
}

// IsImageName reports whether the attachment name carries an image extension
// we are allowed to render inline (never html/svg — Rotliste §5).
func IsImageName(name string) bool {
	switch MimeByName(name) {
	case "image/png", "image/jpeg", "image/gif", "image/webp":
		return true
	}
	return false
}

func MimeByName(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		switch strings.ToLower(name[i+1:]) {
		case "png":
			return "image/png"
		case "jpg", "jpeg":
			return "image/jpeg"
		case "gif":
			return "image/gif"
		case "webp":
			return "image/webp"
		}
	}
	return "application/octet-stream"
}

// FormatDateDE renders a unix timestamp like the PWA (toLocaleString('de')).
func FormatDateDE(unix int64) string {
	return time.Unix(unix, 0).Format("02.01.2006 15:04:05")
}

// BuildReaderHTML assembles the full reader document, following the PWA
// renderDetail convention (subject / meta line / body / attachment chips):
// plaintext bodies go escaped into <pre>, HTML bodies through the sanitizer
// with cid: images rewritten to lm-mail://blob/<sha>. Hard CSP meta is the
// second defense layer behind the Go sanitizer (Rotliste §2).
// shortcut: attachment chips are display-only in M1 (no "save as" yet, M2).
func BuildReaderHTML(m *Mail) string {
	var bodyHTML string
	if reLooksLikeHTML.MatchString(m.Body) {
		bodyHTML = SanitizeMailHTML(rewriteCID(m.Body, m.Attachments))
	} else {
		bodyHTML = `<pre style="white-space:pre-wrap;font-family:inherit;margin:14px 0">` +
			html.EscapeString(m.Body) + `</pre>`
	}
	subject := html.EscapeString(m.Subject)
	if m.Signup {
		subject = "[🔑 Registrierung] " + subject
	}
	var atts strings.Builder
	for _, a := range m.Attachments {
		pkg := ""
		if a.Chunked {
			pkg = " 📦"
		}
		thumb := ""
		if IsImageName(a.Name) {
			// second reference (distinct URL -> distinct WebKit request) for
			// the same blob: served from the RAM cache (scheme-cache-hit)
			thumb = fmt.Sprintf(` <img class="thumb" src="lm-mail://blob/%s?thumb=1" alt="">`, a.SHA256)
		}
		atts.WriteString(fmt.Sprintf(`<span class="attach">↓ %s%s%s</span> `,
			html.EscapeString(a.Name), pkg, thumb))
	}
	meta := fmt.Sprintf("Von %s… · %s", html.EscapeString(m.SenderShort), FormatDateDE(m.ReceivedAt))
	if m.ReceivedSats > 0 {
		meta += fmt.Sprintf(" · <span class=\"recv\">⚡ %d Sats erhalten</span>", m.ReceivedSats)
	}
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; ` +
		`img-src lm-mail: data:; style-src 'unsafe-inline'; font-src 'none'; ` +
		`connect-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none';">` +
		`<style data-lmdesk="1">` +
		`body{font-family:sans-serif;font-size:14px;color:#201a10;margin:0;padding:14px 18px;background:#fffdf7}` +
		`.subj{font-size:17px;font-weight:700}` +
		`.meta{color:#8a8271;font-size:12px;margin-top:4px}` +
		`.recv{color:#1e8449;font-weight:700}` +
		`.attach{display:inline-block;margin:10px 6px 0 0;padding:4px 10px;border:1px solid #c9bfa8;` +
		`border-radius:4px;background:#f4eedd;font-size:12px}` +
		`.thumb{height:32px;vertical-align:middle;margin-left:6px;border:1px solid #c9bfa8}` +
		`hr{border:none;border-top:1px solid #d8cfb8;margin:12px 0}` +
		`blockquote{border-left:3px solid #c9bfa8;margin:8px 0;padding:2px 12px;color:#5a5344}` +
		`pre{white-space:pre-wrap}` +
		`img{max-width:100%}` +
		`</style></head><body>` +
		`<div class="subj">` + subject + `</div>` +
		`<div class="meta">` + meta + `</div><hr>` +
		bodyHTML +
		`<div>` + atts.String() + `</div>` +
		`</body></html>`
}
