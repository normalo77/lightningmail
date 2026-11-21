package core

import (
	"strings"
	"testing"
)

// A2: the four sanitize traps — <style> tag, on* attribute, javascript:
// href, external http image — must never survive, while the allowed
// mail markup does.
func TestSanitizeTraps(t *testing.T) {
	in := `<div class="gelb" style="background-color:#ffe600;color:#201a10">
		<style>.gelb{background:yellow}</style>
		<h2 style="color:#c0392b">Hallo</h2>
		<ul><li>eins</li><li>zwei</li></ul>
		<a href="https://example.com/ok">guter Link</a>
		<a href="javascript:alert(1)">boeser Link</a>
		<button onclick="alert(2)">klick</button>
		<img src="http://tracker.example/pixel.png">
		<img src="lm-mail://blob/` + strings.Repeat("ab", 32) + `">
		<img src="data:image/png;base64,iVBORw0KGgo=">
		<script>alert(3)</script>
	</div>`
	out := SanitizeMailHTML(in)

	for _, trap := range []struct{ name, frag string }{
		{"style-Tag", "<style"},
		{"style-Inhalt", "background:yellow"},
		{"onclick", "onclick"},
		{"javascript-href", "javascript:"},
		{"script", "<script"},
		{"script-Inhalt", "alert(3)"},
		{"button", "<button"},
		{"external-http-img", "tracker.example"},
	} {
		if strings.Contains(strings.ToLower(out), strings.ToLower(trap.frag)) {
			t.Errorf("trap %q survived sanitize: %q in %q", trap.name, trap.frag, out)
		}
	}
	for _, keep := range []string{
		`<h2`, "Hallo", "<ul>", "<li>eins</li>",
		`href="https://example.com/ok"`, "guter Link",
		"lm-mail://blob/" + strings.Repeat("ab", 32),
		"data:image/png;base64,iVBORw0KGgo=",
	} {
		if !strings.Contains(out, keep) {
			t.Errorf("allowed markup %q was dropped: %q", keep, out)
		}
	}
	// allowed style property survives (bluemonday normalizes to "prop: value")
	if !strings.Contains(out, "background-color") || !strings.Contains(out, "#ffe600") {
		t.Errorf("allowed style was dropped: %q", out)
	}
}

func TestSanitizeStyleDenylist(t *testing.T) {
	for _, bad := range []string{
		`<p style="width:expression(alert(1))">x</p>`,
		`<p style="behavior:url(#x)">x</p>`,
		`<p style="background:url(javascript:alert(1))">x</p>`,
		`<p style="background-image:url(http://evil/x.png)">x</p>`,
	} {
		out := SanitizeMailHTML(bad)
		if strings.Contains(out, "expression") || strings.Contains(out, "behavior") ||
			strings.Contains(strings.ToLower(out), "url(") || strings.Contains(out, "javascript:") {
			t.Errorf("style denylist leak: %q -> %q", bad, out)
		}
	}
}

func TestBuildReaderHTML(t *testing.T) {
	sha := strings.Repeat("cd", 32)
	m := &Mail{
		Subject:     "Test <b>",
		Body:        `<p>Siehe Bild:</p><img src="cid:bild.png">`,
		SenderShort: "aabbccddeeff",
		ReceivedAt:  1760000000,
		Attachments: []Attachment{{SHA256: sha, Name: "bild.png", Size: 2097152, Chunked: true, Chunks: 2}},
	}
	out := BuildReaderHTML(m)
	if !strings.Contains(out, `src="lm-mail://blob/`+sha+`"`) {
		t.Errorf("cid not rewritten: %s", out)
	}
	if !strings.Contains(out, "Test &lt;b&gt;") {
		t.Error("subject not escaped")
	}
	if !strings.Contains(out, "Content-Security-Policy") {
		t.Error("CSP meta missing")
	}
	if !strings.Contains(out, `<style data-lmdesk="1">`) {
		t.Error("wrapper style marker missing (DOMCHECK counts style:not([data-lmdesk]))")
	}
	if !strings.Contains(out, "📦") {
		t.Error("chunked attachment chip missing")
	}
	if !strings.Contains(out, `lm-mail://blob/`+sha+`?thumb=1`) {
		t.Error("image attachment thumbnail (cache-hit probe) missing")
	}
	// plaintext path: escaped into <pre>, line breaks survive ("<3" is no tag)
	p := &Mail{Subject: "p", Body: "zeile1\n<3 & grüße", SenderShort: "aa", ReceivedAt: 1}
	po := BuildReaderHTML(p)
	if !strings.Contains(po, "<pre") || !strings.Contains(po, "&lt;3 &amp; grüße") || !strings.Contains(po, "\n") {
		t.Errorf("plaintext body wrong: %s", po)
	}
}
