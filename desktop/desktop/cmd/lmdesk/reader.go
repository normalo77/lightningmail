package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bnema/puregotk-webkit/soup"
	"github.com/bnema/puregotk-webkit/webkit"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gtk"
)

// WebKit reader pane. Rotliste contract: ephemeral session, async scheme
// handler with req.Ref + IdleAdd, decide-policy WITH type check + allowlist,
// streams/gbytes/gerror unref'd, JS off.

// schemeCB must be a package-level value — C keeps the trampoline forever.
var schemeCB = webkit.URISchemeRequestCallback(handleLMScheme)

var schemeHits atomic.Int32

// domCheck is the A2 evidence probe (only with LMDESK_DOMCHECK=1, which
// re-enables JS for exactly this run — production keeps JS hard-off).
const domCheckJS = `JSON.stringify({` +
	`mailStyles: document.querySelectorAll('style:not([data-lmdesk])').length,` +
	`scripts: document.querySelectorAll('script').length,` +
	`onclickAttrs: document.querySelectorAll('[onclick]').length,` +
	`jsHrefs: document.querySelectorAll('a[href^="javascript:"]').length,` +
	`imgSrcs: [].map.call(document.images, function(i){return i.src.slice(0,60);}),` +
	`probeBg: (function(){var d=[].filter.call(document.querySelectorAll('div,p'),` +
	`function(e){return e.textContent.indexOf('NICHT gelb')>=0;})[0];` +
	`return d?getComputedStyle(d).backgroundColor:null;})(),` +
	`h2Color: (function(){var h=document.querySelector('h2');` +
	`return h?getComputedStyle(h).color:null;})()})`

// readerXML instantiates the WebView with an ephemeral NetworkSession via
// GtkBuilder: WebKitGTK 2.54 removed webkit_web_view_new_with_network_session
// (and the NetworkSession scheme registration), the session is now a
// construct-only property — the builder sets it without any dlsym/unsafe.
const readerXML = `<?xml version="1.0" encoding="UTF-8"?>
<interface>
  <object class="WebKitNetworkSession" id="session">
    <property name="is-ephemeral">True</property>
  </object>
  <object class="WebKitWebView" id="view">
    <property name="network-session">session</property>
    <property name="default-content-security-policy" translatable="no">default-src 'none'; img-src lm-mail: data:; style-src 'unsafe-inline'; font-src 'none'; connect-src 'none'; media-src 'none'; frame-src 'none'; form-action 'none';</property>
  </object>
</interface>`

// newReader builds the WebView on an ephemeral NetworkSession (Rotliste §3:
// no default context, no disk artifacts) and registers lm-mail:// on the
// view's own WebContext.
func (a *App) newReader() *webkit.WebView {
	// register the GTypes so GtkBuilder resolves the class names
	_ = webkit.NetworkSessionGLibType()
	_ = webkit.WebViewGLibType()
	builder := gtk.NewBuilderFromString(readerXML, len(readerXML))
	a.readerBuilder = builder // keep alive: it holds the WebView reference
	obj := builder.GetObject("view")
	if obj == nil {
		log.Fatalf("reader: builder returned no WebKitWebView")
	}
	view := webkit.WebViewNewFromInternalPtr(obj.GoPointer())

	session := view.GetNetworkSession()
	if session == nil || !session.GetPropertyIsEphemeral() {
		log.Fatalf("reader: network session not ephemeral")
	}
	session.SetItpEnabled(false)
	log.Printf("reader: ephemeral NetworkSession aktiv (keine Disk-Artefakte)")

	ctx := view.GetContext()
	ctx.RegisterUriScheme("lm-mail", &schemeCB, 0, nil)
	log.Printf("scheme lm-mail registriert (WebView-eigener WebContext)")

	// settings hardening (Rotliste §2) — GetSettings is transfer-none
	domCheck := os.Getenv("LMDESK_DOMCHECK") == "1"
	if s := view.GetSettings(); s != nil {
		s.SetEnableJavascript(domCheck) // evidence-run only; production: false
		s.SetEnableJavascriptMarkup(false)
		s.SetAllowFileAccessFromFileUrls(false)
		s.SetAllowUniversalAccessFromFileUrls(false)
		s.SetAllowTopNavigationToDataUrls(false)
		s.SetEnableBackForwardNavigationGestures(false)
		s.SetEnableDeveloperExtras(false)
		s.SetEnablePageCache(false)
		s.SetEnableHtml5LocalStorage(false)
		s.SetEnableHtml5Database(false)
	}
	// engine-level third defense behind sanitizer + CSP meta (construct-only
	// property, set via the builder XML above)

	decide := func(_ webkit.WebView, decPtr uintptr, t webkit.PolicyDecisionType) bool {
		// Rotliste #3: type switch FIRST — never blind-cast the decision ptr.
		switch t {
		case webkit.PolicyDecisionTypeNavigationActionValue,
			webkit.PolicyDecisionTypeNewWindowActionValue:
			d := webkit.NavigationPolicyDecisionNewFromInternalPtr(decPtr)
			na := d.GetNavigationAction()
			if na == nil {
				d.Ignore()
				return true
			}
			uri := ""
			if r := na.GetRequest(); r != nil {
				uri = r.GetUri()
			}
			switch {
			case uri == "about:blank" || strings.HasPrefix(uri, "lm-mail://"):
				// initial LoadHtml frame / own scheme — Spike-Erkenntnis 4
				return false
			case (strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "mailto:")) && na.IsUserGesture():
				// external link click -> system handler (xdg-open equivalent)
				d.Ignore()
				log.Printf("decide-policy: extern %s -> AppInfoLaunchDefault", uri)
				if _, err := gio.AppInfoLaunchDefaultForUri(uri, nil); err != nil {
					log.Printf("launch %s: %v", uri, err)
				}
				return true
			default:
				d.Ignore()
				log.Printf("decide-policy: blockiert type=%d uri=%s", int(t), uri)
				return true
			}
		case webkit.PolicyDecisionTypeResponseValue:
			// subresource responses: CSP + sanitizer already allowlisted
			return false
		}
		return false
	}
	view.ConnectDecidePolicy(&decide)

	load := func(_ webkit.WebView, ev webkit.LoadEvent) {
		log.Printf("load-changed event=%d", int(ev))
		if ev == webkit.LoadFinishedValue && domCheck && !a.domCheckDone.Swap(true) {
			a.runDOMCheck()
		}
	}
	view.ConnectLoadChanged(&load)
	return view
}

func (a *App) runDOMCheck() {
	cb := gio.AsyncReadyCallback(func(_, resPtr, _ uintptr) {
		res := &gio.AsyncResultBase{Ptr: resPtr}
		v, err := a.reader.EvaluateJavascriptFinish(res)
		if err != nil {
			log.Printf("DOMCHECK evaluate: %v", err)
			return
		}
		log.Printf("DOMCHECK %s", v.ToString())
	})
	a.reader.EvaluateJavascript(domCheckJS, len(domCheckJS), nil, nil, nil, &cb, 0)
}

// handleLMScheme serves lm-mail://blob/<sha256hex> from the RAM cache; on a
// miss it refs the request and fetches in a goroutine (Rotliste #7: never
// block the GTK main thread), answering via IdleAdd.
func handleLMScheme(reqPtr, _ uintptr) {
	req := webkit.URISchemeRequestNewFromInternalPtr(reqPtr)
	uri := req.GetUri()
	n := schemeHits.Add(1)
	log.Printf("scheme-handler #%d: %s", n, uri)

	sha, ok := parseLMBlobURI(uri)
	if !ok || !ui.shaAllowed(sha) {
		log.Printf("scheme-handler: abgelehnt (parse=%v, cross-mail-Schutz)", ok)
		finishErr(req, 404, "lm-mail: not found")
		return
	}
	if data, ct, hit := ui.cacheGet(sha); hit {
		log.Printf("scheme-cache-hit %s… (%d bytes)", sha[:12], len(data))
		finishData(req, data, ct)
		return
	}
	req.Ref()
	go func() {
		data, ct, hit, err := ui.fetchShared(sha)
		f := glib.SourceOnceFunc(func(_ uintptr) {
			defer req.Unref()
			if err != nil {
				log.Printf("scheme-fetch %s…: %v", sha[:12], err)
				finishErr(req, 404, "lm-mail: fetch failed")
				return
			}
			if hit {
				log.Printf("scheme-cache-hit %s… (%d bytes, single-flight)", sha[:12], len(data))
			} else {
				log.Printf("scheme-fetch ok %s… (%d bytes, %s)", sha[:12], len(data), ct)
			}
			finishData(req, data, ct)
		})
		glib.IdleAddOnce(&f, 0)
	}()
}

// flight is one in-flight blob download; parallel requests for the same sha
// wait for it instead of pulling the (multi-MiB) blob twice.
type flight struct {
	done chan struct{}
	data []byte
	ct   string
	err  error
}

// fetchShared: cache first, then single-flight network fetch. hit=true means
// the bytes came from the RAM cache (or a finished leader fetch).
func (a *App) fetchShared(sha string) ([]byte, string, bool, error) {
	if data, ct, ok := a.cacheGet(sha); ok {
		return data, ct, true, nil
	}
	a.fmu.Lock()
	if a.flights == nil {
		a.flights = map[string]*flight{}
	}
	f, found := a.flights[sha]
	if !found {
		f = &flight{done: make(chan struct{})}
		a.flights[sha] = f
	}
	a.fmu.Unlock()
	if found {
		<-f.done // wait for the leader
		if f.err != nil {
			return nil, "", false, f.err
		}
		return f.data, f.ct, true, nil
	}
	data, ct, err := a.fetchBlob(sha)
	f.data, f.ct, f.err = data, ct, err
	if err == nil {
		a.cachePut(sha, data, ct)
	}
	close(f.done)
	a.fmu.Lock()
	delete(a.flights, sha)
	a.fmu.Unlock()
	return data, ct, false, err
}

// parseLMBlobURI strictly validates lm-mail://blob/<64 lowercase hex>.
func parseLMBlobURI(uri string) (string, bool) {
	const p = "lm-mail://blob/"
	if !strings.HasPrefix(uri, p) {
		return "", false
	}
	sha := uri[len(p):]
	if i := strings.IndexAny(sha, "?#"); i >= 0 {
		sha = sha[:i]
	}
	if len(sha) != 64 {
		return "", false
	}
	if _, err := hex.DecodeString(sha); err != nil {
		return "", false
	}
	return sha, true
}

func (a *App) shaAllowed(sha string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.currentShas[sha]
	return ok && a.currentMsgID != ""
}

func (a *App) cacheGet(sha string) ([]byte, string, bool) {
	a.mu.Lock()
	ct := a.currentShas[sha]
	a.mu.Unlock()
	data, ok := a.cache.Get(sha)
	return data, ct, ok
}

func (a *App) cachePut(sha string, data []byte, _ string) {
	a.cache.Put(sha, data)
}

// fetchBlob downloads a blob, walking the chunk manifest when the attachment
// is chunked (Etappe-7 convention, chunks.ts reassemble).
func (a *App) fetchBlob(sha string) ([]byte, string, error) {
	a.mu.Lock()
	mail := a.byID[a.currentMsgID]
	ct := a.currentShas[sha]
	a.mu.Unlock()
	if mail == nil {
		return nil, "", fmt.Errorf("no open mail")
	}
	chunked := false
	for _, at := range mail.Attachments {
		if at.SHA256 == sha {
			chunked = at.Chunked
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if !chunked {
		data, err := a.api.Blob(ctx, sha)
		if err != nil {
			return nil, "", err
		}
		return data, ct, nil
	}
	// manifest walk: {v:1,size,chunks:[hex…]}
	manRaw, err := a.api.Blob(ctx, sha)
	if err != nil {
		return nil, "", err
	}
	var man struct {
		V      int      `json:"v"`
		Size   int64    `json:"size"`
		Chunks []string `json:"chunks"`
	}
	if err := json.Unmarshal(manRaw, &man); err != nil || man.V != 1 {
		return nil, "", fmt.Errorf("bad manifest: %v", err)
	}
	out := make([]byte, 0, man.Size)
	for _, csha := range man.Chunks {
		c, err := a.api.Blob(ctx, csha)
		if err != nil {
			return nil, "", fmt.Errorf("chunk %s…: %w", csha[:12], err)
		}
		out = append(out, c...)
	}
	if int64(len(out)) != man.Size {
		return nil, "", fmt.Errorf("reassemble: %d von %d Bytes", len(out), man.Size)
	}
	log.Printf("reassemble ok: %d Scheiben, %d Bytes", len(man.Chunks), len(out))
	return out, ct, nil
}

func finishData(req *webkit.URISchemeRequest, data []byte, ct string) {
	if ct == "" {
		ct = "application/octet-stream"
	}
	gb := glib.NewBytes(data, uint(len(data))) // copies into the GLib allocator
	stream := gio.NewMemoryInputStreamFromBytes(gb)
	headers := soup.NewMessageHeaders(soup.MessageHeadersResponseValue)
	// decrypted attachment bytes must not linger in WebKit's own caches —
	// the zeroed RAM-LRU is the only copy (Rotliste §3)
	headers.Append("Cache-Control", "no-store")
	resp := webkit.NewURISchemeResponse(&stream.InputStream, int64(len(data)))
	resp.SetContentType(ct)
	resp.SetHttpHeaders(headers)
	req.FinishWithResponse(resp)
	resp.Unref()
	stream.Unref()
	gb.Unref()
}

func finishErr(req *webkit.URISchemeRequest, code int, msg string) {
	q := "lm-mail"
	e := glib.NewErrorLiteral(glib.QuarkFromString(&q), code, msg)
	req.FinishError(e)
	e.Free()
}
