// M0-Spike: natives GTK4/Adwaita-Fenster mit WebKitGTK-6.0-Reader.
// Beweis: Screenshot unter Xvfb + sauberer stderr-Log.
package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"
	"strings"
	"sync/atomic"

	"github.com/bnema/puregotk-webkit/webkit"
	"github.com/bnema/puregotk/v4/adw"
	"github.com/bnema/puregotk/v4/gio"
	"github.com/bnema/puregotk/v4/glib"
	"github.com/bnema/puregotk/v4/gtk"
)

//go:embed testmail.html
var testmailHTML string

// PNGs werden in main() generiert und bleiben bis Prozessende referenziert.
// shortcut: statische RAM-Buffer; bei dynamischen Inhalten auf g_bytes umstellen (M1).
var (
	imgInline []byte
	imgScheme []byte
)

var schemeHits atomic.Int32

// schemeCB muss global leben — C hält den Callback über die Registrierung.
var schemeCB = webkit.URISchemeRequestCallback(handleLMScheme)

type mail struct{ subj, abs, vorschau string }

var mails = []mail{
	{"Wichtige Update-Informationen", "Anna &lt;anna@lightningmail.app&gt;", "Hallo! Anbei die neuen Details zu deinem Postfach..."},
	{"Zahlungsbestaetigung #4711", "Rechnungen &lt;buchhaltung@example.org&gt;", "Vielen Dank fuer deine Zahlung. Hier die Belege..."},
	{"Relay Alpha Stand", "Bernhard &lt;dev@lightningmail.app&gt;", "Kurzer Status: WebKit-Reader laedt lm-mail://..."},
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("lmspike ")
	imgInline = genPNG(0)
	imgScheme = genPNG(1)
	log.Printf("main: start")

	appID := "app.lightningmail.spike"
	app := adw.NewApplication(&appID, gio.GApplicationDefaultFlagsValue)
	defer app.Unref()

	actcb := func(_ gio.Application) { log.Printf("main: activate-cb"); activate(app) }
	app.ConnectActivate(&actcb)
	if code := app.Run(len(os.Args), os.Args); code > 0 {
		os.Exit(code)
	}
}

func activate(app *adw.Application) {
	ctx := webkit.WebContextGetDefault()
	ctx.RegisterUriScheme("lm-mail", &schemeCB, 0, nil)
	log.Printf("scheme lm-mail registriert (WebContext default)")

	win := adw.NewApplicationWindow(&app.Application)
	defer win.Unref()
	title := "lightningmail"
	win.SetTitle(&title)
	win.SetDefaultSize(1280, 800)

	toolbar := adw.NewToolbarView()
	hdr := adw.NewHeaderBar()
	wt := adw.NewWindowTitle("lightningmail", "M0-Spike")
	hdr.SetTitleWidget(&wt.Widget)
	toolbar.AddTopBar(&hdr.Widget)

	paned := gtk.NewPaned(gtk.OrientationHorizontalValue)
	list := gtk.NewListBox()
	list.SetSelectionMode(gtk.SelectionSingleValue)
	for _, m := range mails {
		list.Append(&rowWidget(m).Widget)
	}
	scroller := gtk.NewScrolledWindow()
	scroller.SetChild(&list.Widget)
	paned.SetStartChild(&scroller.Widget)

	view := webkit.NewWebView()
	view.SetVexpand(true)
	view.SetHexpand(true)
	paned.SetEndChild(&view.Widget)
	paned.SetPosition(300)

	selcb := func(_ gtk.ListBox, rowPtr uintptr) {
		row := gtk.ListBoxRowNewFromInternalPtr(rowPtr)
		i := row.GetIndex()
		log.Printf("row-selected index=%d subj=%q", i, mails[i].subj)
		loadMail(view, i)
	}
	list.ConnectRowSelected(&selcb)

	// A4: externe Links abfangen (Callback-Beweis), initiale about:blank/lm-mail-Navigation durchlassen.
	decide := func(_ webkit.WebView, decPtr uintptr, t webkit.PolicyDecisionType) bool {
		uri := "?"
		if d := webkit.NavigationPolicyDecisionNewFromInternalPtr(decPtr); d != nil {
			if na := d.GetNavigationAction(); na != nil {
				if r := na.GetRequest(); r != nil {
					uri = r.GetUri()
				}
			}
			if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") || strings.HasPrefix(uri, "mailto:") {
				log.Printf("A4 decide-policy feuert: type=%d uri=%s (xdg-open in M1)", t, uri)
				d.Ignore()
				return true
			}
		}
		return false
	}
	view.ConnectDecidePolicy(&decide)

	a4probed := false
	loadcb := func(_ webkit.WebView, ev webkit.LoadEvent) {
		log.Printf("load-changed event=%d", int(ev))
		if ev == webkit.LoadFinishedValue && !a4probed {
			a4probed = true
			// A4-Nachweis: simulierte externe Navigation nach Abschluss des Mail-Loads —
			// muss den decide-policy-Callback erreichen und dort abgewiesen werden.
			view.LoadUri("https://lightningmail.example/simulierter-linkklick")
		}
	}
	view.ConnectLoadChanged(&loadcb)

	if s := view.GetSettings(); s != nil {
		s.SetPropertyEnableJavascript(false)
	}

	toolbar.SetContent(&paned.Widget)
	win.SetContent(&toolbar.Widget)
	win.Present()

	list.SelectRow(list.GetRowAtIndex(0))
	log.Printf("UI steht, Mail 0 geladen")
}

func rowWidget(m mail) *gtk.Box {
	box := gtk.NewBox(gtk.OrientationVerticalValue, 2)
	box.SetMarginStart(12)
	box.SetMarginEnd(12)
	box.SetMarginTop(8)
	box.SetMarginBottom(8)
	empty := ""
	subj := gtk.NewLabel(&empty)
	subj.SetMarkup("<b>" + m.subj + "</b>")
	subj.SetXalign(0)
	abs := gtk.NewLabel(&empty)
	abs.SetMarkup(`<span size="small" foreground="#555555">` + m.abs + `</span>`)
	abs.SetXalign(0)
	vor := gtk.NewLabel(&empty)
	vor.SetMarkup(`<span size="small" foreground="#888888">` + m.vorschau + `</span>`)
	vor.SetXalign(0)
	vor.SetWrap(true)
	box.Append(&subj.Widget)
	box.Append(&abs.Widget)
	box.Append(&vor.Widget)
	return box
}

func loadMail(view *webkit.WebView, i int) {
	dataURI := "data:image/png;base64," + base64.StdEncoding.EncodeToString(imgInline)
	html := strings.Replace(testmailHTML, "{{IMG_DATAURI}}", dataURI, 1)
	html = strings.Replace(html, "<h2>M0-Testmail</h2>", fmt.Sprintf("<h2>%s</h2>", mails[i].subj), 1)
	view.LoadHtml(html, nil)
	log.Printf("LoadHtml Mail %d (%d bytes)", i, len(html))
}

// C-Signatur: void (*)(WebKitURISchemeRequest *request, gpointer user_data) — Arg1 ist der Request.
func handleLMScheme(reqPtr uintptr, _ uintptr) {
	req := webkit.URISchemeRequestNewFromInternalPtr(reqPtr)
	uri := req.GetUri()
	log.Printf("scheme-handler aufruf #%d: %s", schemeHits.Add(1), uri)
	ct := "image/png"
	if strings.HasSuffix(uri, "/demo1") {
		stream := gio.NewMemoryInputStreamFromData(imgScheme, len(imgScheme), nil)
		req.Finish(&stream.InputStream, int64(len(imgScheme)), &ct)
	} else {
		q := "lm-mail"
		req.FinishError(glib.NewErrorLiteral(glib.QuarkFromString(&q), 404, "lm-mail: object not found"))
	}
}

func genPNG(mode int) []byte {
	const n = 40
	img := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		for x := 0; x < n; x++ {
			var c color.RGBA
			if mode == 0 {
				c = color.RGBA{240, 240, 240, 255}
				if (x/10+y/10)%2 == 0 {
					c = color.RGBA{30, 132, 73, 255}
				}
				if y >= 18 && y <= 21 {
					c = color.RGBA{192, 57, 43, 255}
				}
			} else {
				dx, dy := float64(x)-19.5, float64(y)-19.5
				if dx*dx+dy*dy < 300 {
					c = color.RGBA{36, 113, 163, 255}
				} else {
					c = color.RGBA{247, 220, 111, 255}
				}
			}
			img.Set(x, y, c)
		}
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		log.Fatalf("png: %v", err)
	}
	return b.Bytes()
}
