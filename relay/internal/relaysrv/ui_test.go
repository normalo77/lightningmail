package relaysrv

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// Etappe O (Selbstbau): ui_dir setzt relayd die PWA unter /app/ — same-origin.
func TestUIStaticServe(t *testing.T) {
	srv, _ := newOIDCTestServer(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "index.html"), []byte("<h1>bmail-ui</h1>"), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.UIDir = dir
	ts := httptest.NewServer(srv.routes())
	defer ts.Close()

	res, err := ts.Client().Get(ts.URL + "/app/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || string(body) != "<h1>bmail-ui</h1>" {
		t.Fatalf("GET /app/: %d %q", res.StatusCode, body)
	}

	// /app ohne Slash: Redirect auf /app/ (Client nicht automatisch folgen lassen)
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	res, err = noFollow.Get(ts.URL + "/app")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMovedPermanently || res.Header.Get("Location") != "/app/" {
		t.Fatalf("GET /app: %d Location=%q", res.StatusCode, res.Header.Get("Location"))
	}

	// Ohne ui_dir bleibt /app/ dicht (Hosting-Fall: UI liegt am Site-Frontend).
	srv.cfg.UIDir = ""
	ts2 := httptest.NewServer(srv.routes())
	defer ts2.Close()
	res, err = ts2.Client().Get(ts2.URL + "/app/")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("ui_dir leer: GET /app/ = %d, erwartet 404", res.StatusCode)
	}
}
