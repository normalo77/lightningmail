// gui.go: Nativer Linux-Client — die PWA steckt als Embed im Binary,
// ein lokaler Server proxyt /relay-a und /relay-b (relative Pfade ohne CORS),
// dazu nativer Vault (~/.local/share/lightningmail/vault.json) und notify-send.
package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

//go:embed all:ui
var uiFS embed.FS

func vaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".local", "share", "lightningmail", "vault.json")
}

func cmdGUI(args []string) {
	port := 17840
	for i := 0; i < len(args); i++ {
		if args[i] == "--port" && i+1 < len(args) {
			if p, err := strconv.Atoi(args[i+1]); err == nil && p > 0 {
				port = p
			}
			i++
		}
	}

	mux := http.NewServeMux()
	tb := make([]byte, 32)
	_, _ = rand.Read(tb)
	nativeToken := hex.EncodeToString(tb)
	const cspHeader = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https:; img-src 'self' data: blob:; font-src 'self' data:; frame-ancestors 'none'"

	// Relay-Reverse-Proxy: Ziel = $BMAIL_RELAY oder https://lightningmail.app,
	// Pfad bleibt erhalten (/relay-a/* -> Ziel/relay-a/*).
	relay := os.Getenv("BMAIL_RELAY")
	if relay == "" {
		relay = "https://lightningmail.app"
	}
	target, err := url.Parse(relay)
	if err != nil {
		fmt.Fprintf(os.Stderr, "BMAIL_RELAY ungültig: %v\n", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	// Host muss aufs Ziel zeigen (SingleHostReverseProxy behält sonst den
	// lokalen Host → Cloudflare 403); Go-Default-UA wird ebenfalls geblockt.
	baseDirector := proxy.Director
	proxy.Director = func(r *http.Request) {
		baseDirector(r)
		r.Host = target.Host
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 lightningmail-native/1.0")
	}
	mux.Handle("/relay-a/", proxy)
	mux.Handle("/relay-b/", proxy)

	// Nativer Vault: Schluessel-JSON auf der Platte, 0600 (CSRF-geschuetzt via X-LM-Native-Token).
	mux.HandleFunc("/__native/vault", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-LM-Native-Token") != nativeToken {
			http.Error(w, `{"error":"forbidden (missing native token)"}`, http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet:
			b, err := os.ReadFile(vaultPath())
			if err != nil {
				http.Error(w, `{"error":"no vault"}`, http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(b)
		case http.MethodPost:
			body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			if err != nil || len(body) == 0 {
				http.Error(w, `{"error":"empty body"}`, http.StatusBadRequest)
				return
			}
			if err := os.MkdirAll(filepath.Dir(vaultPath()), 0700); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			if err := os.WriteFile(vaultPath(), body, 0600); err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			fmt.Fprint(w, `{"ok":true}`)
		default:
			http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		}
	})

	// Desktop-Benachrichtigung (best effort — CSRF-geschuetzt + "--" gegen Flag-Injection).
	mux.HandleFunc("/__native/notify", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-LM-Native-Token") != nativeToken {
			http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
			return
		}
		var n struct {
			Title string `json:"title"`
			Text  string `json:"text"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&n)
		_ = exec.Command("notify-send", "--", n.Title, n.Text).Run()
		fmt.Fprint(w, `{"ok":true}`)
	})

	// Eingebettete PWA (100% code-pinned im Binary, mit CSP-Header).
	sub, err := fs.Sub(uiFS, "ui")
	if err != nil {
		fmt.Fprintf(os.Stderr, "embed ui: %v\n", err)
		os.Exit(1)
	}
	fileSrv := http.FileServer(http.FS(sub))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspHeader)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fileSrv.ServeHTTP(w, r)
	})

	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		// Port belegt → zufälliger freier Port
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			fmt.Fprintf(os.Stderr, "listen: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Port %d belegt, nutze %s\n", port, ln.Addr())
	}
	addr := "http://" + ln.Addr().String()
	fmt.Printf("LightningMail — nativer Linux-Client: %s  (Strg+C beendet)\n", addr)
	fmt.Printf("Relay-Proxy: /relay-a, /relay-b -> %s\n", relay)
	go openAppWindow(addr)
	if err := http.Serve(ln, mux); err != nil {
		fmt.Fprintf(os.Stderr, "serve: %v\n", err)
		os.Exit(1)
	}
}

// openAppWindow startet ein natives App-Fenster (Chrome/Chromium --app),
// sonst normalen Browser. Best effort: ohne Desktop läuft der Server trotzdem.
func openAppWindow(addr string) {
	candidates := [][]string{
		{"chromium", "--app=" + addr},
		{"google-chrome", "--app=" + addr},
		{"firefox", addr},
		{"xdg-open", addr},
	}
	for _, c := range candidates {
		p, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		cmd := exec.Command(p, c[1:]...)
		cmd.Stdout, cmd.Stderr = nil, nil
		if cmd.Start() == nil {
			fmt.Printf("App-Fenster: %s %v\n", c[0], c[1:])
			return
		}
	}
	fmt.Println("kein Browser gefunden — URL oben manuell öffnen")
}
