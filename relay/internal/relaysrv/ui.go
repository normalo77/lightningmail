// registerUI (Etappe O, Selbstbau): mit gesetztem ui_dir serviert relayd die
// gebaute PWA unter /app/ — Selbstbauer oeffnen https://<domain>/app/ und
// haben API und UI same-origin auf dem eigenen Relay (kein CORS, kein
// Zweit-Webserver). Leer = UI wird nicht serviert (Hosting-Fall, dort
// uebernimmt das Site-Frontend).
package relaysrv

import (
	"log"
	"net/http"
)

func (s *Server) registerUI(mux *http.ServeMux) {
	ui := s.cfg.UIDir
	if ui == "" {
		return
	}
	files := http.FileServer(http.Dir(ui))
	mux.Handle("/app/", http.StripPrefix("/app/", files))
	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/app/", http.StatusMovedPermanently)
	})
	log.Printf("relaysrv: Web-UI aus %s unter /app/", ui)
}
