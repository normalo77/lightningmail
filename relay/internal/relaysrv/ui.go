// registerUI (Etappe O, self-hosting): with ui_dir set, relayd serves the
// built PWA under /app/ — self-hosters open https://<domain>/app/ and
// get API and UI same-origin on their own relay (no CORS, no
// second web server). Empty = UI not served (hosting case, there
// the site frontend takes over).
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
