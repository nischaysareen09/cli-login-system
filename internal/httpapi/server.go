// Package httpapi exposes a small JSON API and a self-contained web UI on
// top of the same auth/session logic used by the CLI. It is a bonus
// interface, not a replacement for the CLI — the terminal shell remains
// the primary, required deliverable; this runs alongside it.
package httpapi

import (
	"database/sql"
	"embed"
	"net/http"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/session"
)

//go:embed static/index.html
var staticFiles embed.FS

const sessionCookieName = "vault_session"

// Server holds the dependencies HTTP handlers need — the same DB
// connection and configs the CLI uses, so both interfaces see identical,
// consistent state.
type Server struct {
	conn       *sql.DB
	lockoutCfg auth.LockoutConfig
	sessionCfg session.Config
}

// NewHandler builds the full HTTP handler (routes + middleware) for the
// web UI and its JSON API.
func NewHandler(conn *sql.DB, lockoutCfg auth.LockoutConfig, sessionCfg session.Config) http.Handler {
	s := &Server{conn: conn, lockoutCfg: lockoutCfg, sessionCfg: sessionCfg}

	mux := http.NewServeMux()

	// The UI itself: a single self-contained HTML file (inline CSS/JS),
	// embedded into the binary — no external CDN, no separate build step.
	mux.HandleFunc("GET /{$}", s.handleIndex)

	// JSON API, mirroring the CLI's command set 1:1.
	mux.HandleFunc("POST /api/register", s.handleRegister)
	mux.HandleFunc("POST /api/login", s.handleLogin)
	mux.HandleFunc("POST /api/logout", s.handleLogout)
	mux.HandleFunc("GET /api/me", s.handleMe)
	mux.HandleFunc("POST /api/2fa/enable/start", s.handleEnable2FAStart)
	mux.HandleFunc("GET /api/2fa/qrcode.png", s.handleQRCode)
	mux.HandleFunc("POST /api/2fa/enable/confirm", s.handleEnable2FAConfirm)
	mux.HandleFunc("POST /api/2fa/disable", s.handleDisable2FA)

	return mux
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	b, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Write(b)
}
