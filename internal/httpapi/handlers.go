package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/db"
	"cli-login-system/internal/models"
	"cli-login-system/internal/session"
)

// ---- JSON helpers ----

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// decodeJSON is intentionally strict about Content-Type. Requiring
// application/json means a cross-site <form> submission (which can only
// send text/plain, application/x-www-form-urlencoded, or
// multipart/form-data without triggering a CORS preflight the server
// doesn't grant) can never reach these handlers with attacker-controlled
// cookies attached — a lightweight, demo-appropriate CSRF mitigation on
// top of the SameSite=Lax cookie. See README security notes for the
// production-grade caveats this doesn't cover (no CSRF token, no TLS).
func decodeJSON(r *http.Request, v interface{}) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		return false
	}
	return json.NewDecoder(r.Body).Decode(v) == nil
}

// ---- Session helpers ----

func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// currentUser resolves the logged-in user from the session cookie, or nil
// if there isn't a valid one.
func (s *Server) currentUser(r *http.Request) (*models.User, string) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, ""
	}
	user, err := session.Validate(s.conn, cookie.Value)
	if err != nil {
		return nil, ""
	}
	return user, cookie.Value
}

// ---- Handlers ----

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password string }
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, err := auth.Register(s.conn, req.Username, req.Password)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"username": user.Username})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct{ Username, Password, TotpCode string }
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	user, err := auth.Login(s.conn, s.lockoutCfg, req.Username, req.Password)
	if err != nil {
		var lockErr *auth.AccountLockedError
		if errors.As(err, &lockErr) {
			writeError(w, http.StatusForbidden, lockErr.Error())
			return
		}
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}

	// Mirrors the CLI's flow exactly: password is checked first; 2FA (if
	// enabled) is a separate check layered on top, and no session is
	// created until both pass.
	if user.TOTPEnabled {
		if req.TotpCode == "" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "totp_required"})
			return
		}
		if !auth.VerifyTOTPCode(user.TOTPSecret, req.TotpCode) {
			writeError(w, http.StatusUnauthorized, auth.ErrInvalidTOTPCode.Error())
			return
		}
	}

	sess, err := session.Create(s.conn, s.sessionCfg, user.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create session")
		return
	}

	s.setSessionCookie(w, sess.Token, sess.ExpiresAt)
	writeJSON(w, http.StatusOK, userDetailsJSON(user, sess.ExpiresAt))
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	_, token := s.currentUser(r)
	if token != "" {
		_ = session.End(s.conn, token)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	user, token := s.currentUser(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return
	}
	sess, err := getSessionExpiry(s, token)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load session")
		return
	}
	writeJSON(w, http.StatusOK, userDetailsJSON(user, sess))
}

func (s *Server) handleEnable2FAStart(w http.ResponseWriter, r *http.Request) {
	user, _ := s.currentUser(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return
	}

	key, err := auth.StartEnableTOTP(s.conn, user.ID, user.Username)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"secret":  key.Secret(),
		"qr_url":  "/api/2fa/qrcode.png",
		"otpauth": key.URL(),
	})
}

// handleQRCode renders the current user's pending/active TOTP secret as a
// PNG QR code, so the browser can display an actual scannable image
// rather than just the raw text (which is also shown as a fallback).
func (s *Server) handleQRCode(w http.ResponseWriter, r *http.Request) {
	user, _ := s.currentUser(r)
	if user == nil || user.TOTPSecret == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	otpauthURL := buildOTPAuthURL("VAULT SHELL", user.Username, user.TOTPSecret)
	png, err := renderQRCodePNG(otpauthURL)
	if err != nil {
		http.Error(w, "failed to render QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, "qrcode.png", time.Now(), bytes.NewReader(png))
}

func (s *Server) handleEnable2FAConfirm(w http.ResponseWriter, r *http.Request) {
	user, _ := s.currentUser(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return
	}

	var req struct{ Code string }
	if !decodeJSON(r, &req) {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if err := auth.ConfirmEnableTOTP(s.conn, user.ID, req.Code); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa enabled"})
}

func (s *Server) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	user, _ := s.currentUser(r)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "not logged in")
		return
	}

	if err := auth.DisableTOTP(s.conn, user.ID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "2fa disabled"})
}

// ---- Small helpers ----

func userDetailsJSON(u *models.User, sessionExpiresAt time.Time) map[string]interface{} {
	lastLogin := ""
	if u.LastLoginAt != nil {
		lastLogin = u.LastLoginAt.UTC().Format(time.RFC3339)
	}
	return map[string]interface{}{
		"username":           u.Username,
		"created_at":         u.CreatedAt.UTC().Format(time.RFC3339),
		"totp_enabled":       u.TOTPEnabled,
		"session_expires_at": sessionExpiresAt.UTC().Format(time.RFC3339),
		"last_login_at":      lastLogin,
	}
}

// getSessionExpiry is a small convenience wrapper so handleMe can show the
// same session_expires_at field the CLI shows.
func getSessionExpiry(s *Server, token string) (time.Time, error) {
	sess, err := db.GetSession(s.conn, token)
	if err != nil {
		return time.Time{}, err
	}
	return sess.ExpiresAt, nil
}

// buildOTPAuthURL constructs the standard otpauth:// URI (RFC-adjacent,
// Google Authenticator's de facto format) for an existing secret, so the
// QR endpoint can reconstruct the same code the CLI would have shown
// without generating (and thereby invalidating) a new secret.
func buildOTPAuthURL(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")

	u := url.URL{
		Scheme:   "otpauth",
		Host:     "totp",
		Path:     "/" + issuer + ":" + account,
		RawQuery: v.Encode(),
	}
	return u.String()
}
