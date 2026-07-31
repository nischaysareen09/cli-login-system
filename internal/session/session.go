// Package session handles login session creation, validation, and expiry
// for the CLI login system.
package session

import (
	"database/sql"
	"errors"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"

	"cli-login-system/internal/db"
	"cli-login-system/internal/models"
)

// ErrSessionExpired is returned by Validate when the session token was once
// valid but its expiry time has passed. The stale session is deleted as a
// side effect so it doesn't linger in the database.
var ErrSessionExpired = errors.New("session: session has expired")

// ErrInvalidSession is returned by Validate for a token that doesn't match
// any session (never existed, already logged out, or already expired and
// cleaned up by an earlier call).
var ErrInvalidSession = errors.New("session: invalid session")

// Config controls session behavior. Timeout is how long a session stays
// valid after login, configurable via SESSION_TIMEOUT_MINUTES.
type Config struct {
	Timeout time.Duration
}

// DefaultConfig reads SESSION_TIMEOUT_MINUTES from the environment, falling
// back to 15 minutes if unset or invalid.
func DefaultConfig() Config {
	minutes := 15
	if v := os.Getenv("SESSION_TIMEOUT_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			minutes = n
		}
	}
	return Config{Timeout: time.Duration(minutes) * time.Minute}
}

// Create starts a new session for the given user, valid for cfg.Timeout
// from now. The returned token is what the CLI holds onto (in memory, for
// the lifetime of the process) to authenticate subsequent commands.
func Create(conn *sql.DB, cfg Config, userID int64) (*models.Session, error) {
	token := uuid.NewString()
	expiresAt := time.Now().Add(cfg.Timeout)
	return db.CreateSession(conn, token, userID, expiresAt)
}

// Validate looks up a session token and returns the associated user if the
// session exists and hasn't expired. If it has expired, the session is
// deleted and ErrSessionExpired is returned — callers should treat this the
// same as being logged out and prompt for a fresh login.
func Validate(conn *sql.DB, token string) (*models.User, error) {
	sess, err := db.GetSession(conn, token)
	if err != nil {
		if errors.Is(err, db.ErrSessionNotFound) {
			return nil, ErrInvalidSession
		}
		return nil, err
	}

	if sess.IsExpired() {
		// Best-effort cleanup; if this fails the session will still be
		// treated as invalid by the caller, and future GetSession calls
		// will still catch it as expired.
		_ = db.DeleteSession(conn, token)
		return nil, ErrSessionExpired
	}

	return db.GetUserByID(conn, sess.UserID)
}

// End (logout) deletes the session, immediately invalidating the token.
func End(conn *sql.DB, token string) error {
	return db.DeleteSession(conn, token)
}
