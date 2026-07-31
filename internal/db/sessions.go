package db

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"cli-login-system/internal/models"
)

// ErrSessionNotFound is returned when a lookup finds no matching session.
var ErrSessionNotFound = errors.New("db: session not found")

// CreateSession inserts a new session row for the given user and token,
// expiring at the given time.
func CreateSession(conn *sql.DB, token string, userID int64, expiresAt time.Time) (*models.Session, error) {
	now := time.Now().UTC()

	_, err := conn.Exec(
		`INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)`,
		token, userID, now.Format(timeLayout), expiresAt.UTC().Format(timeLayout),
	)
	if err != nil {
		return nil, fmt.Errorf("db: failed to create session: %w", err)
	}

	return &models.Session{
		Token:     token,
		UserID:    userID,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

// GetSession fetches a session by token. Returns ErrSessionNotFound if no
// such session exists (this includes tokens that were never valid, and
// ones already deleted by DeleteSession).
func GetSession(conn *sql.DB, token string) (*models.Session, error) {
	var (
		s                    models.Session
		createdAt, expiresAt string
	)

	err := conn.QueryRow(
		`SELECT token, user_id, created_at, expires_at FROM sessions WHERE token = ?`,
		token,
	).Scan(&s.Token, &s.UserID, &createdAt, &expiresAt)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("db: failed to scan session row: %w", err)
	}

	if s.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("db: failed to parse session created_at: %w", err)
	}
	if s.ExpiresAt, err = time.Parse(timeLayout, expiresAt); err != nil {
		return nil, fmt.Errorf("db: failed to parse session expires_at: %w", err)
	}

	return &s, nil
}

// DeleteSession removes a session (used for logout, and for cleaning up
// expired sessions once they're discovered).
func DeleteSession(conn *sql.DB, token string) error {
	_, err := conn.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	if err != nil {
		return fmt.Errorf("db: failed to delete session: %w", err)
	}
	return nil
}
