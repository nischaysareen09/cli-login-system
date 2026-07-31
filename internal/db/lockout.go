package db

import (
	"database/sql"
	"fmt"
	"time"
)

// IncrementFailedAttempts increments the user's failed_attempts counter and
// returns the new count. Callers use the returned count to decide whether
// the threshold for locking the account has been reached.
func IncrementFailedAttempts(conn *sql.DB, userID int64) (int, error) {
	_, err := conn.Exec(`UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?`, userID)
	if err != nil {
		return 0, fmt.Errorf("db: failed to increment failed_attempts: %w", err)
	}

	var count int
	if err := conn.QueryRow(`SELECT failed_attempts FROM users WHERE id = ?`, userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("db: failed to read failed_attempts: %w", err)
	}
	return count, nil
}

// LockAccount sets locked_until so the account is locked until the given time.
func LockAccount(conn *sql.DB, userID int64, until time.Time) error {
	_, err := conn.Exec(
		`UPDATE users SET locked_until = ? WHERE id = ?`,
		until.UTC().Format(timeLayout), userID,
	)
	if err != nil {
		return fmt.Errorf("db: failed to lock account: %w", err)
	}
	return nil
}

// ResetFailedAttempts clears failed_attempts back to zero and removes any
// lock (locked_until = NULL). Called after a successful login, and also
// used to unlock an account once its lockout window has passed.
func ResetFailedAttempts(conn *sql.DB, userID int64) error {
	_, err := conn.Exec(
		`UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("db: failed to reset failed_attempts: %w", err)
	}
	return nil
}
