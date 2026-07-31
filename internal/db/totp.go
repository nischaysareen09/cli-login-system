package db

import (
	"database/sql"
	"fmt"
)

// SetPendingTOTPSecret stores a newly generated TOTP secret for the user
// without enabling 2FA yet. 2FA only becomes active once the user proves
// they've correctly set up their authenticator app by confirming a code
// (see EnableTOTP).
func SetPendingTOTPSecret(conn *sql.DB, userID int64, secret string) error {
	_, err := conn.Exec(`UPDATE users SET totp_secret = ? WHERE id = ?`, secret, userID)
	if err != nil {
		return fmt.Errorf("db: failed to set pending totp secret: %w", err)
	}
	return nil
}

// EnableTOTP flips totp_enabled on for the user. Called only after the
// caller has verified the user supplied a correct code for the secret set
// by SetPendingTOTPSecret.
func EnableTOTP(conn *sql.DB, userID int64) error {
	_, err := conn.Exec(`UPDATE users SET totp_enabled = 1 WHERE id = ?`, userID)
	if err != nil {
		return fmt.Errorf("db: failed to enable totp: %w", err)
	}
	return nil
}

// DisableTOTP turns 2FA off and clears the stored secret, so a fresh
// secret will be generated if the user enables 2FA again later.
func DisableTOTP(conn *sql.DB, userID int64) error {
	_, err := conn.Exec(
		`UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?`,
		userID,
	)
	if err != nil {
		return fmt.Errorf("db: failed to disable totp: %w", err)
	}
	return nil
}
