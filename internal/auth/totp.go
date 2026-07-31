package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	"cli-login-system/internal/db"
)

// issuer is shown in Google Authenticator (and compatible apps) alongside
// the account name, so users can tell which service a code belongs to.
const issuer = "CLI-Login-System"

// ErrInvalidTOTPCode is returned when a supplied 6-digit code doesn't match.
var ErrInvalidTOTPCode = errors.New("auth: invalid 2FA code")

// ErrTOTPAlreadyEnabled is returned by StartEnableTOTP if 2FA is already on.
var ErrTOTPAlreadyEnabled = errors.New("auth: 2FA is already enabled")

// ErrTOTPNotEnabled is returned by DisableTOTP if 2FA isn't currently on.
var ErrTOTPNotEnabled = errors.New("auth: 2FA is not enabled")

// StartEnableTOTP begins the 2FA setup flow: it generates a new TOTP secret
// and stores it as "pending" (2FA is NOT active yet). It returns the
// otp.Key, whose URL() is the otpauth:// URI a user scans into Google
// Authenticator (or a compatible app), and whose Secret() is the plain
// base32 secret for manual entry.
//
// The caller must follow up with ConfirmEnableTOTP once the user has typed
// in a code from their app — 2FA only becomes active at that point. This
// two-step flow prevents a user locking themselves out by enabling 2FA
// against an app they never actually finished setting up correctly.
func StartEnableTOTP(conn *sql.DB, userID int64, username string) (*otp.Key, error) {
	user, err := db.GetUserByID(conn, userID)
	if err != nil {
		return nil, err
	}
	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: username,
	})
	if err != nil {
		return nil, fmt.Errorf("auth: failed to generate totp secret: %w", err)
	}

	if err := db.SetPendingTOTPSecret(conn, userID, key.Secret()); err != nil {
		return nil, err
	}

	return key, nil
}

// ConfirmEnableTOTP checks a 6-digit code against the pending secret set by
// StartEnableTOTP and, if it matches, activates 2FA for the account.
func ConfirmEnableTOTP(conn *sql.DB, userID int64, code string) error {
	user, err := db.GetUserByID(conn, userID)
	if err != nil {
		return err
	}
	if user.TOTPSecret == "" {
		return fmt.Errorf("auth: no pending 2FA setup found; run enable-2fa first")
	}

	if !VerifyTOTPCode(user.TOTPSecret, code) {
		return ErrInvalidTOTPCode
	}

	return db.EnableTOTP(conn, userID)
}

// DisableTOTP turns 2FA off for the user and clears the stored secret.
func DisableTOTP(conn *sql.DB, userID int64) error {
	user, err := db.GetUserByID(conn, userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}
	return db.DisableTOTP(conn, userID)
}

// VerifyTOTPCode reports whether the given 6-digit code is valid right now
// for the given base32 secret. Used both to confirm 2FA setup and to check
// the code a user supplies at login.
func VerifyTOTPCode(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now(), totp.ValidateOpts{
		Period:    30,
		Skew:      1, // allow ±1 time-step (30s) of clock drift
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && valid
}
