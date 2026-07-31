package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"cli-login-system/internal/db"
	"cli-login-system/internal/models"
)

// ErrAccountLocked is returned by Login when the account is currently
// locked out due to too many failed attempts. Use errors.As to recover the
// *AccountLockedError and find out when it unlocks.
var ErrAccountLocked = errors.New("auth: account is locked")

// AccountLockedError carries the time the account unlocks, so the CLI can
// show a helpful message like "locked until 3:04PM".
type AccountLockedError struct {
	Until time.Time
}

func (e *AccountLockedError) Error() string {
	return fmt.Sprintf("account is locked until %s", e.Until.Local().Format(time.Kitchen))
}

func (e *AccountLockedError) Unwrap() error {
	return ErrAccountLocked
}

// LockoutConfig controls how lockout behaves. Both values are configurable
// via environment variables so they can be tuned per deployment without a
// code change (see docker-compose.yml).
type LockoutConfig struct {
	MaxFailedAttempts int
	LockoutDuration   time.Duration
}

// DefaultLockoutConfig reads MAX_FAILED_ATTEMPTS and LOCKOUT_DURATION_MINUTES
// from the environment, falling back to sane defaults (5 attempts, 5 minute
// lockout) if they're unset or invalid.
func DefaultLockoutConfig() LockoutConfig {
	maxAttempts := 5
	if v := os.Getenv("MAX_FAILED_ATTEMPTS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxAttempts = n
		}
	}

	lockoutMinutes := 5
	if v := os.Getenv("LOCKOUT_DURATION_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lockoutMinutes = n
		}
	}

	return LockoutConfig{
		MaxFailedAttempts: maxAttempts,
		LockoutDuration:   time.Duration(lockoutMinutes) * time.Minute,
	}
}

// Login is the full password-login flow used by the CLI: it checks whether
// the account is locked, verifies the password, and updates failed-attempt
// / lockout state accordingly. On success it resets the failure counter and
// updates last_login_at. It does not handle TOTP (Step 5) or session
// creation (Step 6) — those wrap around this in later steps.
func Login(conn *sql.DB, cfg LockoutConfig, username, password string) (*models.User, error) {
	user, err := db.GetUserByUsername(conn, username)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Lock check comes before password verification: a locked account
	// should not leak whether the supplied password happened to be right.
	if user.IsLocked() {
		return nil, &AccountLockedError{Until: *user.LockedUntil}
	}

	if verifyErr := VerifyPassword(user.PasswordHash, password); verifyErr != nil {
		newCount, incErr := db.IncrementFailedAttempts(conn, user.ID)
		if incErr != nil {
			return nil, incErr
		}
		if newCount >= cfg.MaxFailedAttempts {
			until := time.Now().Add(cfg.LockoutDuration)
			if lockErr := db.LockAccount(conn, user.ID, until); lockErr != nil {
				return nil, lockErr
			}
			return nil, &AccountLockedError{Until: until}
		}
		return nil, ErrInvalidCredentials
	}

	// Successful login: clear any failure history and record the login time.
	if err := db.ResetFailedAttempts(conn, user.ID); err != nil {
		return nil, err
	}
	if err := db.UpdateLastLogin(conn, user.ID); err != nil {
		return nil, err
	}

	// Re-fetch so the returned user reflects the reset state and updated
	// last_login_at rather than the stale pre-login snapshot.
	return db.GetUserByID(conn, user.ID)
}
