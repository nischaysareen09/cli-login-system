package models

import "time"

// User represents a row in the users table.
type User struct {
	ID             int64
	Username       string
	PasswordHash   string

	TOTPSecret  string // empty string if 2FA has never been set up
	TOTPEnabled bool

	FailedAttempts int
	LockedUntil    *time.Time // nil if the account is not currently locked

	CreatedAt   time.Time
	LastLoginAt *time.Time // nil if the user has never logged in
}

// IsLocked reports whether the account is currently locked out, based on
// LockedUntil compared to the current time.
func (u *User) IsLocked() bool {
	return u.LockedUntil != nil && time.Now().Before(*u.LockedUntil)
}
