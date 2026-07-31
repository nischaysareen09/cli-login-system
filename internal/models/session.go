package models

import "time"

// Session represents a row in the sessions table — an active login session
// identified by a random token.
type Session struct {
	Token     string
	UserID    int64
	CreatedAt time.Time
	ExpiresAt time.Time
}

// IsExpired reports whether the session's expiry time has passed.
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
