package auth

import (
	"database/sql"
	"errors"

	"cli-login-system/internal/db"
	"cli-login-system/internal/models"
)

// ErrInvalidCredentials is returned whenever a username/password pair does
// not check out. It's deliberately generic — we never reveal whether the
// username exists or the password was wrong, to avoid leaking which part
// of the credentials an attacker got right.
var ErrInvalidCredentials = errors.New("auth: invalid username or password")

// AuthenticatePassword verifies a username/password pair against the
// database. It does NOT yet handle account lockout or session creation —
// those are layered on top in Steps 4 and 6. On its own, this function is
// just: "does this password match what's on file for this user?"
func AuthenticatePassword(conn *sql.DB, username, password string) (*models.User, error) {
	user, err := db.GetUserByUsername(conn, username)
	if err != nil {
		if errors.Is(err, db.ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := VerifyPassword(user.PasswordHash, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	return user, nil
}
