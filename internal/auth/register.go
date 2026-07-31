package auth

import (
	"database/sql"
	"fmt"

	"cli-login-system/internal/db"
	"cli-login-system/internal/models"
)

// ErrInvalidUsername is returned when a username fails basic validation.
var ErrInvalidUsername = fmt.Errorf("auth: username must be 3-32 characters, letters/numbers/underscore/dash only")

// ErrWeakPassword is returned when a password is too short to be accepted.
var ErrWeakPassword = fmt.Errorf("auth: password must be at least 8 characters")

const minPasswordLength = 8

// Register creates a new user with the given username and plaintext
// password. The password is hashed with bcrypt before it ever touches the
// database — the plaintext is never stored or logged.
//
// Returns db.ErrUsernameTaken if the username is already in use.
func Register(conn *sql.DB, username, password string) (*models.User, error) {
	if !isValidUsername(username) {
		return nil, ErrInvalidUsername
	}
	if len(password) < minPasswordLength {
		return nil, ErrWeakPassword
	}

	hash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	user, err := db.CreateUser(conn, username, hash)
	if err != nil {
		return nil, err // may be db.ErrUsernameTaken
	}

	return user, nil
}

func isValidUsername(username string) bool {
	if len(username) < 3 || len(username) > 32 {
		return false
	}
	for _, r := range username {
		isLetter := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')
		isDigit := r >= '0' && r <= '9'
		isAllowedSymbol := r == '_' || r == '-'
		if !isLetter && !isDigit && !isAllowedSymbol {
			return false
		}
	}
	return true
}
