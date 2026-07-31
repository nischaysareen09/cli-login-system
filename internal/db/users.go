package db

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"cli-login-system/internal/models"
)

// ErrUserNotFound is returned when a lookup finds no matching user.
var ErrUserNotFound = errors.New("db: user not found")

// ErrUsernameTaken is returned by CreateUser when the username already exists.
var ErrUsernameTaken = errors.New("db: username already taken")

const timeLayout = time.RFC3339

// CreateUser inserts a new user with the given username and bcrypt password
// hash. createdAt is stored in RFC3339 format.
func CreateUser(conn *sql.DB, username, passwordHash string) (*models.User, error) {
	now := time.Now().UTC()

	res, err := conn.Exec(
		`INSERT INTO users (username, password_hash, totp_enabled, failed_attempts, created_at)
		 VALUES (?, ?, 0, 0, ?)`,
		username, passwordHash, now.Format(timeLayout),
	)
	if err != nil {
		// SQLite reports unique constraint violations with this substring.
		if isUniqueConstraintErr(err) {
			return nil, ErrUsernameTaken
		}
		return nil, fmt.Errorf("db: failed to create user: %w", err)
	}

	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("db: failed to read new user id: %w", err)
	}

	return &models.User{
		ID:           id,
		Username:     username,
		PasswordHash: passwordHash,
		CreatedAt:    now,
	}, nil
}

// GetUserByUsername fetches a user by username. Returns ErrUserNotFound if
// no such user exists.
func GetUserByUsername(conn *sql.DB, username string) (*models.User, error) {
	row := conn.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enabled,
		        failed_attempts, locked_until, created_at, last_login_at
		 FROM users WHERE username = ?`,
		username,
	)
	return scanUser(row)
}

// GetUserByID fetches a user by their numeric ID. Returns ErrUserNotFound if
// no such user exists.
func GetUserByID(conn *sql.DB, id int64) (*models.User, error) {
	row := conn.QueryRow(
		`SELECT id, username, password_hash, totp_secret, totp_enabled,
		        failed_attempts, locked_until, created_at, last_login_at
		 FROM users WHERE id = ?`,
		id,
	)
	return scanUser(row)
}

// UpdateLastLogin sets last_login_at to now for the given user.
func UpdateLastLogin(conn *sql.DB, userID int64) error {
	now := time.Now().UTC().Format(timeLayout)
	_, err := conn.Exec(`UPDATE users SET last_login_at = ? WHERE id = ?`, now, userID)
	if err != nil {
		return fmt.Errorf("db: failed to update last_login_at: %w", err)
	}
	return nil
}

// scanUser reads a single user row. Shared by GetUserByUsername and GetUserByID.
func scanUser(row *sql.Row) (*models.User, error) {
	var (
		u                                  models.User
		totpSecret, lockedUntil, lastLogin sql.NullString
		createdAt                          string
		totpEnabledInt                     int
	)

	err := row.Scan(
		&u.ID, &u.Username, &u.PasswordHash,
		&totpSecret, &totpEnabledInt,
		&u.FailedAttempts, &lockedUntil,
		&createdAt, &lastLogin,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("db: failed to scan user row: %w", err)
	}

	u.TOTPSecret = totpSecret.String
	u.TOTPEnabled = totpEnabledInt != 0

	if u.CreatedAt, err = time.Parse(timeLayout, createdAt); err != nil {
		return nil, fmt.Errorf("db: failed to parse created_at: %w", err)
	}

	if lockedUntil.Valid {
		t, err := time.Parse(timeLayout, lockedUntil.String)
		if err != nil {
			return nil, fmt.Errorf("db: failed to parse locked_until: %w", err)
		}
		u.LockedUntil = &t
	}

	if lastLogin.Valid {
		t, err := time.Parse(timeLayout, lastLogin.String)
		if err != nil {
			return nil, fmt.Errorf("db: failed to parse last_login_at: %w", err)
		}
		u.LastLoginAt = &t
	}

	return &u, nil
}

func isUniqueConstraintErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
