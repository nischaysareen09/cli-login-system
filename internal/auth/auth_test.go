package auth

import (
	"database/sql"
	"errors"
	"testing"

	"cli-login-system/internal/db"
)

// newTestDB spins up an in-memory SQLite database with the schema applied,
// so these tests exercise the real DB layer rather than mocks.
func newTestDB(t *testing.T) *sql.DB {
	t.Helper()
	conn, err := db.Connect(":memory:")
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	if err := db.Migrate(conn); err != nil {
		t.Fatalf("failed to migrate test db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func TestRegister_Success(t *testing.T) {
	conn := newTestDB(t)

	user, err := Register(conn, "alice", "correcthorsebatterystaple")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}
	if user.Username != "alice" {
		t.Errorf("expected username %q, got %q", "alice", user.Username)
	}
	if user.PasswordHash == "correcthorsebatterystaple" {
		t.Error("stored password hash must not equal the plaintext password")
	}
	if user.ID == 0 {
		t.Error("expected a non-zero user ID after registration")
	}
}

func TestRegister_DuplicateUsername(t *testing.T) {
	conn := newTestDB(t)

	if _, err := Register(conn, "bob", "password123"); err != nil {
		t.Fatalf("first Register returned error: %v", err)
	}
	_, err := Register(conn, "bob", "differentpassword")
	if !errors.Is(err, db.ErrUsernameTaken) {
		t.Fatalf("expected db.ErrUsernameTaken, got %v", err)
	}
}

func TestRegister_WeakPassword(t *testing.T) {
	conn := newTestDB(t)
	_, err := Register(conn, "carol", "short")
	if !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("expected ErrWeakPassword, got %v", err)
	}
}

func TestRegister_InvalidUsername(t *testing.T) {
	conn := newTestDB(t)
	_, err := Register(conn, "a", "password123")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("expected ErrInvalidUsername for too-short username, got %v", err)
	}

	_, err = Register(conn, "has a space", "password123")
	if !errors.Is(err, ErrInvalidUsername) {
		t.Fatalf("expected ErrInvalidUsername for username with a space, got %v", err)
	}
}

func TestAuthenticatePassword_Success(t *testing.T) {
	conn := newTestDB(t)
	if _, err := Register(conn, "dave", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	user, err := AuthenticatePassword(conn, "dave", "correctpassword")
	if err != nil {
		t.Fatalf("AuthenticatePassword returned error: %v", err)
	}
	if user.Username != "dave" {
		t.Errorf("expected username %q, got %q", "dave", user.Username)
	}
}

func TestAuthenticatePassword_WrongPassword(t *testing.T) {
	conn := newTestDB(t)
	if _, err := Register(conn, "erin", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	_, err := AuthenticatePassword(conn, "erin", "wrongpassword")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestAuthenticatePassword_UnknownUser(t *testing.T) {
	conn := newTestDB(t)
	_, err := AuthenticatePassword(conn, "nobody", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}
