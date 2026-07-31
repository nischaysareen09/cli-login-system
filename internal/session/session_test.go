package session

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"cli-login-system/internal/auth"
	"cli-login-system/internal/db"
)

// newTestDB spins up an in-memory SQLite database with the schema applied.
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

func TestCreate_ReturnsValidSession(t *testing.T) {
	conn := newTestDB(t)
	user, err := auth.Register(conn, "quinn", "correctpassword")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	cfg := Config{Timeout: 15 * time.Minute}
	sess, err := Create(conn, cfg, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if sess.Token == "" {
		t.Fatal("expected a non-empty session token")
	}
	if sess.UserID != user.ID {
		t.Errorf("expected UserID %d, got %d", user.ID, sess.UserID)
	}
	if !sess.ExpiresAt.After(time.Now()) {
		t.Error("expected ExpiresAt to be in the future")
	}
}

func TestValidate_ValidSessionReturnsUser(t *testing.T) {
	conn := newTestDB(t)
	user, err := auth.Register(conn, "rachel", "correctpassword")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	sess, err := Create(conn, Config{Timeout: 15 * time.Minute}, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	got, err := Validate(conn, sess.Token)
	if err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if got.Username != "rachel" {
		t.Errorf("expected username %q, got %q", "rachel", got.Username)
	}
}

func TestValidate_UnknownTokenRejected(t *testing.T) {
	conn := newTestDB(t)
	_, err := Validate(conn, "not-a-real-token")
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
}

func TestValidate_ExpiredSessionRejectedAndCleanedUp(t *testing.T) {
	conn := newTestDB(t)
	user, err := auth.Register(conn, "steve", "correctpassword")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	// Very short timeout so it actually expires during the test.
	sess, err := Create(conn, Config{Timeout: 20 * time.Millisecond}, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	_, err = Validate(conn, sess.Token)
	if !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("expected ErrSessionExpired, got %v", err)
	}

	// Second call should now find nothing at all (expired session was
	// deleted as a side effect of the first Validate call).
	_, err = Validate(conn, sess.Token)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession after expired session was cleaned up, got %v", err)
	}
}

func TestEnd_LogoutInvalidatesSession(t *testing.T) {
	conn := newTestDB(t)
	user, err := auth.Register(conn, "tina", "correctpassword")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	sess, err := Create(conn, Config{Timeout: 15 * time.Minute}, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}

	if err := End(conn, sess.Token); err != nil {
		t.Fatalf("End returned error: %v", err)
	}

	_, err = Validate(conn, sess.Token)
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession after logout, got %v", err)
	}
}

func TestCreate_DifferentSessionsGetDifferentTokens(t *testing.T) {
	conn := newTestDB(t)
	user, err := auth.Register(conn, "uma", "correctpassword")
	if err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	cfg := Config{Timeout: 15 * time.Minute}
	s1, err := Create(conn, cfg, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	s2, err := Create(conn, cfg, user.ID)
	if err != nil {
		t.Fatalf("Create returned error: %v", err)
	}
	if s1.Token == s2.Token {
		t.Fatal("expected two separate Create calls to produce different tokens")
	}
}
