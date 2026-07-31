package auth

import (
	"errors"
	"testing"
	"time"
)

// testLockoutConfig uses a lockout duration long enough to survive the
// real bcrypt cost (~0.5s per attempt at our production cost factor) of the
// several Login calls each test makes — otherwise the window can expire
// mid-test before we get to assert the account is still locked.
func testLockoutConfig() LockoutConfig {
	return LockoutConfig{
		MaxFailedAttempts: 3,
		LockoutDuration:   3 * time.Second,
	}
}

// shortLockoutConfig is only for TestLogin_UnlocksAfterLockoutWindowPasses,
// which needs the window to actually expire within the test run.
func shortLockoutConfig() LockoutConfig {
	return LockoutConfig{
		MaxFailedAttempts: 3,
		LockoutDuration:   1 * time.Second,
	}
}

func TestLogin_Success(t *testing.T) {
	conn := newTestDB(t)
	if _, err := Register(conn, "frank", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	user, err := Login(conn, testLockoutConfig(), "frank", "correctpassword")
	if err != nil {
		t.Fatalf("Login returned error: %v", err)
	}
	if user.LastLoginAt == nil {
		t.Error("expected LastLoginAt to be set after successful login")
	}
	if user.FailedAttempts != 0 {
		t.Errorf("expected FailedAttempts to be 0 after success, got %d", user.FailedAttempts)
	}
}

func TestLogin_LocksAfterMaxFailedAttempts(t *testing.T) {
	conn := newTestDB(t)
	cfg := testLockoutConfig()
	if _, err := Register(conn, "grace", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	for i := 0; i < cfg.MaxFailedAttempts-1; i++ {
		_, err := Login(conn, cfg, "grace", "wrongpassword")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: expected ErrInvalidCredentials, got %v", i+1, err)
		}
	}

	_, err := Login(conn, cfg, "grace", "wrongpassword")
	var lockErr *AccountLockedError
	if !errors.As(err, &lockErr) {
		t.Fatalf("expected *AccountLockedError after hitting max attempts, got %v", err)
	}

	_, err = Login(conn, cfg, "grace", "correctpassword")
	if !errors.As(err, &lockErr) {
		t.Fatalf("expected account to still be locked even with correct password, got %v", err)
	}
}

func TestLogin_UnlocksAfterLockoutWindowPasses(t *testing.T) {
	conn := newTestDB(t)
	cfg := shortLockoutConfig()
	if _, err := Register(conn, "henry", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	for i := 0; i < cfg.MaxFailedAttempts; i++ {
		Login(conn, cfg, "henry", "wrongpassword")
	}

	var lockErr *AccountLockedError
	if _, err := Login(conn, cfg, "henry", "correctpassword"); !errors.As(err, &lockErr) {
		t.Fatalf("expected account to be locked immediately after max attempts, got %v", err)
	}

	time.Sleep(cfg.LockoutDuration + 200*time.Millisecond)

	user, err := Login(conn, cfg, "henry", "correctpassword")
	if err != nil {
		t.Fatalf("expected login to succeed after lockout window passed, got error: %v", err)
	}
	if user.Username != "henry" {
		t.Errorf("expected username %q, got %q", "henry", user.Username)
	}
}

func TestLogin_SuccessResetsFailedAttemptCounter(t *testing.T) {
	conn := newTestDB(t)
	cfg := testLockoutConfig()
	if _, err := Register(conn, "irene", "correctpassword"); err != nil {
		t.Fatalf("Register returned error: %v", err)
	}

	if _, err := Login(conn, cfg, "irene", "wrongpassword"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}

	user, err := Login(conn, cfg, "irene", "correctpassword")
	if err != nil {
		t.Fatalf("expected successful login, got error: %v", err)
	}
	if user.FailedAttempts != 0 {
		t.Errorf("expected failed_attempts reset to 0, got %d", user.FailedAttempts)
	}

	for i := 0; i < cfg.MaxFailedAttempts-1; i++ {
		_, err := Login(conn, cfg, "irene", "wrongpassword")
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d after reset: expected ErrInvalidCredentials (not locked), got %v", i+1, err)
		}
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	conn := newTestDB(t)
	_, err := Login(conn, testLockoutConfig(), "nosuchuser", "whatever")
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expected ErrInvalidCredentials for unknown user, got %v", err)
	}
}
