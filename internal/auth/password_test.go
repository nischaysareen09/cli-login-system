package auth

import "testing"

func TestHashPassword_ProducesDifferentHashForSamePassword(t *testing.T) {
	h1, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	h2, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if h1 == h2 {
		t.Fatal("expected different hashes for the same password (bcrypt should salt each hash)")
	}
	if h1 == "correct horse battery staple" {
		t.Fatal("hash must not equal the plaintext password")
	}
}

func TestVerifyPassword_CorrectPassword(t *testing.T) {
	hash, err := HashPassword("mysecretpassword")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if err := VerifyPassword(hash, "mysecretpassword"); err != nil {
		t.Fatalf("expected correct password to verify, got error: %v", err)
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	hash, err := HashPassword("mysecretpassword")
	if err != nil {
		t.Fatalf("HashPassword returned error: %v", err)
	}
	if err := VerifyPassword(hash, "wrongpassword"); err == nil {
		t.Fatal("expected wrong password to fail verification, got nil error")
	}
}
