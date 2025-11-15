package auth

import "testing"

func TestHashCheckPassword(t *testing.T) {
	password := "thisIS4T3stPassW*rd..."

	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword failed: %v", err)
		return
	}

	match, err := CheckPasswordHash(password, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash failed: %v", err)
		return
	}

	if !match {
		t.Errorf("Password and hash didn't match: %v", err)
		return
	}
}

func TestHashCheckWrongPassword(t *testing.T) {
	password := "thisIS4T3stPassW*rd..."
	wrongPassword := "thisIS4WRONGPassW*rd..."

	hash, err := HashPassword(password)
	if err != nil {
		t.Errorf("HashPassword failed: %v", err)
		return
	}

	match, err := CheckPasswordHash(wrongPassword, hash)
	if err != nil {
		t.Errorf("CheckPasswordHash failed: %v", err)
		return
	}

	if match {
		t.Errorf("Wrong password and hash matched: %v", err)
		return
	}
}
