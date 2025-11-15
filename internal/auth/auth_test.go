package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

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

func TestMakeAndValidateToken(t *testing.T) {
	userId, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("Error generating uuid: %v", err)
		return
	}

	jwtSecret := "#h42sZBF%i5qH@6pcdLCeUVQ"

	duration, err := time.ParseDuration("5s")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}

	token, err := MakeJWT(userId, jwtSecret, duration)
	if err != nil {
		t.Errorf("Error making jwt token: %v", err)
		return
	}

	returnedUserId, err := ValidateJWT(token, jwtSecret)
	if err != nil {
		t.Errorf("Error validating token: %v", err)
		return
	}

	if returnedUserId != userId {
		t.Errorf("Returned user id and original user id don't match: %v", err)
		return
	}
}

func TestMakeAndValidateTokenWrongSecret(t *testing.T) {
	userId, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("Error generating uuid: %v", err)
		return
	}

	jwtSecret := "#h42sZBF%i5qH@6pcdLCeUVQ"
	jwtWrongSecret := "#h42sZBF%i4qH@6pcdLCeUVQ"

	duration, err := time.ParseDuration("5s")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}

	token, err := MakeJWT(userId, jwtSecret, duration)
	if err != nil {
		t.Errorf("Error making jwt token: %v", err)
		return
	}

	returnedUserId, err := ValidateJWT(token, jwtWrongSecret)
	if err == nil {
		t.Errorf("Validated with wrong jwt secret")
		return
	}

	if returnedUserId == userId {
		t.Errorf("Returned correct user with wrong jwt secret")
		return
	}
}

func TestMakeAndValidateExpiredToken(t *testing.T) {
	userId, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("Error generating uuid: %v", err)
		return
	}

	jwtSecret := "#h42sZBF%i5qH@6pcdLCeUVQ"

	duration, err := time.ParseDuration("1ms")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}

	token, err := MakeJWT(userId, jwtSecret, duration)
	if err != nil {
		t.Errorf("Error making jwt token: %v", err)
		return
	}

	biggerDuration, err := time.ParseDuration("2ms")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}
	time.Sleep(biggerDuration)

	returnedUserId, err := ValidateJWT(token, jwtSecret)
	if err == nil {
		t.Errorf("Expired token validated: %v", err)
		return
	}

	if returnedUserId == userId {
		t.Errorf("Returned user id with expired token and original user id match: %v", err)
		return
	}
}

func TestGetBearerToken(t *testing.T) {
	userId, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("Error generating uuid: %v", err)
		return
	}

	jwtSecret := "#h42sZBF%i5qH@6pcdLCeUVQ"

	duration, err := time.ParseDuration("5s")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}

	token, err := MakeJWT(userId, jwtSecret, duration)
	if err != nil {
		t.Errorf("Error making jwt token: %v", err)
		return
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+token)

	returnedToken, err := GetBearerToken(headers)
	if err != nil {
		t.Errorf("Error getting bearer token")
		return
	}

	if returnedToken != token {
		t.Errorf("Tokens don't match")
		return
	}
}

func TestGetBearerTokenWrongHeaderFormat(t *testing.T) {
	userId, err := uuid.NewUUID()
	if err != nil {
		t.Errorf("Error generating uuid: %v", err)
		return
	}

	jwtSecret := "#h42sZBF%i5qH@6pcdLCeUVQ"

	duration, err := time.ParseDuration("5s")
	if err != nil {
		t.Errorf("Error parsing duration: %v", err)
		return
	}

	token, err := MakeJWT(userId, jwtSecret, duration)
	if err != nil {
		t.Errorf("Error making jwt token: %v", err)
		return
	}

	headers := http.Header{}
	headers.Set("Authorization", "Beer "+token)

	_, err = GetBearerToken(headers)
	if err == nil {
		t.Errorf("Got token with wrongly formatted header value")
		return
	}
}
