package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

// Test - Constructor
// Check that NewJWTManager creates a JWTManager with correct fields
func TestNewJWTManager(t *testing.T) {
	j := NewJWTManager("secret123", time.Hour)

	assert.NotNil(t, j)
	assert.Equal(t, "secret123", j.SecretKey)
	assert.Equal(t, time.Hour, j.TokenDuration)
}

// Test - Generate + Verify
// Checks full round-trip: Generate -> Verify works correctly
func TestJWTManager_GenerateAndVerify(t *testing.T) {
	j := NewJWTManager("supersecret", time.Minute)

	token, err := j.Generate("alice")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	claims, err := j.Verify(token)
	assert.NoError(t, err)
	assert.Equal(t, "alice", claims.Username)

	//Ensure expiry is set roughly to 1 minute in the future
	assert.WithinDuration(t, time.Now().Add(time.Minute), claims.ExpiresAt.Time, time.Second*2)
}

// Test - Expired Token
// Ensures that Verify rejects expired tokens
func TestJWTManager_ExpiredToken(t *testing.T) {
	j := NewJWTManager("key", -time.Minute) //Token already expired

	token, err := j.Generate("tom")
	assert.NoError(t, err)

	_, err = j.Verify(token)
	assert.Error(t, err)
}

// Test - Invalid Secret Key
// Ensures Verify fails when using a different signing key
func TestJWTManager_InvalidSecretKey(t *testing.T) {
	j1 := NewJWTManager("key1", time.Minute)
	j2 := NewJWTManager("key2", time.Minute)

	token, err := j1.Generate("catlin")
	assert.NoError(t, err)

	_, err = j2.Verify(token) //verify with different key
	assert.Error(t, err)
}

// Test - Malformed Token String
// Ensures malformed tokens are rejected
func TestJWTManager_MalformedToken(t *testing.T) {
	j := NewJWTManager("secret", time.Minute)

	_, err := j.Verify("this.is.not.a.valid.token")
	assert.Error(t, err)
}

// Test - Wrong Signing Method
// Checks that only HS256 token are accepted
func TestJWTManager_WrongSigningMethod(t *testing.T) {
	j := NewJWTManager("secret", time.Minute)

	// Generate a temporary RSA key for the RS256 signing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create an RS256 token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, &Claims{
		Username: "dan",
	})

	// Properly sign with the RSA private key so it's a valid token structurally
	signed, err := token.SignedString(privateKey)
	assert.NoError(t, err)

	// Now Verify should reject this token due to unexpected signing method
	_, err = j.Verify(signed)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected signing method")
}
