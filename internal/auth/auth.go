package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTGenerator interface {
	Generate(username string) (string, error)
}

// JWTManager handles creation and verification of JWT tokens
type JWTManager struct {
	SecretKey     string
	TokenDuration time.Duration
}

// Claims contains JWT claims
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// NewJWTManager creates a new JWTManager
func NewJWTManager(secretKey string, duration time.Duration) *JWTManager {
	return &JWTManager{
		SecretKey:     secretKey,
		TokenDuration: duration,
	}
}

// Generate creates a signed JWT for a username
func (j *JWTManager) Generate(username string) (string, error) {
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(j.TokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(j.SecretKey))
}

// Verify parses and validates a JWT token
func (j *JWTManager) Verify(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Ensure signing method is HMAC
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(j.SecretKey), nil
	})
	if err != nil {
		return nil, err
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token")
	}

	return claims, nil
}
