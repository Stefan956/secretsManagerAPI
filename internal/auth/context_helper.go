package auth

import "context"

type contextKey string

const (
	usernameKey   contextKey = "username"
	secretNameKey contextKey = "secretName"
)

// WithUsername injects the username into the request context
func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, usernameKey, username) //to avoid collisions - use custom key type
}

// GetUsername retrieves the username from the request context
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(usernameKey).(string)
	return username, ok
}

// WithSecretName injects the secret name into the request context
func WithSecretName(ctx context.Context, secretName string) context.Context {
	return context.WithValue(ctx, secretNameKey, secretName)
}

// GetSecretName retrieves the secret name from the request context
func GetSecretName(ctx context.Context) (string, bool) {
	secretName, ok := ctx.Value(secretNameKey).(string)
	return secretName, ok
}
