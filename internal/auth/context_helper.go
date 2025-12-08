package auth

import "context"

type contextKey string

const (
	UsernameKey   contextKey = "username"
	SecretNameKey contextKey = "secretName"
)

// WithUsername injects the username into the request context
func WithUsername(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, UsernameKey, username) //to avoid collisions - use custom key type
}

// GetUsername retrieves the username from the request context
func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}

// WithSecretName injects the secret name into the request context
func WithSecretName(ctx context.Context, secretName string) context.Context {
	return context.WithValue(ctx, SecretNameKey, secretName)
}

// GetSecretName retrieves the secret name from the request context
func GetSecretName(ctx context.Context) (string, bool) {
	secretName, ok := ctx.Value(SecretNameKey).(string)
	return secretName, ok
}
