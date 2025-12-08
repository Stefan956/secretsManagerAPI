package auth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Verify correct storage and retrieval of username in context
func TestWithUsername(t *testing.T) {
	ctx := context.Background()
	ctx = WithUsername(ctx, "alice")

	username, ok := GetUsername(ctx)
	assert.True(t, ok)
	assert.Equal(t, "alice", username)
}

// Ensure missing username returns false
func TestGetUsername_Missing(t *testing.T) {
	ctx := context.Background()

	username, ok := GetUsername(ctx)
	assert.False(t, ok)
	assert.Empty(t, username)
}

// Verify secret name round-trip
func TestWithSecretNameAndGetSecretName(t *testing.T) {
	ctx := context.Background()
	ctx = WithSecretName(ctx, "db-password")

	secretName, ok := GetSecretName(ctx)
	assert.True(t, ok)
	assert.Equal(t, "db-password", secretName)
}

// Ensure missing secret returns false
func TestGetSecretName_Missing(t *testing.T) {
	ctx := context.Background()

	secretName, ok := GetSecretName(ctx)
	assert.False(t, ok)
	assert.Empty(t, secretName)
}

// Table-driven version
func TestContextHelpers_TableDriven(t *testing.T) {
	test := []struct {
		name     string
		withFunc func(context.Context) context.Context
		getFunc  func(context.Context) (string, bool)
		Value    string
		expectOk bool
	}{
		{"username - present", func(ctx context.Context) context.Context { return WithUsername(ctx, "alice") }, GetUsername, "alice", true},
		{"username - missing", func(ctx context.Context) context.Context { return ctx }, GetUsername, "", false},
		{"secretName - present", func(ctx context.Context) context.Context { return WithSecretName(ctx, "api-key") }, GetSecretName, "api-key", true},
		{"secretName - missing", func(ctx context.Context) context.Context { return ctx }, GetSecretName, "", false},
	}

	for _, tt := range test {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctx = tt.withFunc(ctx)
			val, ok := tt.getFunc(ctx)
			assert.Equal(t, tt.Value, val)
			assert.Equal(t, tt.expectOk, ok)
		})
	}
}
