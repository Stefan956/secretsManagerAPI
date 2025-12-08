package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests for UserRequest - marshalling and unmarshalling
func TestUserRequest_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		input    UserRequest
		expected string
	}{
		{
			name: "valid user request",
			input: UserRequest{
				Username: "alice",
				Password: "secret123",
			},
			expected: `{"username":"alice","password":"secret123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.input)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(b))
		})
	}
}

func TestUserRequest_JSONUnmarshalling(t *testing.T) {
	jsonStr := `{"username":"bob","password":"hunter2"}`
	var req UserRequest
	err := json.Unmarshal([]byte(jsonStr), &req)
	require.NoError(t, err)
	assert.Equal(t, "bob", req.Username)
	assert.Equal(t, "hunter2", req.Password)
}

// Testing UserResponse - marshalling and unmarshalling
func TestUserResponse_JSONMarshalling(t *testing.T) {
	tests := []struct {
		name     string
		input    UserResponse
		expected string
	}{
		{
			name: "with token",
			input: UserResponse{
				Token:   "abcd1234",
				Message: "login successful",
			},
			expected: `{"token":"abcd1234","message":"login successful"}`,
		},
		{
			name: "without token (omitempty)",
			input: UserResponse{
				Message: "user registered",
			},
			expected: `{"message":"user registered"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.input)
			require.NoError(t, err)
			assert.JSONEq(t, tt.expected, string(b))
		})
	}
}

func TestUserResponse_JSONUnmarshalling(t *testing.T) {
	jsonStr := `{"token":"xyz","message":"success"}`
	var resp UserResponse
	err := json.Unmarshal([]byte(jsonStr), &resp)
	require.NoError(t, err)
	assert.Equal(t, "xyz", resp.Token)
	assert.Equal(t, "success", resp.Message)
}
