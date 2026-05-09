package integration

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secretsManagerAPI/internal/auth"

	"github.com/stretchr/testify/require"
)

// Helper that mounts middleware + handler and performs a request
func doRequestWithAuth(jwtMgr *auth.JWTManager, method, path, authHeader string, handler http.HandlerFunc) *httptest.ResponseRecorder {
	// Wrap the handler with the real middleware
	h := auth.JWTMiddleware(jwtMgr, http.HandlerFunc(handler))

	req := httptest.NewRequest(method, path, nil)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// Simple handler that reads username from context and writes it back
func usernameEchoHandler(w http.ResponseWriter, r *http.Request) {
	username, ok := auth.UsernameFromContext(r.Context())
	if !ok {
		http.Error(w, "username not found in context", http.StatusInternalServerError)
		return
	}
	_, _ = io.WriteString(w, username)
}

// Deeper call to validate context propagation
func nestedReadUsername(ctx context.Context) string {
	if u, ok := auth.UsernameFromContext(ctx); ok {
		return "user:" + u
	}
	return "nouser"
}

// Testing JWT middleware with table-driven tests
func Test_JWTMiddleware_TableDriven(t *testing.T) {
	// Create a single jwt manager instance used for generating valid tokens
	jwtMgr := auth.NewJWTManager("test-secret-1", 5*time.Minute)

	tests := []struct {
		name           string
		setupAuth      func() string // Returns the Authorization header value (possibly empty)
		expectedStatus int
		expectedBody   string // If empty, body is ignored
		handler        http.HandlerFunc
	}{
		{
			name: "valid token reaches handler",
			setupAuth: func() string {
				token, err := jwtMgr.Generate("alice")
				if err != nil {
					// Test helper, failing here is fine
					t.Fatalf("failed to generate token: %v", err)
				}
				return "Bearer " + token
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "alice",
			handler:        usernameEchoHandler,
		},
		{
			name: "invalid token returns 401",
			setupAuth: func() string {
				return "Bearer this.is.not.a.valid.token"
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "",
			handler:        usernameEchoHandler,
		},
		{
			name: "missing Bearer prefix returns 401",
			setupAuth: func() string {
				// Create a valid token but do not include "Bearer " prefix
				token, err := jwtMgr.Generate("bob")
				if err != nil {
					t.Fatalf("failed to generate token: %v", err)
				}
				return token // Intentionally missing "Bearer "
			},
			expectedStatus: http.StatusUnauthorized,
			expectedBody:   "",
			handler:        usernameEchoHandler,
		},
		{
			name: "context propagation works end-to-end",
			setupAuth: func() string {
				token, err := jwtMgr.Generate("charlie")
				if err != nil {
					t.Fatalf("failed to generate token: %v", err)
				}
				return "Bearer " + token
			},
			expectedStatus: http.StatusOK,
			expectedBody:   "user:charlie",
			handler: func(w http.ResponseWriter, r *http.Request) {
				// Emulate deeper call stack inside handler
				_, _ = io.WriteString(w, nestedReadUsername(r.Context()))
			},
		},
	}

	for _, tc := range tests {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			authHeader := ""
			if tc.setupAuth != nil {
				authHeader = tc.setupAuth()
			}

			rr := doRequestWithAuth(jwtMgr, http.MethodGet, "/protected", authHeader, tc.handler)
			require.Equal(t, tc.expectedStatus, rr.Code, "status for %s", tc.name)

			if tc.expectedBody != "" {
				body := strings.TrimSpace(rr.Body.String())
				require.Equal(t, tc.expectedBody, body, "body for %s", tc.name)
			}
		})
	}
}
