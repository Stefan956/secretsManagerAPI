package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers/mocks"

	"golang.org/x/crypto/bcrypt"
)

// TestUserHandler_Register_Success - table driven tests for Register success cases
func TestUserHandler_Register_Success(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
	}{
		{"simple", "alice", "pass1"},
		{"another", "bob", "s3cr3t"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := mocks.NewMockK8sClient()
			jwt := &mocks.MockJWTManager{Token: "mockToken", GenerateErr: nil}

			handler := &UserHandler{
				JWTManager: jwt,
				Client:     client,
			}

			body := map[string]string{
				"username": tt.username,
				"password": tt.password,
			}
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("failed to marshal body for test %q: %v", tt.name, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
			rec := httptest.NewRecorder()

			handler.Register(rec, req)

			if rec.Code != http.StatusCreated {
				t.Fatalf("expected status %d got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
			}

			// verify CreateSecret was called and stored credentials under the namespace
			if !client.CreateSecretCalled {
				t.Fatalf("expected create secret to be called")
			}

			// validate stored secret
			key := "user-" + tt.username + "/credentials"

			sec, ok := client.Secrets[key]
			if !ok {
				t.Fatalf("expected secret %s to exist", key)
			}

			if sec.Data["username"] != tt.username {
				t.Fatalf("expected username=%s got %s",
					tt.username, sec.Data["username"])
			}

			// password should be a bcrypt hash (non-empty)
			if len(sec.Data["password"]) == 0 {
				t.Fatalf("password hash missing")
			}

			if err := bcrypt.CompareHashAndPassword([]byte(sec.Data["password"]), []byte(tt.password)); err != nil {
				t.Fatalf("stored password hash does not match provided password: %v", err)
			}
		})
	}
}

// TestUserHandler_Handler_Success - table driven tests for Login and ChangeUserPassword
func TestUserHandler_Handler_Success(t *testing.T) {
	tests := []struct {
		name           string
		handler        string // "login" or "change_password"
		username       string
		password       string
		newPassword    string
		expectCode     int
		expectToken    string // for login
		expectPassword func(oldHash, newHash string) bool
	}{
		{
			name:        "login_success",
			handler:     "login",
			username:    "alice",
			password:    "mypw",
			expectCode:  http.StatusOK,
			expectToken: "tok-123",
		},
		{
			name:        "change_password_success",
			handler:     "change_password",
			username:    "alice",
			password:    "oldpw",
			newPassword: "newpw",
			expectCode:  http.StatusOK,
			// verify that password was changed (hash differs and matches new password)
			expectPassword: func(oldHash, newHash string) bool {
				if oldHash == newHash {
					return false
				}
				return bcrypt.CompareHashAndPassword([]byte(newHash), []byte("newpw")) == nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := mocks.NewMockK8sClient()

			// prepare credentials secret with bcrypt hash of tt.password
			hash, err := bcrypt.GenerateFromPassword([]byte(tt.password), bcrypt.DefaultCost)
			if err != nil {
				t.Fatalf("failed to generate bcrypt hash for password %q: %v", tt.password, err)
			}

			key := "user-" + tt.username + "/credentials"
			mock.Secrets[key] = mocks.ExampleSecret{
				Namespace: "user-" + tt.username,
				Name:      "credentials",
				Data: map[string]string{
					"username": tt.username,
					"password": string(hash),
				},
			}

			jwt := &mocks.MockJWTManager{Token: "tok-123", GenerateErr: nil}
			h := &UserHandler{
				JWTManager: jwt,
				Client:     mock,
			}

			switch tt.handler {
			case "login":
				body := map[string]string{
					"username": tt.username,
					"password": tt.password,
				}
				b, err := json.Marshal(body)
				if err != nil {
					t.Fatalf("failed to marshal body for test %q: %v", tt.name, err)
				}

				req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
				rec := httptest.NewRecorder()

				h.Login(rec, req)

				if rec.Code != tt.expectCode {
					t.Fatalf("expected status %d got %d body=%s", tt.expectCode, rec.Code, rec.Body.String())
				}

				var resp map[string]interface{}
				if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
					t.Fatalf("invalid response JSON: %v", err)
				}
				if token, ok := resp["token"].(string); !ok || token != tt.expectToken {
					t.Fatalf("expected token %q got %v", tt.expectToken, resp["token"])
				}

			case "change_password":
				// Inject username into context (middleware would do this)
				body := map[string]string{
					"new_password": tt.newPassword,
				}

				b, err := json.Marshal(body)
				if err != nil {
					t.Fatalf("failed to marshal body for test %q: %v", tt.name, err)
				}

				req := httptest.NewRequest(http.MethodPut, "/user/password", bytes.NewReader(b))
				req = req.WithContext(auth.WithUsername(context.Background(), tt.username))

				rec := httptest.NewRecorder()

				// capture old hash
				oldHash := mock.Secrets[key].Data["password"]

				h.ChangeUserPassword(rec, req)

				if rec.Code != tt.expectCode {
					t.Fatalf("expected status %d got %d body=%s", tt.expectCode, rec.Code, rec.Body.String())
				}

				if !mock.UpdateSecretCalled {
					t.Fatalf("expected UpdateSecret to be called")
				}

				newHash := mock.Secrets[key].Data["password"]

				if tt.expectPassword != nil && !tt.expectPassword(oldHash, newHash) {
					t.Fatalf("password expectation failed; oldHash=%s newHash=%s", oldHash, newHash)
				}

			default:
				t.Fatalf("unknown handler %s", tt.handler)
			}
		})
	}
}
