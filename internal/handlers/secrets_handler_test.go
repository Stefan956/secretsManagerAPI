package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers/mocks"
	"secretsManagerAPI/internal/models"
	"testing"
)

// use the auth package keys to inject into request context
var (
	userKey   = auth.UsernameKey
	secretKey = auth.SecretNameKey
)

func withUser(ctx context.Context, username string) context.Context {
	return context.WithValue(ctx, userKey, username)
}

func withSecret(ctx context.Context, secret string) context.Context {
	return context.WithValue(ctx, secretKey, secret)
}

// Testing - Create Secret
func TestSecretsHandler_CreateSecret(t *testing.T) {
	tests := []struct {
		name           string
		body           map[string]any
		forceError     error
		expectedStatus int
	}{
		{
			name: "success",
			body: map[string]any{
				"secretName": "api-key",
				"data": map[string]any{
					"token": "1234",
				},
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "missing secret name",
			body: map[string]any{
				"data": map[string]string{"a": "b"},
			},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "create fails",
			body: map[string]any{
				"secretName": "x",
				"data":       map[string]string{"a": "b"},
			},
			forceError:     errors.New("k8s error"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := mocks.NewMockK8sClient()
			mock.CreateErr = tt.forceError

			handler := &SecretsHandler{Client: mock}

			bodyBytes, err := json.Marshal(tt.body)
			if err != nil {
				t.Fatalf("failed to marshal body for test %q: %v", tt.name, err)
			}

			req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(bodyBytes))
			req = req.WithContext(withUser(req.Context(), "alice"))

			rec := httptest.NewRecorder()
			handler.CreateSecret(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Fatalf("expected %d got %d. Body: %s", tt.expectedStatus, rec.Code, rec.Body.String())
			}

			if tt.expectedStatus == http.StatusCreated && !mock.CreateSecretCalled {
				t.Fatalf("expected CreateSecret to be called")
			}
		})
	}
}

// Testing - Get Secret
func TestSecretsHandler_GetSecret(t *testing.T) {
	mock := mocks.NewMockK8sClient()

	// Build key using flat format
	ns := "user-alice"
	secretName := "api-key"
	key := ns + "/" + secretName

	mock.Secrets[key] = mocks.ExampleSecret{
		Namespace: ns,
		Name:      secretName,
		Data:      map[string]string{"token": "1234"},
	}

	handler := &SecretsHandler{Client: mock}

	req := httptest.NewRequest(http.MethodGet, "/secrets/api-key", nil)
	req = req.WithContext(withUser(req.Context(), "alice"))
	req = req.WithContext(withSecret(req.Context(), secretName))

	rec := httptest.NewRecorder()
	handler.GetSecret(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d; body=%s", rec.Code, rec.Body.String())
	}

	if !mock.GetSecretCalled {
		t.Fatalf("expected GetSecret to be called")
	}

	var resp models.SecretResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response JSON: %v; body=%s", err, rec.Body.String())
	}

	if resp.SecretName != "api-key" {
		t.Fatalf("wrong secret name")
	}
	if resp.Data["token"] != "1234" {
		t.Fatalf("wrong secret data")
	}
}

// Testing - Update Secret
func TestSecretsHandler_UpdateSecret(t *testing.T) {
	mock := mocks.NewMockK8sClient()

	ns := "user-bob"
	secretName := "api-key"
	key := ns + "/" + secretName

	mock.Secrets[key] = mocks.ExampleSecret{
		Namespace: ns,
		Name:      secretName,
		Data:      map[string]string{"token": "old"},
	}

	handler := &SecretsHandler{Client: mock}

	reqBody := models.SecretRequest{Data: map[string]string{"token": "new"}}
	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("failed to marshal body for test Update Secret: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/secrets/api-key", bytes.NewReader(bodyBytes))
	req = req.WithContext(withUser(req.Context(), "bob"))
	req = req.WithContext(withSecret(req.Context(), secretName))

	rec := httptest.NewRecorder()
	handler.UpdateSecret(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 got %d; body=%s", rec.Code, rec.Body.String())
	}

	if !mock.UpdateSecretCalled {
		t.Fatalf("expected UpdateSecret to be called")
	}

	updated, _ := mock.GetSecret("user-bob", "api-key")
	if updated["token"] != "new" {
		t.Fatalf("secret update failed; got %v", updated)
	}
}

// Testing - Delete secret
func TestSecretsHandler_DeleteSecret(t *testing.T) {
	mock := mocks.NewMockK8sClient()

	ns := "user-alice"
	secretName := "session"
	key := ns + "/" + secretName

	mock.Secrets[key] = mocks.ExampleSecret{
		Namespace: ns,
		Name:      secretName,
		Data:      map[string]string{"token": "abc"},
	}

	handler := &SecretsHandler{Client: mock}

	req := httptest.NewRequest(http.MethodDelete, "/secrets/session", nil)
	req = req.WithContext(withUser(req.Context(), "alice"))
	req = req.WithContext(withSecret(req.Context(), secretName))

	rec := httptest.NewRecorder()
	handler.DeleteSecret(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 got %d; body=%s", rec.Code, rec.Body.String())
	}

	if !mock.DeleteSecretCalled {
		t.Fatalf("expected DeleteSecret to be called")
	}

	if _, exists := mock.Secrets[key]; exists {
		t.Fatalf("secret should be deleted")
	}
}
