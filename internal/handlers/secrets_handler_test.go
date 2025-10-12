package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"secretsManagerAPI/internal/auth"
)

// helper to extract a secret name from response JSON without panicking if key missing
func extractSecretName(m map[string]interface{}) string {
	if v, ok := m["secretName"].(string); ok {
		return v
	}
	if v, ok := m["name"].(string); ok {
		return v
	}
	if v, ok := m["secret_name"].(string); ok {
		return v
	}
	return ""
}

// resolveName prefers response name but falls back to mockCaptured
func resolveName(resp map[string]interface{}, mockCaptured string) string {
	if n := extractSecretName(resp); n != "" {
		return n
	}
	return mockCaptured
}

// mockClient implements K8sClient for testing.
type mockClient struct {
	createErr error
	getData   map[string]string
	getErr    error
	updateErr error
	deleteErr error

	// capture inputs
	lastNamespace string
	lastName      string
	lastData      map[string]string
}

func (m *mockClient) CreateSecret(namespace, name string, data map[string]string) error {
	m.lastNamespace = namespace
	m.lastName = name
	m.lastData = data
	return m.createErr
}

func (m *mockClient) GetSecret(namespace, name string) (map[string]string, error) {
	m.lastNamespace = namespace
	m.lastName = name
	return m.getData, m.getErr
}

func (m *mockClient) UpdateSecret(namespace, name string, data map[string]string) error {
	m.lastNamespace = namespace
	m.lastName = name
	m.lastData = data
	return m.updateErr
}

func (m *mockClient) DeleteSecret(namespace, name string) error {
	m.lastNamespace = namespace
	m.lastName = name
	return m.deleteErr
}

func TestCreateSecret_Success(t *testing.T) {
	mock := &mockClient{}
	h := NewSecretsHandler(mock)

	body := map[string]interface{}{
		"secretName": "s1",
		"name":       "s1", // also include `name` to match handler's expected field
		"data": map[string]string{
			"key": "val",
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json") // ensure handler treats body as JSON
	// inject username via auth helper
	req = req.WithContext(auth.WithUsername(context.Background(), "alice"))

	rec := httptest.NewRecorder()
	h.CreateSecret(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}

	if name := resolveName(resp, mock.lastName); name != "s1" {
		t.Fatalf("unexpected secretName: %v", name)
	}

	// verify client captured namespace
	if mock.lastNamespace != "user-alice" {
		t.Fatalf("expected namespace user-alice got %s", mock.lastNamespace)
	}
}

func TestCreateSecret_InvalidPayload(t *testing.T) {
	mock := &mockClient{}
	h := NewSecretsHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader([]byte("notjson")))
	req = req.WithContext(auth.WithUsername(context.Background(), "bob"))

	rec := httptest.NewRecorder()
	h.CreateSecret(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d got %d body=%s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestGetSecret_Success(t *testing.T) {
	mock := &mockClient{
		getData: map[string]string{"k": "v"},
	}
	h := NewSecretsHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/s1", nil)
	ctx := auth.WithUsername(context.Background(), "carol")
	ctx = auth.WithSecretName(ctx, "s1")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.GetSecret(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if name := resolveName(resp, mock.lastName); name != "s1" {
		t.Fatalf("unexpected secretName: %v", name)
	}
	data, ok := resp["data"].(map[string]interface{})
	if !ok || data["k"] != "v" {
		t.Fatalf("unexpected data: %v", resp["data"])
	}
	if mock.lastNamespace != "user-carol" {
		t.Fatalf("expected namespace user-carol got %s", mock.lastNamespace)
	}
}

func TestGetSecret_MissingSecretName(t *testing.T) {
	mock := &mockClient{}
	h := NewSecretsHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/secrets/s1", nil)
	req = req.WithContext(auth.WithUsername(context.Background(), "dave"))

	rec := httptest.NewRecorder()
	h.GetSecret(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status %d got %d body=%s", http.StatusBadRequest, rec.Code, rec.Body.String())
	}
}

func TestUpdateSecret_Success(t *testing.T) {
	mock := &mockClient{}
	h := NewSecretsHandler(mock)

	body := map[string]interface{}{
		"secretName": "s2", // handler uses secretName from context, struct's field may be ignored but include anyway
		"data": map[string]string{
			"a": "b",
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "/secrets/s2", bytes.NewReader(b))
	ctx := auth.WithUsername(context.Background(), "erin")
	ctx = auth.WithSecretName(ctx, "s2")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.UpdateSecret(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status %d got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if name := resolveName(resp, mock.lastName); name != "s2" {
		t.Fatalf("unexpected secretName: %v", name)
	}

	// verify client lastData
	expected := map[string]string{"a": "b"}
	if !reflect.DeepEqual(mock.lastData, expected) {
		t.Fatalf("expected data %v got %v", expected, mock.lastData)
	}
}

func TestDeleteSecret_Success(t *testing.T) {
	mock := &mockClient{}
	h := NewSecretsHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/secrets/s3", nil)
	ctx := auth.WithUsername(context.Background(), "frank")
	ctx = auth.WithSecretName(ctx, "s3")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	h.DeleteSecret(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected status %d got %d body=%s", http.StatusNoContent, rec.Code, rec.Body.String())
	}
}

func TestClientErrorsPropagate(t *testing.T) {
	mock := &mockClient{
		createErr: errors.New("create fail"),
		getErr:    errors.New("get fail"),
		updateErr: errors.New("update fail"),
		deleteErr: errors.New("delete fail"),
		getData:   nil,
	}
	h := NewSecretsHandler(mock)

	// Create should return 500
	createBody := map[string]interface{}{
		"secretName": "x",
		"data":       map[string]string{"k": "v"},
	}
	cb, _ := json.Marshal(createBody)
	req := httptest.NewRequest(http.MethodPost, "/secrets", bytes.NewReader(cb))
	req = req.WithContext(auth.WithUsername(context.Background(), "g"))
	rec := httptest.NewRecorder()
	h.CreateSecret(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rec.Code)
	}

	// Get should return 500
	req = httptest.NewRequest(http.MethodGet, "/secrets/x", nil)
	ctx := auth.WithUsername(context.Background(), "g")
	ctx = auth.WithSecretName(ctx, "x")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	h.GetSecret(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rec.Code)
	}

	// Update should return 500
	ub, _ := json.Marshal(createBody)
	req = httptest.NewRequest(http.MethodPut, "/secrets/x", bytes.NewReader(ub))
	ctx = auth.WithUsername(context.Background(), "g")
	ctx = auth.WithSecretName(ctx, "x")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	h.UpdateSecret(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rec.Code)
	}

	// Delete should return 500
	req = httptest.NewRequest(http.MethodDelete, "/secrets/x", nil)
	ctx = auth.WithUsername(context.Background(), "g")
	ctx = auth.WithSecretName(ctx, "x")
	req = req.WithContext(ctx)
	rec = httptest.NewRecorder()
	h.DeleteSecret(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 got %d", rec.Code)
	}
}
