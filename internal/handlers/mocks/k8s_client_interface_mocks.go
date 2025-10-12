package mocks

import (
	"encoding/json"
	"fmt"
	"net/http"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/models"

	"golang.org/x/crypto/bcrypt"
)

type MockHandler struct {
	JWTManager auth.JWTGenerator
	Client     *MockClient
}

// MockClient implements K8sClient interface for tests
type MockClient struct {
	secrets map[string]map[string]map[string]string // namespace -> secretName -> data
}

func NewMockClient() *MockClient {
	return &MockClient{secrets: make(map[string]map[string]map[string]string)}
}

func (m *MockClient) CreateSecret(namespace, name string, data map[string]string) error {
	if m.secrets[namespace] == nil {
		m.secrets[namespace] = make(map[string]map[string]string)
	}
	copied := make(map[string]string)
	for k, v := range data {
		copied[k] = v
	}
	m.secrets[namespace][name] = copied

	return nil
}

func (m *MockClient) GetSecret(namespace, name string) (map[string]string, error) {
	if nsMap, ok := m.secrets[namespace]; ok {
		if data, ok := nsMap[name]; ok {
			copied := make(map[string]string)
			for k, v := range data {
				copied[k] = v
			}
			return copied, nil
		}
	}

	return nil, fmt.Errorf("secret not found")
}

func (m *MockClient) UpdateSecret(namespace, name string, data map[string]string) error {
	if nsMap, ok := m.secrets[namespace]; ok {
		if _, ok := nsMap[name]; ok {
			copied := make(map[string]string)
			for k, v := range data {
				copied[k] = v
			}
			nsMap[name] = copied
			return nil
		}
	}

	return fmt.Errorf("secret not found")
}

func (m *MockClient) DeleteSecret(namespace, name string) error {
	if nsMap, ok := m.secrets[namespace]; ok {
		if _, ok := nsMap[name]; ok {
			delete(nsMap, name)
			return nil
		}
	}
	return fmt.Errorf("secret not found")
}

// Register simulates registering a new user by storing credentials in mockClient
func (h *MockHandler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	namespace := "user-" + req.Username

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	creds := map[string]string{
		"username": req.Username,
		"password": string(hash),
	}

	if err := h.Client.CreateSecret(namespace, "credentials", creds); err != nil {
		http.Error(w, "Failed to store credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.UserResponse{
		Message: "User registered successfully",
	})
}

// Login simulates logging in by checking credentials in mockClient
func (h *MockHandler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.UserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	namespace := "user-" + req.Username

	secretData, err := h.Client.GetSecret(namespace, "credentials")
	if err != nil {
		http.Error(w, "User does not exist", http.StatusUnauthorized)
		return
	}

	storedHash, ok := secretData["password"]
	if !ok {
		http.Error(w, "Credentials not found", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	token, err := h.JWTManager.Generate(req.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.UserResponse{
		Token:   token,
		Message: "Login successful",
	})
}

func (h *MockHandler) ChangeUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the current username from context (mocking JWT middleware)
	username, ok := auth.UsernameFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	namespace := "user-" + username

	// Get existing credentials
	secretData, err := h.Client.GetSecret(namespace, "credentials")
	if err != nil {
		http.Error(w, "Failed to get current credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update password if provided
	if req.NewPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
			return
		}
		secretData["password"] = string(hash)
	}

	// Save updated credentials back to mock client
	if err := h.Client.UpdateSecret(namespace, "credentials", secretData); err != nil {
		http.Error(w, "Failed to update credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.UserResponse{
		Message: "User details updated successfully",
	})
}
