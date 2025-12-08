package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/k8s"

	"secretsManagerAPI/internal/models"

	"golang.org/x/crypto/bcrypt"
)

// UserHandler handles user registration and login
type UserHandler struct {
	JWTManager auth.JWTGenerator
	Client     k8s.K8sClient
}

// NewUserHandler creates a new UserHandler
func NewUserHandler(client k8s.K8sClient, jwtManager auth.JWTGenerator) *UserHandler {
	return &UserHandler{
		JWTManager: jwtManager,
		Client:     client,
	}
}

// Register creates a new user namespace and stores credentials in a secret
func (h *UserHandler) Register(w http.ResponseWriter, r *http.Request) {
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

	// Create user namespace
	if err := h.Client.CreateNamespace("user-" + req.Username); err != nil {
		http.Error(w, "Failed to create namespace: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	// Store credentials in a secret (username + hashed password)
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

// Login validates user credentials and returns a JWT token
func (h *UserHandler) Login(w http.ResponseWriter, r *http.Request) {
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

	// Get credentials from secret
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

	// Compare password
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := h.JWTManager.Generate(req.Username)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(models.UserResponse{
		Token:   token,
		Message: "Login successful",
	}); err != nil {
		fmt.Println("failed to write response:", err) // log it
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

}

// ChangeUserPassword allows a user to change their password
func (h *UserHandler) ChangeUserPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get the current username from JWTMiddleware context
	currentUsername, ok := auth.UsernameFromContext(r.Context())
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

	// Work in user namespace
	namespace := "user-" + currentUsername

	// Get credentials secret
	secretData, err := h.Client.GetSecret(namespace, "credentials")
	if err != nil {
		http.Error(w, "Failed to get current credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// If new password provided → hash and update
	if req.NewPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
			return
		}
		secretData["password"] = string(hash)
	}

	// Update secret
	if err := h.Client.UpdateSecret(namespace, "credentials", secretData); err != nil {
		http.Error(w, "Failed to update credentials: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.UserResponse{
		Message: "User details updated successfully",
	})
}

// DeleteUser deletes the user namespace and all associated resources
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get username from JWT context
	username, ok := auth.UsernameFromContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	//namespace := "user-" + username

	// Delete namespace (which deletes all secrets/resources)
	if err := h.Client.DeleteNamespace("user-" + username); err != nil {
		http.Error(w, "Failed to delete user namespace: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.UserResponse{
		Message: "User deleted successfully",
	})
}
