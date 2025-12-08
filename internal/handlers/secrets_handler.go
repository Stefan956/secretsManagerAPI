package handlers

import (
	"encoding/json"
	"net/http"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/k8s"
	"secretsManagerAPI/internal/models"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// SecretsHandler handles CRUD for secrets
type SecretsHandler struct {
	Client k8s.K8sClient
}

// NewSecretsHandler creates a new SecretsHandler
func NewSecretsHandler(client k8s.K8sClient) *SecretsHandler {
	return &SecretsHandler{
		Client: client,
	}
}

// CreateSecret handles POST /secrets
func (h *SecretsHandler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	username, ok := auth.GetUsername(r.Context())
	if !ok {
		http.Error(w, "username not found in context", http.StatusInternalServerError)
		return
	}

	// Read body into a generic map so we don't depend on struct tags in models.SecretRequest.
	var raw map[string]any
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	// Try several possible keys for the secret name.
	var name string
	if v, ok := raw["secretName"].(string); ok && v != "" {
		name = v
	} else if v, ok := raw["name"].(string); ok && v != "" {
		name = v
	} else if v, ok := raw["secret_name"].(string); ok && v != "" {
		name = v
	} else if v, ok := raw["secret-name"].(string); ok && v != "" {
		name = v
	}

	if name == "" {
		http.Error(w, "secret name missing", http.StatusBadRequest)
		return
	}

	// Extract data field (accept either map[string]string or map[string]interface{}).
	var data map[string]string
	if d, ok := raw["data"].(map[string]any); ok {
		data = make(map[string]string, len(d))
		for kk, vv := range d {
			// convert values to strings
			if s, ok := vv.(string); ok {
				data[kk] = s
			} else {
				// non-string value: marshal and store as string representation
				bs, _ := json.Marshal(vv)
				data[kk] = string(bs)
			}
		}
	} else if d2, ok := raw["data"].(map[string]string); ok {
		data = d2
	} else {
		data = map[string]string{} // tolerate missing/empty data
	}

	namespace := "user-" + username

	if err := h.Client.CreateSecret(namespace, name, data); err != nil {
		http.Error(w, "failed to create secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(models.SecretResponse{
		SecretName: name,
		Data:       data,
	})
}

// GetSecret handles GET /secrets/{name}
func (h *SecretsHandler) GetSecret(w http.ResponseWriter, r *http.Request) {
	username, ok := auth.GetUsername(r.Context())
	if !ok {
		http.Error(w, "username not found in context", http.StatusInternalServerError)
		return
	}

	secretName, ok := auth.GetSecretName(r.Context())
	if !ok {
		http.Error(w, "secret name missing", http.StatusBadRequest)
		return
	}

	namespace := "user-" + username

	secretData, err := h.Client.GetSecret(namespace, secretName)
	if err != nil {
		// Check for "Not Found" error specifically
		if apierrors.IsNotFound(err) {
			http.Error(w, "Secret not found in your namespace", http.StatusNotFound) // Return 404
			return
		}

		// For all other errors (e.g., RBAC failure, connection issue), return 500
		http.Error(w, "failed to get secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(models.SecretResponse{
		SecretName: secretName,
		Data:       secretData,
	})
}

// UpdateSecret handles PUT /secrets/{name}
func (h *SecretsHandler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	username, ok := auth.GetUsername(r.Context())
	if !ok {
		http.Error(w, "username not found in context", http.StatusInternalServerError)
		return
	}

	secretName, ok := auth.GetSecretName(r.Context())
	if !ok {
		http.Error(w, "secret name missing", http.StatusBadRequest)
		return
	}

	var req models.SecretRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request payload", http.StatusBadRequest)
		return
	}

	namespace := "user-" + username

	if err := h.Client.UpdateSecret(namespace, secretName, req.Data); err != nil {
		http.Error(w, "failed to update secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.SecretResponse{
		SecretName: secretName,
		Data:       req.Data,
	})
}

// DeleteSecret handles DELETE /secrets/{name}
func (h *SecretsHandler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	username, ok := auth.GetUsername(r.Context())
	if !ok {
		http.Error(w, "username not found in context", http.StatusInternalServerError)
		return
	}

	secretName, ok := auth.GetSecretName(r.Context())
	if !ok {
		http.Error(w, "secret name missing", http.StatusBadRequest)
		return
	}

	namespace := "user-" + username

	if err := h.Client.DeleteSecret(namespace, secretName); err != nil {
		http.Error(w, "failed to delete secret: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
