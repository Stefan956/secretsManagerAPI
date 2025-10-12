package models

// SecretRequest represents the payload for creating or updating a secret
type SecretRequest struct {
	SecretName string            `json:"secret-name" binding:"required"` // Secret name
	Data       map[string]string `json:"data" binding:"required"`        // Arbitrary key/values
}

// SecretResponse represents a secret returned by the API
type SecretResponse struct {
	SecretName string            `json:"secret-name"` // Secret name
	Data       map[string]string `json:"data"`        // Key/value pairs
}

// SecretListResponse represents a list of secret names in a namespace
type SecretListResponse struct {
	Secrets []string `json:"secrets"`
}
