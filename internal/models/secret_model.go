package models

// SecretRequest represents the payload for creating or updating a secret
// swagger:model SecretRequest
type SecretRequest struct {
	// Name of the secret
	SecretName string `json:"secret-name" example:"db-credentials" validate:"required"`

	// Arbitrary key-value pairs stored in the secret
	Data map[string]string `json:"data" example:"{\"username\":\"admin\",\"password\":\"s3cr3t\"}" validate:"required"`
}

// SecretResponse represents a secret returned by the API
// swagger:model SecretResponse
type SecretResponse struct {
	// Name of the secret
	// example: db-credentials
	SecretName string `json:"secret-name"`

	// Key-value pairs stored in the secret
	// example: {"username":"admin","password":"s3cr3t"}
	Data map[string]string `json:"data"`
}

// SecretListResponse represents a list of secret names in a namespace
// swagger:model SecretListResponse
type SecretListResponse struct {
	// List of secret names
	Secrets []string `json:"secrets" example:"db-credentials,api-key"`
}
