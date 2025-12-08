package handlers

import "net/http"

// SecretsHandlerInterface defines the behavior expected from Secret handlers (real or mock)
type SecretsHandlerInterface interface {
	CreateSecret(w http.ResponseWriter, r *http.Request)
	GetSecret(w http.ResponseWriter, r *http.Request)
	UpdateSecret(w http.ResponseWriter, r *http.Request)
	DeleteSecret(w http.ResponseWriter, r *http.Request)
}
