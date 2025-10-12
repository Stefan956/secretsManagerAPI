package models

// UserRequest represents the incoming JSON payload for user registration/login
type UserRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// UserResponse represents the outgoing JSON response
type UserResponse struct {
	Token   string `json:"token,omitempty"`
	Message string `json:"message"`
}
