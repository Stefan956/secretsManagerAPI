package models

// UserRequest represents the incoming JSON payload for user registration or login
// swagger:model UserRequest
type UserRequest struct {
	// Username chosen by the user
	Username string `json:"username" example:"stefan" validate:"required"`

	// User password (plain text, will be hashed server-side)
	Password string `json:"password" example:"P@ssw0rd123" validate:"required"`
}

// UserResponse represents the outgoing JSON response
// swagger:model UserResponse
type UserResponse struct {
	// JWT access token returned after successful login
	Token string `json:"token,omitempty" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`

	// Human-readable message describing the result
	Message string `json:"message" example:"Login successful"`
}
