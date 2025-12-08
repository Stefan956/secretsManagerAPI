package mocks

import "secretsManagerAPI/internal/auth"

type MockJWTManager struct {
	Token       string
	VerifyUser  string
	GenerateErr error
	VerifyErr   error
	Claims      *auth.Claims
}

func (m *MockJWTManager) Generate(username string) (string, error) {
	return m.Token, m.GenerateErr
}

func (m *MockJWTManager) Verify(token string) (*auth.Claims, error) {
	return m.Claims, m.VerifyErr
}
