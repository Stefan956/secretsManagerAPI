package mocks

import (
	"errors"
	"fmt"
	"strings"
)

// MockK8sClient implements the handlers.K8sClient interface for tests.
type MockK8sClient struct {
	// call flags for assertions
	CreateSecretCalled bool
	GetSecretCalled    bool
	UpdateSecretCalled bool
	DeleteSecretCalled bool

	// forceable errors (set in tests)
	CreateErr error
	GetErr    error
	UpdateErr error
	DeleteErr error

	// Key - namespace/name
	Secrets map[string]ExampleSecret
}

type ExampleSecret struct {
	Namespace string
	Name      string
	Data      map[string]string
}

// helper: build a single unique key for a secret in K8s style: "<namespace>/<name>"
func makeKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

func NewMockK8sClient() *MockK8sClient {
	return &MockK8sClient{
		Secrets: make(map[string]ExampleSecret),
	}
}

// cloneMap returns a copy of the provided map[string]string (defensive copy).
func cloneMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// CreateSecret simulates creating (or replacing) a Kubernetes secret.
func (m *MockK8sClient) CreateSecret(namespace, name string, data map[string]string) error {
	m.CreateSecretCalled = true
	if m.CreateErr != nil {
		return m.CreateErr
	}
	if m.Secrets == nil {
		m.Secrets = make(map[string]ExampleSecret)
	}

	key := makeKey(namespace, name)
	m.Secrets[key] = ExampleSecret{
		Namespace: namespace,
		Name:      name,
		Data:      cloneMap(data),
	}
	return nil
}

// GetSecret returns a copy of the secret's data, or an error if not found.
func (m *MockK8sClient) GetSecret(namespace, name string) (map[string]string, error) {
	m.GetSecretCalled = true
	if m.GetErr != nil {
		return nil, m.GetErr
	}
	if m.Secrets == nil {
		return nil, errors.New("not found")
	}

	key := makeKey(namespace, name)
	sec, ok := m.Secrets[key]
	if !ok {
		return nil, fmt.Errorf("secret %s not found", key)
	}

	return cloneMap(sec.Data), nil
}

// UpdateSecret updates an existing secret. Returns error if the secret does not exist.
func (m *MockK8sClient) UpdateSecret(namespace, name string, data map[string]string) error {
	m.UpdateSecretCalled = true
	if m.UpdateErr != nil {
		return m.UpdateErr
	}
	if m.Secrets == nil {
		return fmt.Errorf("secret %s/%s not found", namespace, name)
	}

	key := makeKey(namespace, name)
	if _, ok := m.Secrets[key]; !ok {
		return fmt.Errorf("secret %s not found", key)
	}

	m.Secrets[key] = ExampleSecret{
		Namespace: namespace,
		Name:      name,
		Data:      cloneMap(data),
	}
	return nil
}

// DeleteSecret deletes a secret; returns error if not found.
func (m *MockK8sClient) DeleteSecret(namespace, name string) error {
	m.DeleteSecretCalled = true
	if m.DeleteErr != nil {
		return m.DeleteErr
	}
	if m.Secrets == nil {
		return fmt.Errorf("secret %s/%s not found", namespace, name)
	}

	key := makeKey(namespace, name)
	if _, ok := m.Secrets[key]; !ok {
		return fmt.Errorf("secret %s not found", key)
	}

	delete(m.Secrets, key)
	return nil
}

// CreateNamespace is a no-op in the flat-map mock. Namespaces are not stored separately.
func (m *MockK8sClient) CreateNamespace(name string) error {
	// No-op: we don't maintain a separate namespaces collection in the flat-key mock.
	return nil
}

// DeleteNamespace removes all secrets in the given namespace.
func (m *MockK8sClient) DeleteNamespace(name string) error {
	if m.Secrets == nil {
		return nil
	}
	prefix := name + "/"
	for k := range m.Secrets {
		if strings.HasPrefix(k, prefix) {
			delete(m.Secrets, k)
		}
	}
	return nil
}
