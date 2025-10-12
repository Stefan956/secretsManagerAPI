package handlers

// K8sClient defines the methods used by SecretsHandler so it can be mocked in tests.
type K8sClient interface {
	CreateSecret(namespace, name string, data map[string]string) error
	GetSecret(namespace, name string) (map[string]string, error)
	UpdateSecret(namespace, name string, data map[string]string) error
	DeleteSecret(namespace, name string) error
}
