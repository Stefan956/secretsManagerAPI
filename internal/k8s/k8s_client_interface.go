package k8s

// K8sClient defines the methods used by SecretsHandler so it can be mocked in tests.
// This interface isolates Kubernetes-specific logic inside the k8s package,
// so that the handlers no longer manipulates raw Kubernetes clients directly
type K8sClient interface {
	CreateSecret(namespace, name string, data map[string]string) error
	GetSecret(namespace, name string) (map[string]string, error)
	UpdateSecret(namespace, name string, data map[string]string) error
	DeleteSecret(namespace, name string) error

	CreateNamespace(name string) error
	DeleteNamespace(name string) error
}
