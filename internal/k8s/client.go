package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

// Adding the following variables, so that the code can be tested
var (
	inClusterConfig      = rest.InClusterConfig
	buildConfigFromFlags = clientcmd.BuildConfigFromFlags
	newForConfig         = kubernetes.NewForConfig
)

type Client struct {
	ClientSet kubernetes.Interface
	Context   context.Context
}

// NewClient creates a new Kubernetes client. It first tries to create an in-cluster config
func NewClient(ctx context.Context) (*Client, error) {
	config, err := inClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err = buildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}
	}

	clientset, err := newForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{ClientSet: clientset, Context: ctx}, nil
}

// NewClientWithConfig Function to use injected config for testing
func NewClientWithConfig(ctx context.Context, config *rest.Config) (*Client, error) {
	clientset, err := newForConfig(config)
	if err != nil {
		return nil, err
	}
	return &Client{ClientSet: clientset, Context: ctx}, nil
}

func (c *Client) CreateNamespace(name string) error {
	ctx := context.Background()
	if c.Context != nil {
		ctx = c.Context
	}

	ns := &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	_, err := c.ClientSet.CoreV1().Namespaces().Create(ctx, ns, metav1.CreateOptions{})
	if err != nil {
		// If already exists, treat as success
		if apierrors.IsAlreadyExists(err) {
			return nil
		}
		return fmt.Errorf("failed to create namespace %q: %w", name, err)
	}

	// wait for namespace to become Active before returning
	// short timeout to avoid blocking too long
	timeout := 10 * time.Second
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		got, err := c.ClientSet.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if err == nil && got.Status.Phase == v1.NamespaceActive {
			return nil
		}
		// if Get returns NotFound keep retrying
		time.Sleep(200 * time.Millisecond)
	}

	// Namespace created but did not become Active within timeout
	return fmt.Errorf("namespace %q did not become Active within %s", name, timeout)
}

// DeleteNamespace deletes the namespace with the given name and waits until it is fully deleted
func (c *Client) DeleteNamespace(name string) error {
	ctx := context.Background()
	if c.Context != nil {
		ctx = c.Context
	}

	err := c.ClientSet.CoreV1().Namespaces().Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("failed to delete namespace %q: %w", name, err)
	}
	// poll until namespace disappears
	timeout := 30 * time.Second
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		_, err := c.ClientSet.CoreV1().Namespaces().Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("namespace %q was not deleted after %s", name, timeout)
}
