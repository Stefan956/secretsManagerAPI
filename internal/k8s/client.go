package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type Client struct {
	//ClientSet *kubernetes.Clientset
	ClientSet kubernetes.Interface
	Context   context.Context
}

func NewClient(ctx context.Context) (*Client, error) {
	//config, err := rest.InClusterConfig()
	//if err != nil {
	//	return nil, err
	//}

	// Try in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		// Fallback to kubeconfig
		kubeconfig := filepath.Join(os.Getenv("HOME"), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	return &Client{ClientSet: clientset,
		Context: ctx}, nil
}
