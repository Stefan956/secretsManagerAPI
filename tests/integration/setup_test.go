package integration

import (
	"os"
	"testing"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var (
	testEnv   *envtest.Environment
	cfg       *rest.Config
	clientset kubernetes.Interface
)

// Testing entry point
func TestMain(m *testing.M) {
	// Boots a real API server + etcd in memory
	testEnv = &envtest.Environment{}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		panic(err)
	}

	// Builds a K8s client that talks to the fake cluster
	clientset, err = kubernetes.NewForConfig(cfg)
	if err != nil {
		panic(err)
	}

	code := m.Run()

	if testEnv != nil {
		if err := testEnv.Stop(); err != nil {
			panic(err)
		}
	}
	os.Exit(code)
}
