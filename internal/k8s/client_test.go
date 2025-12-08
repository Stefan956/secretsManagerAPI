package k8s

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Testing the NewClient function with various scenarios
func TestNewClient(t *testing.T) {
	// Backup original functions
	origInCluster := inClusterConfig
	origBuild := buildConfigFromFlags
	origNewForConfig := newForConfig
	defer func() {
		inClusterConfig = origInCluster
		buildConfigFromFlags = origBuild
		newForConfig = origNewForConfig
	}()

	mockConfig := &rest.Config{}

	tests := []struct {
		name          string
		inClusterErr  error
		buildErr      error
		newForErr     error
		expectError   bool
		expectMessage string
	}{
		{
			name:         "in-cluster config works",
			inClusterErr: nil,
			expectError:  false,
		},
		{
			name:          "in-cluster fails, fallback also fails",
			inClusterErr:  errors.New("no cluster"),
			buildErr:      errors.New("missing kubeconfig"),
			expectError:   true,
			expectMessage: "failed to load kubeconfig",
		},
		{
			name:         "in-cluster fails, fallback succeeds",
			inClusterErr: errors.New("no cluster"),
			expectError:  false,
		},
		{
			name:          "clientset creation fails",
			inClusterErr:  nil,
			newForErr:     errors.New("bad config"),
			expectError:   true,
			expectMessage: "bad config",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock functions
			inClusterConfig = func() (*rest.Config, error) {
				return mockConfig, tt.inClusterErr
			}
			buildConfigFromFlags = func(_, _ string) (*rest.Config, error) {
				if tt.buildErr != nil {
					return nil, tt.buildErr
				}
				return mockConfig, nil
			}
			newForConfig = func(_ *rest.Config) (*kubernetes.Clientset, error) {
				if tt.newForErr != nil {
					return nil, tt.newForErr
				}
				return nil, nil // no real client
			}

			client, err := NewClient(context.Background())

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectMessage)
				assert.Nil(t, client)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
				assert.Equal(t, context.Background(), client.Context)
			}
		})
	}
}
