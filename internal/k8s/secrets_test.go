package k8s

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// Testing the CreateSecret, GetSecret, UpdateSecret, and DeleteSecret methods of Client
func TestCreateSecret(t *testing.T) {
	client := &Client{
		ClientSet: fake.NewSimpleClientset(),
		Context:   context.Background(),
	}

	tests := []struct {
		name        string
		namespace   string
		secretName  string
		data        map[string]string
		expectError bool
	}{
		{
			name:        "successfully creates secret",
			namespace:   "default",
			secretName:  "mysecret",
			data:        map[string]string{"key": "value"},
			expectError: false,
		},
		{
			name:        "fails to create duplicate secret",
			namespace:   "default",
			secretName:  "existing",
			data:        map[string]string{"k": "v"},
			expectError: true,
		},
	}

	// Preload a secret to trigger "duplicate" case
	_, _ = client.ClientSet.CoreV1().Secrets("default").Create(client.Context,
		&v1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "existing"}},
		metav1.CreateOptions{},
	)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.CreateSecret(tt.namespace, tt.secretName, tt.data)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				// Verify it actually exists
				secret, _ := client.ClientSet.CoreV1().Secrets(tt.namespace).Get(client.Context, tt.secretName, metav1.GetOptions{})
				assert.Equal(t, tt.data["key"], secret.StringData["key"])
			}
		})
	}
}

// Testing GetSecret function
func TestGetSecret(t *testing.T) {
	client := &Client{
		ClientSet: fake.NewSimpleClientset(),
		Context:   context.Background(),
	}

	// Create a fake secret
	secretData := map[string][]byte{"key": []byte("value")}
	_, _ = client.ClientSet.CoreV1().Secrets("default").Create(client.Context,
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "test"},
			Data:       secretData,
		}, metav1.CreateOptions{})

	tests := []struct {
		name        string
		secretName  string
		expectError bool
		expectedVal string
	}{
		{
			name:        "retrieves existing secret",
			secretName:  "test",
			expectError: false,
			expectedVal: "value",
		},
		{
			name:        "returns error for non-existent secret",
			secretName:  "missing",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := client.GetSecret("default", tt.secretName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedVal, data["key"])
			}
		})
	}
}

// Testing UpdateSecret function
func TestUpdateSecret(t *testing.T) {
	client := &Client{
		ClientSet: fake.NewSimpleClientset(),
		Context:   context.Background(),
	}

	// Create a secret first
	_, _ = client.ClientSet.CoreV1().Secrets("default").Create(client.Context,
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "to-update"},
			StringData: map[string]string{"old": "data"},
		}, metav1.CreateOptions{})

	tests := []struct {
		name        string
		secretName  string
		newData     map[string]string
		expectError bool
	}{
		{
			name:        "updates existing secret successfully",
			secretName:  "to-update",
			newData:     map[string]string{"new": "value"},
			expectError: false,
		},
		{
			name:        "fails when secret not found",
			secretName:  "missing",
			newData:     map[string]string{"x": "y"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.UpdateSecret("default", tt.secretName, tt.newData)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				secret, _ := client.ClientSet.CoreV1().Secrets("default").Get(client.Context, tt.secretName, metav1.GetOptions{})
				assert.Equal(t, tt.newData, secret.StringData)
			}
		})
	}
}

// Testing DeleteSecret function
func TestDeleteSecret(t *testing.T) {
	client := &Client{
		ClientSet: fake.NewSimpleClientset(),
		Context:   context.Background(),
	}

	// Create one to delete
	_, _ = client.ClientSet.CoreV1().Secrets("default").Create(client.Context,
		&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "to-delete"},
		}, metav1.CreateOptions{})

	tests := []struct {
		name        string
		secretName  string
		expectError bool
	}{
		{
			name:        "deletes existing secret",
			secretName:  "to-delete",
			expectError: false,
		},
		{
			name:        "returns error for non-existent secret",
			secretName:  "notfound",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := client.DeleteSecret("default", tt.secretName)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				_, err := client.ClientSet.CoreV1().Secrets("default").Get(client.Context, tt.secretName, metav1.GetOptions{})
				assert.Error(t, err)
			}
		})
	}
}
