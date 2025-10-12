package k8s

import (
	"fmt"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CreateSecret creates a new Kubernetes secret with multiple key-value pairs
func (c *Client) CreateSecret(namespace, name string, data map[string]string) error {
	secret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, //this must be set
		},
		StringData: data,
		Type:       v1.SecretTypeOpaque,
	}

	_, err := c.ClientSet.CoreV1().Secrets(namespace).Create(c.Context, secret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}
	return nil
}

// GetSecret retrieves a Kubernetes secret as a map[string]string
func (c *Client) GetSecret(namespace, name string) (map[string]string, error) {
	secret, err := c.ClientSet.CoreV1().Secrets(namespace).Get(c.Context, name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	result := make(map[string]string)
	for k, v := range secret.Data {
		result[k] = string(v) // convert from []byte to string
	}

	return result, nil
}

// UpdateSecret updates an existing Kubernetes secret with new key-value pairs
func (c *Client) UpdateSecret(namespace, name string, values map[string]string) error {
	secret, err := c.ClientSet.CoreV1().Secrets(namespace).Get(c.Context, name, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get secret: %w", err)
	}

	secret.StringData = values

	_, err = c.ClientSet.CoreV1().Secrets(namespace).Update(c.Context, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	return nil
}

// DeleteSecret deletes a Kubernetes secret
func (c *Client) DeleteSecret(namespace, name string) error {
	err := c.ClientSet.CoreV1().Secrets(namespace).Delete(c.Context, name, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}
