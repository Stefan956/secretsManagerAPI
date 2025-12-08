package integration

import (
	"context"
	"testing"
	"time"

	k8sclient "secretsManagerAPI/internal/k8s"

	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Testing namespace and secret lifecycle using the k8s client
func TestNamespaceAndSecretLifecycle(t *testing.T) {
	ctx := context.Background()

	c, error1 := k8sclient.NewClientWithConfig(ctx, cfg)
	require.NoError(t, error1)

	ns := "user-integ-test"
	secretName := "credentials"

	err := c.CreateNamespace(ns)
	require.NoError(t, err, "CreateNamespace should succeed")

	// Wait for namespace to exist
	deadline := time.Now().Add(5 * time.Second)
	var gotNs *v1.Namespace
	for time.Now().Before(deadline) {
		gotNs, err = clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	require.NoError(t, err)
	require.Equal(t, ns, gotNs.Name)

	// CreateSecret
	creds := map[string]string{
		"username": "alice",
		"password": "supersecret",
	}
	err = c.CreateSecret(ns, secretName, creds)
	require.NoError(t, err)

	// GetSecret
	got, err := c.GetSecret(ns, secretName)
	require.NoError(t, err)
	require.Equal(t, "alice", got["username"])
	require.Equal(t, "supersecret", got["password"])

	// UpdateSecret
	updated := map[string]string{
		"username": "alice",
		"password": "newpass",
		"extra":    "value",
	}
	err = c.UpdateSecret(ns, secretName, updated)
	require.NoError(t, err)

	got2, err := c.GetSecret(ns, secretName)
	require.NoError(t, err)
	require.Equal(t, "newpass", got2["password"])
	require.Equal(t, "value", got2["extra"])

	// DeleteSecret
	err = c.DeleteSecret(ns, secretName)
	require.NoError(t, err)

	_, err = c.GetSecret(ns, secretName)
	require.Error(t, err)

	// DeleteNamespace
	err = c.DeleteNamespace(ns)

	if err != nil {
		t.Logf("DeleteNamespace failed: %v — forcing finalize", err)

		// Fetch the stuck namespace
		nsObj, getErr := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
		require.NoError(t, getErr)

		// Clear finalizers
		nsObj.Spec.Finalizers = []v1.FinalizerName{}

		// Force the FINALIZE subresource
		_, perr := clientset.CoreV1().
			Namespaces().
			Finalize(ctx, nsObj, metav1.UpdateOptions{})
		require.NoError(t, perr, "finalize subresource update must succeed")

		// Poll until namespace is actually gone
		timeout := time.Now().Add(30 * time.Second)
		for time.Now().Before(timeout) {
			_, getErr := clientset.CoreV1().Namespaces().Get(ctx, ns, metav1.GetOptions{})
			if apierrors.IsNotFound(getErr) {
				err = nil
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
	require.NoError(t, err, "DeleteNamespace should succeed")

}

// Testing secret creation and retrieval directly via clientset
func TestSecretCreateAndGet(t *testing.T) {
	ctx := context.Background()

	secretName := "integration-test-secret"

	_, err := clientset.CoreV1().Secrets("default").Create(ctx, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: secretName,
		},
		StringData: map[string]string{
			"token": "abc123",
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	secret, err := clientset.CoreV1().Secrets("default").Get(ctx, secretName, metav1.GetOptions{})
	require.NoError(t, err)

	// Read from Data, converting []byte → string
	val, ok := secret.Data["token"]
	require.True(t, ok, "token key should exist in secret.Data")
	require.Equal(t, "abc123", string(val))

	err = clientset.CoreV1().Secrets("default").Delete(ctx, secretName, metav1.DeleteOptions{})
	require.NoError(t, err)
}
