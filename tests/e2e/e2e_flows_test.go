package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers"
	"secretsManagerAPI/internal/k8s"
	"secretsManagerAPI/internal/models"
	"secretsManagerAPI/internal/server"

	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/clientcmd"
)

// Helper: build a rest.Config from KUBECONFIG (or default)
func mustKubeConfig(t *testing.T) string {
	// prefer KUBECONFIG env if set (Kind script sets it), else default
	if v := os.Getenv("KUBECONFIG"); v != "" {
		return v
	}
	home := os.Getenv("HOME")
	return filepath.Join(home, ".kube", "config")
}

// Helper: start the HTTP server wired with real handlers talking to the given k8s config.
// Returns server URL and a teardown func.
func startAPIServer(t *testing.T, kubeconfigPath string) (baseURL string, teardown func()) {
	t.Helper()

	// Build client config
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	require.NoError(t, err)

	// Create real k8s client for handlers
	k8sClient, err := k8s.NewClientWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	// Create real JWT manager (shared secret for tests)
	jwtMgr := auth.NewJWTManager("e2e-test-secret", 15*time.Minute)

	// Instantiate handlers
	userHandler := handlers.NewUserHandler(k8sClient, jwtMgr)
	secretsHandler := handlers.NewSecretsHandler(k8sClient)

	// Build router with real wiring (router.NewRouter)
	router := server.NewRouter(jwtMgr, userHandler, secretsHandler)

	// Start HTTP test server
	ts := httptest.NewServer(router)

	return ts.URL, func() {
		ts.Close()
		// Cleanup test namespaces
		_ = k8sClient.DeleteNamespace("user-alice")
		_ = k8sClient.DeleteNamespace("user-bob")
		_ = k8sClient.DeleteNamespace("user-charlie")
	}
}

// Helper: do HTTP POST with JSON
func httpPostJSON(t *testing.T, client *http.Client, url string, body interface{}, token string) *http.Response {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// Helper: do HTTP request with method
func doRequest(t *testing.T, client *http.Client, method, url, token string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, url, body)
	require.NoError(t, err)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

// Testing full user and secret flows end-to-end
func TestE2E_UserAndSecretFlows(t *testing.T) {
	if os.Getenv("RUN_E2E") != "true" {
		t.Skip("skipping E2E tests; set RUN_E2E=true to run")
	}

	kubeconfig := mustKubeConfig(t)
	baseURL, teardown := startAPIServer(t, kubeconfig)
	defer teardown()

	client := &http.Client{Timeout: 15 * time.Second}

	//1) User registration alice
	t.Log("Register user alice")
	regReq := models.UserRequest{Username: "alice", Password: "supersecret"}
	resp := httpPostJSON(t, client, baseURL+"/register", regReq, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var regResp models.UserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&regResp))
	require.Contains(t, regResp.Message, "registered")

	// Verify namespace exists and secret stored
	cfgPath := kubeconfig
	restCfg, err := clientcmd.BuildConfigFromFlags("", cfgPath)
	require.NoError(t, err)
	k8sClient, err := k8s.NewClientWithConfig(context.Background(), restCfg)
	require.NoError(t, err)

	// Wait for namespace to become ready
	timeout := time.Now().Add(20 * time.Second)
	nsName := "user-alice"
	for time.Now().Before(timeout) {
		ns, err := k8sClient.ClientSet.CoreV1().Namespaces().Get(context.Background(), nsName, metav1.GetOptions{})
		if err == nil && ns.Status.Phase == v1.NamespaceActive {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Verify secret exists and password is hashed
	creds, err := k8sClient.GetSecret(nsName, "credentials")
	require.NoError(t, err)
	pw, ok := creds["password"]
	require.True(t, ok)
	require.NotEqual(t, "supersecret", pw) // must be hashed
	// verify bcrypt
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(pw), []byte("supersecret")))

	//Login returns JWT
	t.Log("Login alice")
	loginReq := models.UserRequest{Username: "alice", Password: "supersecret"}
	resp = httpPostJSON(t, client, baseURL+"/login", loginReq, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp models.UserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginResp))
	require.NotEmpty(t, loginResp.Token)
	aliceToken := loginResp.Token

	//3) Secret CRUD for alice
	// CREATE secret
	secretReq := models.SecretRequest{
		SecretName: "mysecret",
		Data:       map[string]string{"token": "abc123"},
	}
	resp = httpPostJSON(t, client, baseURL+"/secrets/create/", secretReq, aliceToken)
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// GET secret
	resp = doRequest(t, client, http.MethodGet, baseURL+"/secrets/get/mysecret", aliceToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var secretResp models.SecretResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&secretResp))
	require.Equal(t, "mysecret", secretResp.SecretName)
	require.Equal(t, "abc123", secretResp.Data["token"])

	// UPDATE secret
	updateReq := models.SecretRequest{
		SecretName: "mysecret",
		Data:       map[string]string{"token": "newtoken", "extra": "v"},
	}
	b, _ := json.Marshal(updateReq)
	resp = doRequest(t, client, http.MethodPut, baseURL+"/secrets/update/mysecret", aliceToken, bytes.NewReader(b))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// GET and verify
	resp = doRequest(t, client, http.MethodGet, baseURL+"/secrets/get/mysecret", aliceToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&secretResp))
	require.Equal(t, "newtoken", secretResp.Data["token"])
	require.Equal(t, "v", secretResp.Data["extra"])

	//4) Forbidden without token (bob tries to read alice secret)
	t.Log("Register bob and attempt forbidden access")
	// Register bob
	regReqB := models.UserRequest{Username: "bob", Password: "otherpass"}
	resp = httpPostJSON(t, client, baseURL+"/register", regReqB, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	// Bob login
	resp = httpPostJSON(t, client, baseURL+"/login", regReqB, "")
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginRespB models.UserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginRespB))
	bobToken := loginRespB.Token

	// Bob tries to GET alice's secret
	resp = doRequest(t, client, http.MethodGet, baseURL+"/secrets/get/mysecret", bobToken, nil)
	require.Equal(t, http.StatusNotFound, resp.StatusCode) // or 403 depending on your handler; adjust if your app uses 403

	//5) Delete user alice (authenticated) and verify namespace removal
	t.Log("Delete alice")
	resp = doRequest(t, client, http.MethodDelete, baseURL+"/user/delete/", aliceToken, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Wait for namespace deletion
	delTimeout := time.Now().Add(60 * time.Second)
	deleted := false
	for time.Now().Before(delTimeout) {
		_, err := k8sClient.ClientSet.CoreV1().Namespaces().Get(context.Background(), nsName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			deleted = true
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	require.True(t, deleted, "namespace should be deleted after user deletion")

	// Ensure secrets in that namespace are gone
	_, err = k8sClient.ClientSet.CoreV1().Secrets(nsName).Get(context.Background(), "credentials", metav1.GetOptions{})
	require.Error(t, err)

	// Cleanup bob namespace
	_ = k8sClient.DeleteNamespace("user-bob")
}

// Helper: start the HTTP server wired with a custom JWT expiration time.
func startAPIServerWithCustomJWT(t *testing.T, kubeconfigPath string, jwtExpiration time.Duration) (baseURL string, teardown func()) {
	t.Helper()

	// Build client config
	cfg, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	require.NoError(t, err)

	// Create real k8s client for handlers (only used for cleanup, but required for handlers)
	k8sClient, err := k8s.NewClientWithConfig(context.Background(), cfg)
	require.NoError(t, err)

	// Create JWT manager with custom expiration
	jwtMgr := auth.NewJWTManager("e2e-test-secret", jwtExpiration) // ⬅️ CUSTOM DURATION

	// Instantiate handlers
	userHandler := handlers.NewUserHandler(k8sClient, jwtMgr)
	secretsHandler := handlers.NewSecretsHandler(k8sClient)

	// Build router with real wiring
	router := server.NewRouter(jwtMgr, userHandler, secretsHandler)

	// Start HTTP test server
	ts := httptest.NewServer(router)

	return ts.URL, func() {
		ts.Close()
	}
}

// Testing expired JWT token handling
func TestE2E_JWT_ExpiredToken(t *testing.T) {
	if os.Getenv("RUN_E2E") != "true" {
		t.Skip("skipping E2E tests; set RUN_E2E=true to run")
	}

	// Setup API server with short expiration
	kubeconfig := mustKubeConfig(t)
	const shortExpiry = 1 * time.Second
	baseURL, teardown := startAPIServerWithCustomJWT(t, kubeconfig, shortExpiry)
	defer teardown()

	client := &http.Client{Timeout: 5 * time.Second}

	// Use a unique username to avoid collisions from previous runs
	testUser := fmt.Sprintf("dave-%d", time.Now().UnixNano())
	testPassword := "expiringpass"

	// Ensure cleanup of namespace left behind by test
	t.Cleanup(func() {
		restCfg, _ := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if kc, err := k8s.NewClientWithConfig(context.Background(), restCfg); err == nil {
			_ = kc.DeleteNamespace("user-" + testUser)
		}
	})

	// Register User
	t.Logf("Register user %s", testUser)
	regReq := models.UserRequest{Username: testUser, Password: testPassword}
	resp := httpPostJSON(t, client, baseURL+"/register", regReq, "")
	require.Equal(t, http.StatusCreated, resp.StatusCode)

	// Login and get the short-lived token
	t.Log("Login to get short-lived token")
	loginReq := models.UserRequest{Username: testUser, Password: testPassword}
	resp = httpPostJSON(t, client, baseURL+"/login", loginReq, "")

	require.Equal(t, http.StatusOK, resp.StatusCode)
	var loginResp models.UserResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&loginResp))
	daveToken := loginResp.Token

	// Wait for token to expire
	t.Logf("Waiting %v for token to expire...", shortExpiry+500*time.Millisecond)
	time.Sleep(shortExpiry + 500*time.Millisecond) // Wait 1.5s (expiry is 1s)

	// Attempt to access a protected resource
	t.Log("Attempting to access protected resource with expired token")

	// Use the GET secrets endpoint as the protected path
	resp = doRequest(t, client, http.MethodGet, baseURL+"/secrets/get/any-secret", daveToken, nil)

	// The authentication middleware should fail the token validation
	require.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	bodyBytes, _ := io.ReadAll(resp.Body)
	t.Logf("Response from protected endpoint: %s", string(bodyBytes))
}
