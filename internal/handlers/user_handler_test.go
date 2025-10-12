// internal/handlers/user_handler_test.go
package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers/mocks"
	"secretsManagerAPI/internal/k8s"
	"secretsManagerAPI/internal/models"

	"golang.org/x/crypto/bcrypt"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// fakeJWTManager implements the Generate method used by UserHandler.
type fakeJWTManager struct {
	token string
	err   error
}

func (f *fakeJWTManager) Generate(username string) (string, error) {
	return f.token, f.err
}

func newK8sClientForTest(ctx context.Context) *k8s.Client {
	cs := fake.NewClientset() // returns *fake.Clientset implementing kubernetes.Interface
	return &k8s.Client{
		ClientSet: cs,
		Context:   ctx,
	}
}

func TestRegister_Success(t *testing.T) {
	client := mocks.NewMockClient()
	jwt := &fakeJWTManager{token: "tok-1"}

	handler := &mocks.MockHandler{
		Client:     client,
		JWTManager: jwt,
	}

	reqBody := models.UserRequest{
		Username: "alice",
		Password: "password123",
	}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(b))
	rec := httptest.NewRecorder()

	handler.Register(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status %d got %d body=%s", http.StatusCreated, rec.Code, rec.Body.String())
	}

	secretMap, err := client.GetSecret("user-alice", "credentials")
	if err != nil {
		t.Fatalf("expected GetSecret to succeed, got error: %v", err)
	}
	if secretMap["username"] != "alice" {
		t.Fatalf("expected username 'alice', got %q", secretMap["username"])
	}

	storedHash := secretMap["password"]
	if err := bcrypt.CompareHashAndPassword([]byte(storedHash), []byte("password123")); err != nil {
		t.Fatalf("stored password hash does not match original password: %v", err)
	}

	// login check
	loginReq := models.UserRequest{
		Username: "alice",
		Password: "password123",
	}
	lb, _ := json.Marshal(loginReq)
	lreq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(lb))
	lrec := httptest.NewRecorder()
	handler.Login(lrec, lreq)

	if lrec.Code != http.StatusOK {
		t.Fatalf("login after register expected 200 got %d body=%s", lrec.Code, lrec.Body.String())
	}
	var lr models.UserResponse
	if err := json.NewDecoder(lrec.Body).Decode(&lr); err != nil {
		t.Fatalf("invalid login response JSON: %v", err)
	}
	if lr.Token != jwt.token {
		t.Fatalf("expected JWT %q got %q", jwt.token, lr.Token)
	}
}

func TestRegister_BadMethodAndBadPayload(t *testing.T) {
	client := newK8sClientForTest(context.Background())
	handler := &UserHandler{Client: client}

	// Wrong method
	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rec := httptest.NewRecorder()
	handler.Register(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected %d got %d", http.StatusMethodNotAllowed, rec.Code)
	}

	// Bad payload
	req = httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader([]byte("notjson")))
	rec = httptest.NewRecorder()
	handler.Register(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected %d got %d", http.StatusBadRequest, rec.Code)
	}
}

func TestLogin_SuccessAndInvalidPassword(t *testing.T) {
	ctx := context.Background()
	client := newK8sClientForTest(ctx)

	// create namespace and credentials secret for bob
	username := "bob"
	password := "s3cr3t"
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	_, _ = client.ClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "user-" + username},
	}, metav1.CreateOptions{})

	_, _ = client.ClientSet.CoreV1().Secrets("user-"+username).Create(ctx, &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "credentials"},
		Data: map[string][]byte{
			"username": []byte(username),
			"password": hash,
		},
	}, metav1.CreateOptions{})

	jwt := &fakeJWTManager{token: "jwt-bob"}
	handler := &UserHandler{
		JWTManager: jwt,
		Client:     client,
	}

	// Success case
	loginReq := models.UserRequest{
		Username: username,
		Password: password,
	}
	b, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
	rec := httptest.NewRecorder()
	handler.Login(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	var resp models.UserResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("invalid response JSON: %v", err)
	}
	if resp.Token != jwt.token {
		t.Fatalf("expected token %q got %q", jwt.token, resp.Token)
	}

	// Invalid password
	badReq := models.UserRequest{
		Username: username,
		Password: "wrong",
	}
	b, _ = json.Marshal(badReq)
	req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(b))
	rec = httptest.NewRecorder()
	handler.Login(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestChangeUserPassword_SuccessAndUnauthorized(t *testing.T) {
	client := mocks.NewMockClient()
	jwt := &fakeJWTManager{token: "jwt-carol"}

	handler := &mocks.MockHandler{
		Client:     client,
		JWTManager: jwt,
	}

	username := "carol"
	oldPassword := "oldpass"
	oldHash, _ := bcrypt.GenerateFromPassword([]byte(oldPassword), bcrypt.DefaultCost)

	// Pre-create user credentials in mock client
	client.CreateSecret("user-"+username, "credentials", map[string]string{
		"username": username,
		"password": string(oldHash),
	})

	// Authorized password change
	newPassword := "newpass"
	reqBody := map[string]string{"new_password": newPassword}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPut, "/user/password", bytes.NewReader(b))
	req = req.WithContext(auth.WithUsername(context.Background(), username))
	rec := httptest.NewRecorder()

	handler.ChangeUserPassword(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}

	// Verify the password was updated in mock client
	secretMap, err := client.GetSecret("user-"+username, "credentials")
	if err != nil {
		t.Fatalf("expected GetSecret to succeed, got error: %v", err)
	}
	if err := bcrypt.CompareHashAndPassword([]byte(secretMap["password"]), []byte(newPassword)); err != nil {
		t.Fatalf("expected password to be updated and match new password: %v", err)
	}

	// Login with new password should succeed
	loginReq := models.UserRequest{Username: username, Password: newPassword}
	lb, _ := json.Marshal(loginReq)
	lreq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(lb))
	lrec := httptest.NewRecorder()
	handler.Login(lrec, lreq)
	if lrec.Code != http.StatusOK {
		t.Fatalf("login with new password expected %d got %d body=%s", http.StatusOK, lrec.Code, lrec.Body.String())
	}

	// Login with old password should fail
	oldLoginReq := models.UserRequest{Username: username, Password: oldPassword}
	ob, _ := json.Marshal(oldLoginReq)
	oreq := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(ob))
	orec := httptest.NewRecorder()
	handler.Login(orec, oreq)
	if orec.Code != http.StatusUnauthorized {
		t.Fatalf("login with old password expected %d got %d body=%s", http.StatusUnauthorized, orec.Code, orec.Body.String())
	}

	// Unauthorized: no username in context
	req = httptest.NewRequest(http.MethodPut, "/user/password", bytes.NewReader(b))
	rec = httptest.NewRecorder()
	handler.ChangeUserPassword(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rec.Code)
	}
}

func TestDeleteUser_SuccessAndUnauthorized(t *testing.T) {
	ctx := context.Background()
	client := newK8sClientForTest(ctx)

	username := "dan"
	_, _ = client.ClientSet.CoreV1().Namespaces().Create(ctx, &v1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: "user-" + username},
	}, metav1.CreateOptions{})

	handler := &UserHandler{Client: client}

	// Authorized delete
	req := httptest.NewRequest(http.MethodDelete, "/user", nil)
	req = req.WithContext(auth.WithUsername(context.Background(), username))
	rec := httptest.NewRecorder()
	handler.DeleteUser(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected %d got %d body=%s", http.StatusOK, rec.Code, rec.Body.String())
	}
	// Confirm namespace deleted
	if _, err := client.ClientSet.CoreV1().Namespaces().Get(ctx, "user-"+username, metav1.GetOptions{}); err == nil {
		t.Fatalf("expected namespace to be deleted")
	}

	// Unauthorized
	req = httptest.NewRequest(http.MethodDelete, "/user", nil)
	rec = httptest.NewRecorder()
	handler.DeleteUser(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected %d got %d", http.StatusUnauthorized, rec.Code)
	}
}
