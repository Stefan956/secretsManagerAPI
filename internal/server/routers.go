package server

import (
	"net/http"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers"
	"strings"
)

// scopedRoute represents a single API route
type scopedRoute struct {
	Name        string
	Method      string
	Pattern     string
	HandlerFunc http.HandlerFunc
	Protected   bool // whether the route requires JWT
}

// Router holds dependencies
type Router struct {
	JWTManager     *auth.JWTManager
	UserHandler    *handlers.UserHandler
	SecretsHandler *handlers.SecretsHandler
}

// NewRouter initializes all routes and returns an http.Handler
func NewRouter(jwtManager *auth.JWTManager, userHandler *handlers.UserHandler, secretsHandler *handlers.SecretsHandler) http.Handler {
	// Define routes
	routes := []scopedRoute{
		// Public routes
		{
			Name:        "RegisterUser",
			Method:      http.MethodPost,
			Pattern:     "/register",
			HandlerFunc: userHandler.Register,
			Protected:   false,
		},
		{
			Name:        "LoginUser",
			Method:      http.MethodPost,
			Pattern:     "/login",
			HandlerFunc: userHandler.Login,
			Protected:   false,
		},

		// Protected routes
		{
			Name:        "CreateSecret",
			Method:      http.MethodPost,
			Pattern:     "/secrets/create/",
			HandlerFunc: secretsHandler.CreateSecret,
			Protected:   true,
		},
		{
			Name:        "GetSecret",
			Method:      http.MethodGet,
			Pattern:     "/secrets/get/",
			HandlerFunc: withSecretName(secretsHandler.GetSecret),
			Protected:   true,
		},
		{
			Name:        "UpdateSecret",
			Method:      http.MethodPut,
			Pattern:     "/secrets/update/",
			HandlerFunc: withSecretName(secretsHandler.UpdateSecret),
			Protected:   true,
		},
		{
			Name:        "DeleteSecret",
			Method:      http.MethodDelete,
			Pattern:     "/secrets/delete/",
			HandlerFunc: withSecretName(secretsHandler.DeleteSecret),
			Protected:   true,
		},
		{
			Name:        "ChangeUserPassword",
			Method:      http.MethodPut,
			Pattern:     "/user/change-password/",
			HandlerFunc: userHandler.ChangeUserPassword,
			Protected:   true,
		},
		{
			Name:        "DeleteUser",
			Method:      http.MethodDelete,
			Pattern:     "/user/delete/",
			HandlerFunc: userHandler.DeleteUser,
			Protected:   true,
		},
	}

	// Register routes with mux
	// mux - (short for "multiplexer") matches incoming HTTP requests against a list of registered routes
	//and calls the associated handler for the first match
	mux := http.NewServeMux()
	for _, route := range routes {
		handlerFunc := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { //calls route without JWT
			// Ensure method matches
			if req.Method != route.Method {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			route.HandlerFunc(w, req)
		})

		// Wrap protected routes with JWT middleware
		if route.Protected {
			handler := auth.JWTMiddleware(jwtManager, handlerFunc) //calls route with JWT
			mux.Handle(route.Pattern, handler)
			continue
		}

		mux.Handle(route.Pattern, handlerFunc)
	}

	return mux
}

// withSecretName extracts the secret name from the path and injects it into the context
func withSecretName(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		parts := strings.Split(req.URL.Path, "/")
		if len(parts) < 1 {
			http.Error(w, "Secret name required", http.StatusBadRequest)
			return
		}

		secretName := parts[len(parts)-1] // take the last part
		if secretName == "" {
			http.Error(w, "Secret name required", http.StatusBadRequest)
			return
		}

		ctx := auth.WithSecretName(req.Context(), secretName)
		req = req.WithContext(ctx)

		next(w, req)
	}
}
