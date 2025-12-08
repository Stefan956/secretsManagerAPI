package auth

import (
	"context"
	"net/http"
	"strings"
)

// JWTMiddleware validates JWT tokens and injects username into request context
func JWTMiddleware(jwtManager JWT, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Expect header in format "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			http.Error(w, "Authorization header must be Bearer <token>", http.StatusUnauthorized)
			return
		}

		// Verify JWT
		claims, err := jwtManager.Verify(parts[1])
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Inject username into context
		ctx := WithUsername(r.Context(), claims.Username)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// MethodMiddleware enforces allowed HTTP methods for a handler
func MethodMiddleware(allowedMethods ...string) func(http.Handler) http.Handler {
	methods := make(map[string]struct{}, len(allowedMethods))
	for _, m := range allowedMethods {
		methods[m] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, ok := methods[r.Method]; !ok {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// UsernameFromContext retrieves the username from context
func UsernameFromContext(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}
