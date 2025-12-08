package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"secretsManagerAPI/internal/auth"
	"secretsManagerAPI/internal/handlers"
	"secretsManagerAPI/internal/k8s"
	"secretsManagerAPI/internal/server"
	"time"
)

func main() {
	ctx := context.Background()

	// Initialize Kubernetes client
	k8sClient, err := k8s.NewClient(ctx)
	if err != nil {
		log.Fatalf("failed to initialize Kubernetes client: %v", err)
	}

	mySecretKey := os.Getenv("SECRET_KEY")
	if mySecretKey == "" {
		log.Fatal("SECRET_KEY environment variable is required")
	}

	// Initialize JWT manager
	jwtManager := auth.NewJWTManager(mySecretKey, time.Hour*24)

	// Initialize handlers
	userHandler := handlers.NewUserHandler(k8sClient, jwtManager)
	secretsHandler := handlers.NewSecretsHandler(k8sClient)

	// Setup router
	router := server.NewRouter(jwtManager, userHandler, secretsHandler)

	// Create HTTP server
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Starting server on :8080")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
