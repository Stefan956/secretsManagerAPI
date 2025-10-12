# ===== Build stage =====
FROM golang:1.25 AS builder

# Set environment variables for Go
ENV GO111MODULE=on \
    CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Set working directory
WORKDIR /app

# Copy go.mod and go.sum first (for caching dependencies)
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire project
COPY . .

# Build the binary
RUN go build -o secrets-manager ./cmd/main.go

# ===== Final stage =====
FROM alpine:latest

# Install CA certificates
RUN apk --no-cache add ca-certificates

# Set working directory
WORKDIR /root/

# Copy the binary from the builder
COPY --from=builder /app/secrets-manager .

# Expose the port your app listens on
EXPOSE 8080

# Command to run the binary
CMD ["./secrets-manager"]

