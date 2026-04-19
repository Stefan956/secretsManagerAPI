# Secrets Manager API

A secure REST API for managing application secrets in Kubernetes. Each user gets an isolated namespace where their secrets are stored as native Kubernetes Secret resources.

## Features

- JWT-based authentication (24-hour tokens, HS256)
- bcrypt password hashing
- Per-user namespace isolation in Kubernetes
- Full CRUD for both users and secrets
- Swagger UI at `/swagger/index.html`

## Requirements

- Go 1.21+
- A running Kubernetes cluster (or kubeconfig with access to one)
- `SECRET_KEY` environment variable set for JWT signing

## Getting Started

### Run locally

```bash
export SECRET_KEY=your-super-secret-key
go run ./cmd/main.go
```

The server starts on `:8080`.

### Deploy to Kubernetes

```bash
# Build the image
docker build -t secrets-manager-api-v2 .

# Apply the manifests (Deployment, ServiceAccount, RBAC, Service)
kubectl apply -f deployment.yaml
```

> **Note:** Update the `secret` value in `deployment.yaml` under `secrets-manager-key` before deploying.

## API Reference

### Authentication

| Method | Endpoint | Auth required |
|--------|----------|---------------|
| `POST` | `/register` | No |
| `POST` | `/login` | No |
| `PUT` | `/user/change-password/` | Yes |
| `DELETE` | `/user/delete/` | Yes |

### Secrets

| Method | Endpoint | Auth required |
|--------|----------|---------------|
| `POST` | `/secrets/create/` | Yes |
| `GET` | `/secrets/get/{name}` | Yes |
| `PUT` | `/secrets/update/{name}` | Yes |
| `DELETE` | `/secrets/delete/{name}` | Yes |

All protected endpoints require `Authorization: Bearer <token>` in the request header.

---

## curl Examples

### User Operations

**Register**
```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user5896",
    "password": "password123"
  }'
```

**Login**
```bash
curl -X POST http://localhost:8080/login \
  -H "Content-Type: application/json" \
  -d '{"username": "user5896", "password": "password123"}'
```

**Change Password**
```bash
curl -X PUT http://localhost:8080/user/change-password/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "new_password": "superNewPassword!"
  }'
```

**Delete User**
```bash
curl -X DELETE http://localhost:8080/user/delete/ \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

### Secrets Operations

**Create Secret**
```bash
curl -X POST http://localhost:8080/secrets/create/ \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "secret-name": "db-credentials",
    "data": {
      "username": "alice",
      "password": "supersecret",
      "host": "localhost",
      "port": "5432"
    }
  }'
```

**Get Secret**
```bash
curl -X GET http://localhost:8080/secrets/get/db-credentials \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Update Secret**
```bash
curl -X PUT http://localhost:8080/secrets/update/db-credentials \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "alice",
      "password": "newpassword",
      "host": "db.internal",
      "port": "5432"
    }
  }'
```

**Delete Secret**
```bash
curl -X DELETE http://localhost:8080/secrets/delete/db-credentials \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Swagger UI

Interactive API documentation is available at:

```
http://localhost:8080/swagger/index.html
```

## License

[MIT](https://opensource.org/licenses/MIT)
