# README
curl requests:
requests for user registration, login, credentials updata ana deletion:

curl -X POST http://localhost:8080/login \
-H "Content-Type: application/json" \
-d '{"username": "iskren", "password": "password123"}'

curl -X POST http://localhost:8080/register -H "Content-Type: application/json" \
-d '{
"username": "iskren",
"password": "password123"
}'

curl -X PUT http://localhost:8080/user/change-details/ \
-H "Authorization: Bearer YOUR_TOKEN" \
-H "Content-Type: application/json" \
-d '{
"new_username": "bob",
"new_password": "newSecretPass123"
}'

curl -X PUT http://localhost:8080/user/change-password/ \
-H "Authorization: Bearer YOUR_TOKEN" \
-H "Content-Type: application/json" \
-d '{
"new_password": "superNewPassword!"
}'

curl -X DELETE http://localhost:8080/user/delete/ \
-H "Authorization: Bearer YOUR_TOKEN"


requests for secret creation, retrieval, update and deletion:

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

curl -X GET http://localhost:8080/secrets/get/db-credentials \
-H "Authorization: Bearer YOUR_TOKEN"

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

curl -X DELETE http://localhost:8080/secrets/delete/db-credentials \
-H "Authorization: Bearer YOUR_TOKEN"