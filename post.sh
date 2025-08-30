# curl -X POST \
#     -H "Content-Type: application/json" \
#     -d '{"username": "chris"}' \
#     http://localhost:8000/api/token

curl -X POST \
     -d "username=chris&password=password" \
     http://localhost:8000/api/token