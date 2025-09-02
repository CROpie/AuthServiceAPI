# curl -X GET http://localhost:8000/api/authenticate \
#   -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImNocmlzIiwiZXhwaXJ5IjoxNzU2NzExMDYzfQ.poERFQrcxn5_-pIi_oxP3-KPla-53f5Sf3wUmVD2yek"

response=$(curl -s -X POST http://localhost:8000/api/token \
    -d "username=admin&password=admin")

echo $response