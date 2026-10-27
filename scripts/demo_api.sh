#!/usr/bin/env bash
# End-to-end demonstration of the API contract and its security controls.
# Usage: ./scripts/demo_api.sh [base_url]
set -u

BASE="${1:-http://127.0.0.1:5000}"
line() { printf '\n\033[1m%s\033[0m\n' "$*"; }

line "1. POST /auth/login  (valid credentials)"
LOGIN=$(curl -s -i -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"demo","password":"Demo!Passw0rd"}')
echo "$LOGIN"
TOKEN=$(printf '%s' "$LOGIN" | tail -1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')

line "2. GET /api/data  (no token -> must be rejected)"
curl -s -i "$BASE/api/data"

line "3. GET /api/data  (tampered token -> must be rejected)"
curl -s -i "$BASE/api/data" -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.tampered.signature'

line "4. GET /api/data  (valid token -> 200 OK)"
curl -s -i "$BASE/api/data" -H "Authorization: Bearer $TOKEN"

line "5. POST /auth/login  (SQL injection payload -> rejected by validator)"
curl -s -i -X POST "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin'"'"' OR '"'"'1'"'"'='"'"'1","password":"irrelevant"}'

line "6. POST /api/posts  (XSS payload -> stored HTML-escaped)"
curl -s -i -X POST "$BASE/api/posts" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"<script>alert(\"xss\")</script>","body":"hello <img src=x onerror=alert(1)>"}'

line "7. POST /api/posts  (malformed body -> 400)"
curl -s -i -X POST "$BASE/api/posts" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"title":"","body":"x"}'
