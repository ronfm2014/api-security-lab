# Finding Report Template

> Copy this file for each vulnerability found.  
> Filename: `APIX-ShortName-YYYYMMDD.md`

---

## Finding: [TITLE]

| Field | Value |
|-------|-------|
| **ID** | API[X]-[YYYYMMDD]-001 |
| **Title** | [Short descriptive title] |
| **Target** | [Application name / URL] |
| **Severity** | 🔴 Critical / 🟠 High / 🟡 Medium / 🟢 Low / ℹ️ Info |
| **CVSS Score** | [0.0–10.0] |
| **CVSS Vector** | `CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...` |
| **OWASP Category** | API[X]:2023 — [Name] |
| **Status** | Open / Remediated / Risk Accepted |
| **Discovered** | [Date] |
| **Reported** | [Date] |

---

## 1. Vulnerability Summary

*One paragraph. What is the vulnerability? Why does it exist? What does it allow an attacker to do? Write for a technical reader who hasn't seen this finding before.*

---

## 2. Affected Endpoint(s)

| Method | Endpoint | Parameter | Issue |
|--------|----------|-----------|-------|
| [METHOD] | `/api/v1/[path]` | [param name] | [what's wrong] |

---

## 3. Steps to Reproduce

*Exact, numbered steps. Someone who wasn't present should be able to reproduce this from scratch.*

1. Authenticate as a low-privilege user and capture the JWT token
2. ...
3. Send the following request...

---

## 4. Proof of Concept

**Request:**
```http
[METHOD] /api/v1/[endpoint] HTTP/1.1
Host: [target]
Authorization: Bearer [token]
Content-Type: application/json

{
  "[key]": "[value]"
}
```

**Response:**
```json
{
  "[field]": "[value showing the vulnerability]"
}
```

**Observation:** *What does the response prove? What's notable about it?*

---

## 5. Root Cause Analysis

*Why is this vulnerable? Show the vulnerable code pattern (pseudocode or real code if available) and explain exactly what check is missing or broken.*

```python
# VULNERABLE
def [function_name]([params]):
    # Missing check: [describe what's missing]
    ...
```

---

## 6. Business Impact

*What can an attacker achieve? Translate technical findings into business consequences.*

| Impact Category | Description |
|----------------|-------------|
| Confidentiality | [What data can be read?] |
| Integrity | [What data can be modified?] |
| Availability | [Can service be disrupted?] |
| Compliance | [Which regulations apply? GDPR, HIPAA, PCI-DSS?] |

---

## 7. Remediation

### Recommended Fix

```python
# FIXED
def [function_name]([params]):
    # [Explain the added check]
    if [authorization_check]:
        return 403
    ...
```

### Additional Hardening

- [ ] [Control 1]
- [ ] [Control 2]
- [ ] [Control 3]

### Regression Test

```python
def test_[finding_name]():
    """[Describe what this test validates]"""
    response = client.[method]([endpoint], headers=[...], data=[...])
    assert response.status_code == 403, "Vulnerability present"
```

---

## 8. References

- [OWASP API Top 10 — Relevant Category](https://owasp.org/API-Security/)
- [CWE-XXX — Relevant CWE](https://cwe.mitre.org/)
- [Additional reference]

---

## 9. Timeline

| Date | Event |
|------|-------|
| [Date] | Vulnerability discovered |
| [Date] | Report drafted |
| [Date] | Reported to team |
| [Date] | Fix deployed |
| [Date] | Verified remediated |
