# API Security Lab — OWASP API Top 10 Attack & Defense Playbook

> **Author:** Ronald Maboufotso · CISSP · OSWP · Principal Security Engineer  
> **Purpose:** Hands-on lab environment for attacking and defending REST APIs against the OWASP API Security Top 10 (2023)  
> **Status:** Active · Continuously updated

---

## What This Is

A fully Dockerized, self-contained lab that spins up two intentionally vulnerable API targets — **crAPI** (Completely Ridiculous API) and **VAmPI** — alongside a pre-configured attacker workstation with all tooling ready. Every attack in the OWASP API Top 10 is documented with:

- A methodology walkthrough
- Working proof-of-concept (PoC) requests
- A root-cause analysis
- A remediation recommendation with code examples

This is a practitioner's notebook, not a tutorial. The goal is a repeatable, documented offensive methodology that mirrors a real engagement report.

---

## Lab Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network: api-lab               │
│                                                         │
│  ┌─────────────┐   ┌─────────────┐   ┌──────────────┐  │
│  │    crAPI    │   │    VAmPI    │   │   Attacker   │  │
│  │  :8888/:8025│   │    :5000    │   │  (Kali-slim) │  │
│  └─────────────┘   └─────────────┘   └──────────────┘  │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │         mailhog (SMTP capture) :8025            │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

| Target | Port | Purpose |
|--------|------|---------|
| crAPI Web | 8888 | Full-stack app with rich API backend |
| crAPI Mail | 8025 | Captures registration/reset emails |
| VAmPI | 5000 | Lightweight Flask REST API |
| Attacker | — | Kali-slim with Burp, ffuf, jwt_tool, etc. |

---

## Quick Start

### Prerequisites
- Docker ≥ 24.x and Docker Compose v2
- 4 GB RAM available
- Ports 8888, 8025, 5000 free

### Spin Up the Lab

```bash
git clone https://github.com/YOUR_HANDLE/api-security-lab.git
cd api-security-lab
docker compose up -d
```

Wait ~60 seconds for all services to initialize, then verify:

```bash
docker compose ps
curl -s http://localhost:5000/createdb   # Initialize VAmPI
curl -s http://localhost:8888            # crAPI should return HTML
```

### Access Points

| Service | URL |
|---------|-----|
| crAPI app | http://localhost:8888 |
| crAPI mail | http://localhost:8025 |
| VAmPI API | http://localhost:5000 |

### Tear Down

```bash
docker compose down -v   # -v removes volumes (clean slate)
```

---

## OWASP API Top 10 Coverage

| # | Vulnerability | Target | Write-up |
|---|---------------|--------|----------|
| API1 | Broken Object Level Authorization (BOLA) | crAPI | [→ writeups/API1-BOLA.md](docs/writeups/API1-BOLA.md) |
| API2 | Broken Authentication | VAmPI + crAPI | [→ writeups/API2-BrokenAuth.md](docs/writeups/API2-BrokenAuth.md) |
| API3 | Broken Object Property Level Authorization | crAPI | [→ writeups/API3-BOPLA.md](docs/writeups/API3-BOPLA.md) |
| API4 | Unrestricted Resource Consumption | VAmPI | [→ writeups/API4-ResourceConsumption.md](docs/writeups/API4-ResourceConsumption.md) |
| API5 | Broken Function Level Authorization (BFLA) | crAPI | [→ writeups/API5-BFLA.md](docs/writeups/API5-BFLA.md) |
| API6 | Unrestricted Access to Sensitive Business Flows | crAPI | [→ writeups/API6-BusinessFlows.md](docs/writeups/API6-BusinessFlows.md) |
| API7 | Server Side Request Forgery (SSRF) | crAPI | [→ writeups/API7-SSRF.md](docs/writeups/API7-SSRF.md) |
| API8 | Security Misconfiguration | VAmPI + crAPI | [→ writeups/API8-Misconfig.md](docs/writeups/API8-Misconfig.md) |
| API9 | Improper Inventory Management | crAPI | [→ writeups/API9-Inventory.md](docs/writeups/API9-Inventory.md) |
| API10 | Unsafe Consumption of APIs | crAPI | [→ writeups/API10-UnsafeConsumption.md](docs/writeups/API10-UnsafeConsumption.md) |

---

## Tooling (Pre-installed in Attacker Container)

| Tool | Purpose |
|------|---------|
| Burp Suite Community | Intercept, replay, fuzz |
| ffuf | Directory/endpoint fuzzing |
| jwt_tool | JWT analysis and attack |
| httpie | Human-readable API requests |
| jq | JSON parsing in pipelines |
| Python 3 + requests | Custom PoC scripting |
| Postman (Newman) | Collection-based testing |

---

## Methodology

Each write-up follows this structure, mirroring a professional engagement report:

```
1. Vulnerability Summary     — one-paragraph description
2. Affected Endpoint(s)      — method, path, parameters
3. CVSS Score                — base score + vector string
4. Steps to Reproduce        — exact curl/Burp steps
5. Proof of Concept          — request/response evidence
6. Root Cause Analysis       — why the code is vulnerable
7. Business Impact           — what an attacker gains
8. Remediation               — code-level fix + validation
```

---

## Repository Structure

```
api-security-lab/
├── README.md                    ← You are here
├── docker-compose.yml           ← Lab orchestration
├── docs/
│   ├── writeups/                ← One .md per OWASP API Top 10 item
│   └── diagrams/                ← Architecture and attack flow diagrams
├── lab/
│   ├── crapi/                   ← crAPI config and seed data
│   └── vamPI/                   ← VAmPI config overrides
├── playbook/
│   └── methodology.md           ← Engagement methodology reference
├── tools/
│   ├── attacker.Dockerfile      ← Custom attacker image
│   └── scripts/                 ← Python PoC scripts
└── reports/
    └── templates/
        └── finding-template.md  ← Pentest finding report template
```

---

## Defensive Companion

Each write-up includes a **"Fix It" section** with:
- The vulnerable code pattern (generic/pseudocode)
- The corrected implementation
- A unit test that would catch the vulnerability in CI

The goal is to speak both offensive and defensive — the combination is what Principal-level AppSec roles require.

---

## Learning Path

If you're using this lab for **ASCP exam prep**, work through in this order:

1. Start with API1 (BOLA) — the most common and highest-severity API vuln
2. API2 (Broken Auth) — JWT attacks are heavily tested
3. API5 (BFLA) — easy to miss, critical in real engagements
4. API4 (Rate limiting / resource consumption) — automation-heavy
5. Then work through the rest in order

---

## References

- [OWASP API Security Top 10 (2023)](https://owasp.org/API-Security/editions/2023/en/0x00-header/)
- [crAPI GitHub](https://github.com/OWASP/crAPI)
- [VAmPI GitHub](https://github.com/erev0s/VAmPI)
- [Hacking APIs — Corey Ball](https://nostarch.com/hacking-apis)
- [PortSwigger API Testing Labs](https://portswigger.net/web-security/api-testing)

---

*Built as part of a structured API security practice. All testing performed in isolated lab environments only.*
