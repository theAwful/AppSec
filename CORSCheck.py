"""
CORS Misconfiguration Checker
==============================
Sends requests with crafted Origin headers and checks how the server responds.

Usage:
    python cors_checker.py https://api.example.com
    python cors_checker.py https://api.example.com --output json
    python cors_checker.py https://api.example.com --extra-origins "evil.com,other.com"

Install deps first:
    pip install httpx rich typer
"""

import json
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(help="Check a URL for CORS misconfigurations.")
console = Console()

@dataclass
class ProbeResult:
    origin_sent: str          # the Origin header value we injected
    origin_label: str         # human name: "attacker domain", "null", etc.
    acao: Optional[str]       # Access-Control-Allow-Origin response value
    acac: Optional[str]       # Access-Control-Allow-Credentials response value
    reflected: bool           # did the server echo back our injected origin?
    wildcard: bool            # did the server respond with *?
    credentialed: bool        # did the server set credentials: true?
    finding: Optional[str]    # short description of the problem, or None if clean


def build_probe_origins(target_url: str, extra: list[str]) -> list[tuple[str, str]]:
    """
    Returns a list of (origin_value, human_label) tuples to test.
    We derive probes from the target URL so they're relevant to this host.
    """
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme

    base = host.removeprefix("www.")

    probes = [
        (f"https://evil-attacker.com", "attacker domain"),

        ("null", "null origin"),

        (f"{scheme}://not{base}", "suffix confusion (not{base})"),

        (f"{scheme}://attacker.{base}", "subdomain of target"),

        (f"{scheme}://{host}", "target origin (baseline)"),
    ]

    for origin in extra:
        probes.append((origin if "://" in origin else f"https://{origin}", "user-supplied"))

    return probes


# ---------------------------------------------------------------------------
# Single probe
#
# We intentionally do NOT follow redirects here. A redirect response
# (301/302) may not carry CORS headers — we want the actual API response.
# We also send a preflight-style OPTIONS request alongside the simple GET
# because some servers only set CORS headers on OPTIONS.
# ---------------------------------------------------------------------------

def probe(url: str, origin: str, label: str) -> ProbeResult:
    headers = {"Origin": origin}

    try:
        # Use GET first — catches servers that set CORS on all responses
        resp = httpx.get(url, headers=headers, follow_redirects=False, timeout=8)
    except httpx.RequestError:
        # If GET fails, we still return a clean result rather than crashing
        return ProbeResult(
            origin_sent=origin, origin_label=label,
            acao=None, acac=None,
            reflected=False, wildcard=False, credentialed=False,
            finding=None,
        )

    acao = resp.headers.get("access-control-allow-origin")
    acac = resp.headers.get("access-control-allow-credentials")

    reflected = acao == origin
    wildcard  = acao == "*"
    # "true" is the only value that enables credentialed requests;
    # anything else (including "false") is treated as not set
    credentialed = (acac or "").lower() == "true"

    finding = _classify(origin, acao, reflected, wildcard, credentialed)

    return ProbeResult(
        origin_sent=origin,
        origin_label=label,
        acao=acao,
        acac=acac,
        reflected=reflected,
        wildcard=wildcard,
        credentialed=credentialed,
        finding=finding,
    )


# ---------------------------------------------------------------------------
# Classification
#
# We score findings by severity so the report is prioritised.
# The worst case is reflected origin + credentials: true — that means
# an attacker's page can make credentialed cross-origin requests and read
# the response. Pure wildcard without credentials is less severe because
# browsers block credentialed requests to wildcard origins.
# ---------------------------------------------------------------------------

def _classify(
    origin: str,
    acao: Optional[str],
    reflected: bool,
    wildcard: bool,
    credentialed: bool,
) -> Optional[str]:

    if acao is None:
        return None   # no CORS header at all — not a misconfiguration

    # Worst case: server reflects our arbitrary origin AND allows credentials.
    # This means any website can make authenticated API calls on behalf of
    # a logged-in user and read the response.
    if reflected and credentialed and origin != "null":
        return "CRITICAL — reflects arbitrary origin with credentials: true"

    # null + credentials is also critical: sandboxed iframes can exploit this
    if origin == "null" and reflected and credentialed:
        return "CRITICAL — trusts null origin with credentials: true"

    # Reflected without credentials is still a finding — less severe because
    # the attacker can read public responses but not credentialed ones
    if reflected and origin not in ("null",) and "attacker" in origin:
        return "HIGH — arbitrary origin reflected (no credentials)"

    # null reflected without credentials
    if origin == "null" and reflected:
        return "MEDIUM — null origin reflected"

    # Wildcard is fine for public APIs, but worth flagging for review
    if wildcard and credentialed:
        # Browsers block this combo, but it signals a confused server config
        return "LOW — wildcard with credentials: true (browsers block, but misconfigured)"

    if wildcard:
        return "INFO — wildcard CORS (intentional for public APIs?)"

    return None   # reflected own origin or not reflected — clean


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

SEVERITY_COLOR = {
    "CRITICAL": "red",
    "HIGH":     "orange1",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

def print_table(url: str, results: list[ProbeResult]) -> None:
    findings = [r for r in results if r.finding]
    console.print(f"\n[bold]{url}[/bold]")

    if not findings:
        console.print("  [green]No CORS misconfigurations detected[/green]\n")
    else:
        console.print(f"  [red]{len(findings)} finding(s)[/red]\n")

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Origin sent",   width=34)
    table.add_column("ACAO response", width=34)
    table.add_column("Finding")

    for r in results:
        # Pick a color based on the first word of the finding severity
        color = "default"
        if r.finding:
            first_word = r.finding.split()[0].rstrip("—").strip()
            color = SEVERITY_COLOR.get(first_word, "default")

        acao_display = r.acao or "[dim]not set[/dim]"
        finding_display = f"[{color}]{r.finding}[/{color}]" if r.finding else "[green]clean[/green]"

        table.add_row(
            f"{r.origin_sent}\n[dim]{r.origin_label}[/dim]",
            acao_display,
            finding_display,
        )

    console.print(table)


def print_json(url: str, results: list[ProbeResult]) -> None:
    output = {
        "url": url,
        "findings": [
            {
                "origin_sent":  r.origin_sent,
                "label":        r.origin_label,
                "acao":         r.acao,
                "acac":         r.acac,
                "reflected":    r.reflected,
                "credentialed": r.credentialed,
                "finding":      r.finding,
            }
            for r in results if r.finding
        ],
    }
    console.print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@app.command()
def check(
    url: str = typer.Argument(..., help="URL to test"),
    output: str = typer.Option("table", "--output", "-o", help="table or json"),
    extra_origins: str = typer.Option(
        "", "--extra-origins",
        help="Comma-separated extra origins to test, e.g. 'evil.com,other.io'",
    ),
):
    extras = [o.strip() for o in extra_origins.split(",") if o.strip()]
    probes = build_probe_origins(url, extras)

    results = []
    for origin, label in probes:
        results.append(probe(url, origin, label))

    if output == "json":
        print_json(url, results)
    else:
        print_table(url, results)


if __name__ == "__main__":
    app()
