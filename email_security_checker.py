"""
Email Security Checker
======================
Checks a domain's SPF, DMARC, and DKIM DNS records for misconfigurations.

Usage:
    python email_security_checker.py example.com
    python email_security_checker.py example.com --dkim-selector google
    python email_security_checker.py example.com --output json

Install deps first:
    pip install dnspython rich typer
"""

import json
import re
from dataclasses import dataclass
from typing import Optional

import dns.resolver
import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(help="Check SPF, DMARC, and DKIM records for a domain.")
console = Console()


# ---------------------------------------------------------------------------
# Data model
#
# One CheckResult per record type (SPF, DMARC, DKIM).
# Keeping it flat — no nested objects — makes it easy to serialise to JSON
# and easy to print in a table without extra unpacking logic.
# ---------------------------------------------------------------------------

@dataclass
class CheckResult:
    record_type: str          # "SPF", "DMARC", "DKIM"
    found: bool               # did the DNS record exist at all?
    raw: Optional[str]        # the raw TXT record value
    grade: str                # "pass" | "warn" | "fail"
    issues: list[str]         # list of specific problems found
    recommendation: str       # what to do about it


# ---------------------------------------------------------------------------
# DNS helper
#
# dns.resolver raises specific exceptions we want to handle differently:
#   NXDOMAIN  = the name doesn't exist at all (record missing)
#   NoAnswer  = the name exists but has no TXT records
#   Timeout   = DNS server didn't respond
#
# We return a list of strings because a single hostname can have multiple
# TXT records — SPF for example must have exactly one, so we check for that.
# ---------------------------------------------------------------------------

def query_txt(hostname: str) -> list[str]:
    """Return all TXT record values for a hostname, or [] if none exist."""
    try:
        answers = dns.resolver.resolve(hostname, "TXT")
        # Each answer is a sequence of byte strings (one per 255-char chunk).
        # Join them and decode — this handles long SPF records split across chunks.
        return ["".join(part.decode() for part in rdata.strings) for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []
    except dns.exception.Timeout:
        console.print(f"[yellow]Warning: DNS timeout querying {hostname}[/yellow]")
        return []


# ---------------------------------------------------------------------------
# SPF checker
#
# SPF lives in a TXT record at the root domain.
# Key things to check:
#   - exactly one SPF record (multiple = undefined behaviour, mail may fail)
#   - doesn't end with +all (means "any server is authorised" — useless)
#   - doesn't end with ?all (neutral — also pointless)
#   - -all or ~all is correct (-all = hard fail, ~all = soft fail)
# ---------------------------------------------------------------------------

def check_spf(domain: str) -> CheckResult:
    records = query_txt(domain)
    # Filter to only SPF records — TXT records can contain anything
    spf_records = [r for r in records if r.startswith("v=spf1")]

    if not spf_records:
        return CheckResult(
            record_type="SPF", found=False, raw=None, grade="fail",
            issues=["No SPF record found — anyone can spoof email from this domain"],
            recommendation=f'Add TXT record: "v=spf1 include:_spf.{domain} -all"',
        )

    issues = []

    # Multiple SPF records is an error per RFC 7208 — receivers may reject mail
    if len(spf_records) > 1:
        issues.append(f"Multiple SPF records found ({len(spf_records)}) — RFC forbids this, keep exactly one")

    raw = spf_records[0]

    # +all means every server on the internet is authorised — completely defeats SPF
    if "+all" in raw:
        issues.append("+all authorises every mail server on the internet — SPF is useless")

    # ?all is neutral — receivers treat it as no SPF at all, so it's pointless
    elif "?all" in raw:
        issues.append("?all is neutral — receivers ignore SPF, use -all or ~all instead")

    # ~all (soft fail) is acceptable but -all (hard fail) is stronger
    elif "~all" in raw:
        issues.append("~all is a soft fail — consider -all for stricter enforcement")

    elif "-all" not in raw:
        # No all mechanism at all — SPF has no default-deny
        issues.append("No 'all' mechanism found — add -all to reject unauthorised senders")

    grade = "fail" if any("+all" in i or "anyone" in i or "RFC forbids" in i for i in issues) \
            else "warn" if issues else "pass"

    return CheckResult(
        record_type="SPF", found=True, raw=raw, grade=grade, issues=issues,
        recommendation='Use "-all" to hard-fail unauthorised senders' if issues else "No action needed",
    )


# ---------------------------------------------------------------------------
# DMARC checker
#
# DMARC lives at _dmarc.<domain> as a TXT record.
# Key things to check:
#   - p=none means "do nothing" — monitoring only, no protection
#   - p=quarantine sends to spam — better but not full protection
#   - p=reject is the goal — unauthenticated mail is rejected outright
#   - pct= controls what percentage of mail the policy applies to
#   - rua= is the reporting address — without it you're flying blind
# ---------------------------------------------------------------------------

def check_dmarc(domain: str) -> CheckResult:
    records = query_txt(f"_dmarc.{domain}")
    dmarc_records = [r for r in records if r.startswith("v=DMARC1")]

    if not dmarc_records:
        return CheckResult(
            record_type="DMARC", found=False, raw=None, grade="fail",
            issues=["No DMARC record — phishing and spoofing attacks go unreported"],
            recommendation=f'Add TXT record at _dmarc.{domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc@{domain}"',
        )

    raw = dmarc_records[0]
    issues = []

    # Parse the semicolon-separated tag=value pairs into a dict
    # e.g. "v=DMARC1; p=reject; rua=mailto:x@y.com" → {"v": "DMARC1", "p": "reject", ...}
    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()

    policy = tags.get("p", "")

    if policy == "none":
        issues.append('p=none — policy is "monitor only", no mail is rejected or quarantined')
    elif policy == "quarantine":
        issues.append("p=quarantine — good, but p=reject gives stronger protection")
    elif policy != "reject":
        issues.append(f"Unknown or missing policy value: '{policy}'")

    # pct controls what % of mail the policy applies to — default is 100
    pct = tags.get("pct", "100")
    if pct != "100":
        issues.append(f"pct={pct} — policy only applies to {pct}% of mail, not all of it")

    # Without rua you get no aggregate reports — you can't see who's spoofing you
    if "rua" not in tags:
        issues.append("No rua= tag — you won't receive aggregate reports about spoofing attempts")

    grade = "fail" if policy == "none" or not policy \
            else "warn" if issues else "pass"

    return CheckResult(
        record_type="DMARC", found=True, raw=raw, grade=grade, issues=issues,
        recommendation='Set p=reject and add rua= for full protection' if issues else "No action needed",
    )


# ---------------------------------------------------------------------------
# DKIM checker
#
# DKIM public keys live at <selector>._domainkey.<domain>.
# Unlike SPF/DMARC there's no standard place to discover selectors — you
# have to know (or guess) what selector the mail provider uses.
# We try common ones if the user doesn't supply one.
# ---------------------------------------------------------------------------

COMMON_SELECTORS = [
    "default", "google", "k1", "mail", "dkim",
    "selector1", "selector2", "smtp", "email",
]

def check_dkim(domain: str, selector: Optional[str]) -> CheckResult:
    selectors_to_try = [selector] if selector else COMMON_SELECTORS

    for sel in selectors_to_try:
        hostname = f"{sel}._domainkey.{domain}"
        records = query_txt(hostname)
        dkim_records = [r for r in records if "v=DKIM1" in r or "p=" in r]

        if dkim_records:
            raw = dkim_records[0]
            issues = []

            # p= is the public key — an empty p= means the key is revoked
            key_match = re.search(r"p=([A-Za-z0-9+/=]*)", raw)
            if key_match and not key_match.group(1):
                issues.append(f"p= is empty at selector '{sel}' — key has been revoked")

            grade = "warn" if issues else "pass"
            return CheckResult(
                record_type=f"DKIM ({sel})", found=True, raw=raw[:80] + "…" if len(raw) > 80 else raw,
                grade=grade, issues=issues,
                recommendation="No action needed" if not issues else "Rotate DKIM key with your mail provider",
            )

    tried = selector or f"{len(selectors_to_try)} common selectors"
    return CheckResult(
        record_type="DKIM", found=False, raw=None, grade="warn",
        issues=[f"No DKIM record found (tried: {tried})"],
        recommendation="Check your mail provider's docs for the correct selector, then pass it with --dkim-selector",
    )


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

GRADE_ICON  = {"pass": "[green]✓[/green]", "warn": "[yellow]![/yellow]", "fail": "[red]✗[/red]"}
GRADE_COLOR = {"pass": "green", "warn": "yellow", "fail": "red"}

def print_table(domain: str, results: list[CheckResult]) -> None:
    console.print(f"\n[bold]{domain}[/bold]\n")
    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Record", width=16)
    table.add_column("", width=3)
    table.add_column("Issues / status")

    for r in results:
        icon = GRADE_ICON[r.grade]
        color = GRADE_COLOR[r.grade]
        body = "\n".join(r.issues) if r.issues else "Looks good"
        table.add_row(r.record_type, icon, f"[{color}]{body}[/{color}]")

    console.print(table)

    # Print raw records underneath for reference
    console.print("[dim]Raw records:[/dim]")
    for r in results:
        label = r.record_type.split()[0]   # strip selector from "DKIM (google)"
        value = r.raw or "not found"
        console.print(f"  [dim]{label}:[/dim] {value}")
    console.print()


def print_json(domain: str, results: list[CheckResult]) -> None:
    output = {
        "domain": domain,
        "results": [
            {"record": r.record_type, "found": r.found, "grade": r.grade,
             "issues": r.issues, "recommendation": r.recommendation}
            for r in results
        ],
    }
    console.print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@app.command()
def check(
    domain: str = typer.Argument(..., help="Domain to check, e.g. example.com"),
    dkim_selector: Optional[str] = typer.Option(
        None, "--dkim-selector", "-s",
        help="DKIM selector to check (e.g. 'google', 'selector1'). "
             "If omitted, common selectors are tried automatically.",
    ),
    output: str = typer.Option("table", "--output", "-o", help="table or json"),
):
    # Strip any accidental http:// prefix the user might have included
    domain = domain.removeprefix("https://").removeprefix("http://").rstrip("/")

    results = [
        check_spf(domain),
        check_dmarc(domain),
        check_dkim(domain, dkim_selector),
    ]

    if output == "json":
        print_json(domain, results)
    else:
        print_table(domain, results)


if __name__ == "__main__":
    app()
