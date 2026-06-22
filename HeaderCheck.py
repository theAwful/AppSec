"""
HeaderCheck
======================
Fetches a URL and grades its HTTP security headers.

Usage:
    python header_grader.py https://example.com
    python header_grader.py https://example.com --output json
    python header_grader.py https://example.com --batch urls.txt

Install deps first:
    pip install httpx rich typer
"""

import json
import sys
from dataclasses import dataclass
from typing import Optional

import httpx
import typer
from rich.console import Console
from rich.table import Table
from rich import box

app = typer.Typer(help="Grade the security headers of any URL.")
console = Console()

@dataclass
class HeaderResult:
    name: str           # e.g. "Content-Security-Policy"
    present: bool       # was the header in the response?
    value: Optional[str]  # the raw header value, or None if missing
    score: float        # 0.0 = bad/missing, 1.0 = good
    weight: float       # how much this header contributes to the overall grade
    message: str        # explanation of the finding
    recommendation: str # what to actually do about it

HEADER_RULES = [
    {
        "name": "Content-Security-Policy",
        "weight": 1.0,
        "missing_message": "No CSP — XSS attacks are unrestricted",
        "present_message": "CSP is set",
        "recommendation": "Add: Content-Security-Policy: default-src 'self'",
        # Some values are worse than no CSP at all
        "bad_values": ["unsafe-inline", "unsafe-eval", "*"],
        "bad_message": "CSP present but contains dangerous directives",
    },
    {
        "name": "Strict-Transport-Security",
        "weight": 1.0,
        "missing_message": "No HSTS — users can be downgraded to HTTP",
        "present_message": "HSTS is set",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        # HSTS with a very short max-age is nearly useless
        "min_max_age": 86400,  # 1 day minimum
        "bad_message": "HSTS max-age is too short (under 1 day)",
    },
    {
        "name": "X-Frame-Options",
        "weight": 0.7,
        "missing_message": "No X-Frame-Options — clickjacking possible",
        "present_message": "X-Frame-Options is set",
        "recommendation": "Add: X-Frame-Options: DENY",
        "bad_values": ["ALLOWALL"],
        "bad_message": "X-Frame-Options set to ALLOWALL — framing unrestricted",
    },
    {
        "name": "X-Content-Type-Options",
        "weight": 0.6,
        "missing_message": "No X-Content-Type-Options — MIME sniffing enabled",
        "present_message": "X-Content-Type-Options is set",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    {
        "name": "Referrer-Policy",
        "weight": 0.5,
        "missing_message": "No Referrer-Policy — URLs may leak in Referer header",
        "present_message": "Referrer-Policy is set",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "bad_values": ["unsafe-url", "no-referrer-when-downgrade"],
        "bad_message": "Referrer-Policy leaks full URLs to third parties",
    },
    {
        "name": "Permissions-Policy",
        "weight": 0.4,
        "missing_message": "No Permissions-Policy — browser features unrestricted",
        "present_message": "Permissions-Policy is set",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    {
        "name": "X-Powered-By",
        "weight": 0.3,
        # This one is inverted — present is BAD, absent is good
        "inverted": True,
        "missing_message": "X-Powered-By not exposed (good)",
        "present_message": "X-Powered-By exposes server tech (remove this header)",
        "recommendation": "Remove X-Powered-By to avoid fingerprinting",
    },
    {
        "name": "Server",
        "weight": 0.2,
        "inverted": True,
        "missing_message": "Server header not exposed (good)",
        "present_message": "Server header exposes version info",
        "recommendation": "Remove or genericise the Server header",
    },
]

def check_header(rule: dict, headers: dict[str, str]) -> HeaderResult:
    """
    Evaluate one rule against the response headers.
    headers keys are already lowercased by the caller (normalised at boundary).
    """
    header_key = rule["name"].lower()
    value = headers.get(header_key)
    present = value is not None
    inverted = rule.get("inverted", False)

    # Inverted headers: present = bad, absent = good (X-Powered-By, Server)
    if inverted:
        score = 0.0 if present else 1.0
        message = rule["present_message"] if present else rule["missing_message"]
        return HeaderResult(
            name=rule["name"],
            present=present,
            value=value,
            score=score,
            weight=rule["weight"],
            message=message,
            recommendation=rule["recommendation"] if present else "No action needed",
        )

    # Normal headers: absent = bad
    if not present:
        return HeaderResult(
            name=rule["name"],
            present=False,
            value=None,
            score=0.0,
            weight=rule["weight"],
            message=rule["missing_message"],
            recommendation=rule["recommendation"],
        )

    value_lower = value.lower()

    # Special case: HSTS max-age check
    if "min_max_age" in rule:
        max_age = _parse_max_age(value)
        if max_age is not None and max_age < rule["min_max_age"]:
            return HeaderResult(
                name=rule["name"], present=True, value=value,
                score=0.3, weight=rule["weight"],
                message=rule["bad_message"],
                recommendation=rule["recommendation"],
            )

    # Check for dangerous directive values
    if "bad_values" in rule:
        for bad in rule["bad_values"]:
            if bad.lower() in value_lower:
                return HeaderResult(
                    name=rule["name"], present=True, value=value,
                    score=0.3, weight=rule["weight"],
                    message=rule["bad_message"],
                    recommendation=rule["recommendation"],
                )

    # Header present, no obvious issues
    return HeaderResult(
        name=rule["name"], present=True, value=value,
        score=1.0, weight=rule["weight"],
        message=rule["present_message"],
        recommendation="No action needed",
    )


def _parse_max_age(hsts_value: str) -> Optional[int]:
    """Extract max-age integer from an HSTS header value."""
    import re
    match = re.search(r"max-age=(\d+)", hsts_value, re.IGNORECASE)
    return int(match.group(1)) if match else None


# ---------------------------------------------------------------------------
# Scoring
#
# Weighted average: each header contributes (score * weight).
# Total possible = sum of all weights.
# This means a missing CSP (weight 1.0) hurts far more than a missing
# Permissions-Policy (weight 0.4).
# ---------------------------------------------------------------------------

def calculate_grade(results: list[HeaderResult]) -> tuple[float, str]:
    """Returns (score_0_to_100, letter_grade)."""
    total_weight = sum(r.weight for r in results)
    weighted_sum = sum(r.score * r.weight for r in results)
    score = (weighted_sum / total_weight) * 100 if total_weight else 0

    if score >= 90: grade = "A"
    elif score >= 75: grade = "B"
    elif score >= 60: grade = "C"
    elif score >= 45: grade = "D"
    else: grade = "F"

    return round(score, 1), grade

def fetch_headers(url: str) -> tuple[str, dict[str, str]]:
    """
    Returns (final_url_after_redirects, lowercased_headers).
    Raises ConnectionError on network failure.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        resp = httpx.get(url, follow_redirects=True, timeout=10)
        return str(resp.url), {k.lower(): v for k, v in resp.headers.items()}
    except httpx.TimeoutException:
        raise ConnectionError(f"Timed out connecting to {url}")
    except httpx.RequestError as e:
        raise ConnectionError(f"Could not reach {url}: {e}")


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

GRADE_COLOR = {"A": "green", "B": "cyan", "C": "yellow", "D": "orange1", "F": "red"}

def print_table(url: str, final_url: str, score: float, grade: str,
                results: list[HeaderResult]) -> None:
    g_color = GRADE_COLOR.get(grade, "white")
    console.print(f"\n[bold]{url}[/bold]")
    if final_url != url:
        console.print(f"  [dim]Redirected to: {final_url}[/dim]")
    console.print(f"  Grade: [{g_color}]{grade}[/{g_color}]  Score: {score}/100\n")

    table = Table(box=box.SIMPLE_HEAD, show_header=True, header_style="bold dim")
    table.add_column("Header", width=30)
    table.add_column("", width=3)   # icon column
    table.add_column("Finding", ratio=1)

    for r in sorted(results, key=lambda x: x.score):
        if r.score == 1.0:
            icon, color = "[green]✓[/green]", "default"
        elif r.score == 0.0:
            icon, color = "[red]✗[/red]", "red"
        else:
            icon, color = "[yellow]![/yellow]", "yellow"
        table.add_row(r.name, icon, f"[{color}]{r.message}[/{color}]")

    console.print(table)


def print_json(url: str, score: float, grade: str, results: list[HeaderResult]) -> None:
    output = {
        "url": url,
        "score": score,
        "grade": grade,
        "headers": [
            {"name": r.name, "score": r.score, "message": r.message,
             "recommendation": r.recommendation}
            for r in results
        ],
    }
    console.print(json.dumps(output, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

@app.command()
def grade(
    url: str = typer.Argument(..., help="URL to grade"),
    output: str = typer.Option("table", "--output", "-o", help="table or json"),
    batch: Optional[str] = typer.Option(None, "--batch", "-b",
                                         help="Path to file of URLs, one per line"),
    fail_below: int = typer.Option(0, "--fail-below",
                                    help="Exit with code 1 if score is below this"),
):
    urls = [url]
    if batch:
        with open(batch) as f:
            urls = [line.strip() for line in f if line.strip()]

    any_failed = False
    for target in urls:
        try:
            final_url, headers = fetch_headers(target)
            results = [check_header(rule, headers) for rule in HEADER_RULES]
            score, letter = calculate_grade(results)

            if output == "json":
                print_json(target, score, letter, results)
            else:
                print_table(target, final_url, score, letter, results)

            if fail_below and score < fail_below:
                any_failed = True

        except ConnectionError as e:
            console.print(f"[red]Error:[/red] {e}")

    if any_failed:
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
