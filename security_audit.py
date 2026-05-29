#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
security_audit.py - Passive security-header / cookie audit
=====================================================================

WHAT THIS DOES
--------------
Send a GET to the target URL, then inspect the response for:

  - MISSING security headers (CSP, HSTS, X-Frame-Options, etc.)
  - MISCONFIGURED cookies (HttpOnly / Secure / SameSite missing)
  - DISCLOSURE headers (Server, X-Powered-By, X-AspNet-Version, ...)

Output is a categorized report - findings grouped by severity.

WHY THESE MATTER (the BSCP perspective)
--------------------------------------
Every missing header below is a chained-attack enabler:

  - No CSP                  -> reflected/stored XSS isn't blocked at
                               the browser level. Found XSS? You can
                               exfil cookies / pivot to anything.

  - No HSTS                 -> first-request downgrade to HTTP works.
                               Network attacker MITMs the first visit.

  - No X-Frame-Options /    -> the page can be iframed by an attacker
    no CSP frame-ancestors    site. Clickjacking + UI redress.

  - No X-Content-Type-      -> browser MIME-sniffs and may execute
    Options: nosniff          uploaded content as a different type.

  - No Referrer-Policy      -> internal URLs leak via Referer header
                               to every link / image / iframe.

For cookies:

  - No HttpOnly             -> document.cookie reachable from JS. An
                               XSS payload reads the session cookie.

  - No Secure               -> cookie sent over plain HTTP. MITM steals
                               session.

  - No SameSite=Lax/Strict  -> cookie sent on cross-site requests.
                               CSRF attacks succeed.

For disclosure:

  - Server: Apache/2.4.41   -> attacker can look up known CVEs for
                               that specific version.

  - X-Powered-By: PHP/7.2   -> tech stack revealed for free.

  - X-AspNet-Version: 4.x   -> same for .NET.

A clean audit is a small but real defensive bar. PortSwigger labs
sometimes hide auth bypass behind a missing-Secure cookie that you
can MITM-replay over HTTP.

USE
---
  python3 security_audit.py https://target.com
  python3 security_audit.py https://target.com --output report.html
  python3 security_audit.py https://target.com --proxy burp

It does ONE GET (with --follow-redirects to land at the real page).
For a thorough audit, also run against your post-login dashboard
URL with --cookie/--cookie-jar to see post-auth headers.
"""

import argparse
import sys
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

from intruder import (
    build_session, parse_cookie_pair, load_cookie_jar,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, bold, cyan, green, red, yellow, dim,
)


# ---------------------------------------------------------------------
# RULES
# ---------------------------------------------------------------------
# Each rule is (header_name, severity, why_it_matters). The audit
# treats absence of a "required" header as a finding.
REQUIRED_HEADERS = [
    ("Content-Security-Policy", "high",
     "blocks reflected/stored XSS at the browser level"),
    ("Strict-Transport-Security", "high",
     "forces HTTPS - blocks downgrade attacks on first/return visits"),
    ("X-Content-Type-Options", "medium",
     "must be 'nosniff' to stop browser MIME-sniffing"),
    ("X-Frame-Options", "medium",
     "blocks clickjacking via iframe (CSP frame-ancestors also covers this)"),
    ("Referrer-Policy", "low",
     "controls how much URL info leaks via Referer header"),
    ("Permissions-Policy", "low",
     "restricts which browser features the page can use (camera, mic, etc.)"),
]

# Headers whose mere presence reveals tech stack info.
DISCLOSURE_HEADERS = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Drupal-Dynamic-Cache",
    "Via",
]


@dataclass
class Finding:
    severity: str          # "high" | "medium" | "low" | "info"
    category: str          # "header" | "cookie" | "disclosure"
    title: str
    detail: str


# ---------------------------------------------------------------------
# AUDITORS
# ---------------------------------------------------------------------
def audit_required_headers(headers: dict[str, str]) -> list[Finding]:
    """Check that every required security header is present."""
    findings: list[Finding] = []
    # Headers are case-insensitive in HTTP; build a lower-keyed lookup.
    lower = {k.lower(): v for k, v in headers.items()}
    for name, severity, why in REQUIRED_HEADERS:
        if name.lower() not in lower:
            findings.append(Finding(
                severity=severity,
                category="header",
                title=f"missing {name}",
                detail=why,
            ))
        else:
            value = lower[name.lower()]
            # Per-header value checks
            if name == "X-Content-Type-Options" and value.lower() != "nosniff":
                findings.append(Finding(
                    "medium", "header",
                    f"X-Content-Type-Options is {value!r}, not 'nosniff'",
                    "set to 'nosniff' to stop MIME-sniffing"
                ))
            if name == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    "medium", "header",
                    f"X-Frame-Options is {value!r}, not DENY/SAMEORIGIN",
                    "weak value - set to DENY or SAMEORIGIN"
                ))
            if name == "Strict-Transport-Security" and "max-age" in value.lower():
                # Try to extract the max-age value - too short is a finding.
                try:
                    parts = {p.split("=")[0].strip().lower(): p.split("=")[1].strip()
                             for p in value.split(";") if "=" in p}
                    max_age = int(parts.get("max-age", "0"))
                    if max_age < 31536000:    # one year
                        findings.append(Finding(
                            "low", "header",
                            f"HSTS max-age={max_age} is below 1 year",
                            "spec recommends >=31536000 (1 year)"
                        ))
                except (ValueError, KeyError):
                    pass
    return findings


def audit_cookies(set_cookie_headers: list[str]) -> list[Finding]:
    """
    Inspect each Set-Cookie header for missing security attributes.

    A response can have multiple Set-Cookie headers (one per cookie),
    so we get a list, not a dict.
    """
    findings: list[Finding] = []
    for raw in set_cookie_headers:
        # SimpleCookie parses one cookie at a time; load() expects
        # a full Set-Cookie line.
        try:
            jar = SimpleCookie()
            jar.load(raw)
        except Exception:
            continue
        for name, morsel in jar.items():
            attrs = {k.lower() for k, v in morsel.items() if v}
            # `morsel` exposes attributes like httponly/secure/samesite
            # as keys. Their value is truthy when the attribute is set.
            if not morsel["httponly"]:
                findings.append(Finding(
                    "high", "cookie",
                    f"cookie {name!r} has no HttpOnly",
                    "JavaScript can read it - exposed to XSS"
                ))
            if not morsel["secure"]:
                findings.append(Finding(
                    "high", "cookie",
                    f"cookie {name!r} has no Secure",
                    "transmitted over plain HTTP - MITM steals it"
                ))
            samesite = morsel["samesite"].lower() if morsel["samesite"] else ""
            if samesite not in ("strict", "lax"):
                findings.append(Finding(
                    "medium", "cookie",
                    f"cookie {name!r} has SameSite={samesite or 'unset'}",
                    "browser sends it on cross-site requests - enables CSRF"
                ))
    return findings


def audit_disclosure(headers: dict[str, str]) -> list[Finding]:
    """Flag any 'X-Powered-By' style header that reveals tech stack."""
    findings: list[Finding] = []
    lower = {k.lower(): (k, v) for k, v in headers.items()}
    for name in DISCLOSURE_HEADERS:
        if name.lower() in lower:
            orig_name, value = lower[name.lower()]
            findings.append(Finding(
                "info", "disclosure",
                f"server discloses {orig_name}: {value!r}",
                "reveals tech stack - lookup CVEs for that exact version"
            ))
    return findings


# ---------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

SEVERITY_RENDERERS = {
    "high":   lambda s: red(s),
    "medium": lambda s: yellow(s),
    "low":    lambda s: cyan(s),
    "info":   lambda s: dim(s),
}


def render_report(url: str, status: int, findings: list[Finding]) -> None:
    """Pretty-print findings grouped by severity."""
    print(f"{tag_info()} target : {bold(url)}")
    print(f"{tag_info()} status : {status}")
    print()
    if not findings:
        print(f"{tag_ok()} no findings - all required headers + cookie flags look good")
        return

    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = "  ".join(
        SEVERITY_RENDERERS[sev](f"{counts.get(sev, 0)} {sev}")
        for sev in ("high", "medium", "low", "info") if counts.get(sev, 0)
    )
    print(f"{tag_info()} findings: {summary}")
    print()

    current_sev = None
    for f in findings:
        if f.severity != current_sev:
            current_sev = f.severity
            print(SEVERITY_RENDERERS[f.severity](f"--- {f.severity.upper()} ---"))
        print(f"  [{f.category}] {bold(f.title)}")
        print(f"    {dim(f.detail)}")


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("url", help="Target URL")
    ap.add_argument("--follow-redirects", action="store_true",
                    help="Follow 3xx redirects and audit the landing page "
                         "(default: stop at first response)")
    ap.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                    help="Set a cookie before the GET (for post-auth audits)")
    ap.add_argument("--cookie-jar", type=Path,
                    help="JSON cookie jar to load cookies from")
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy. 'burp' = http://127.0.0.1:8080.")
    ap.add_argument("--insecure", action="store_true")

    args = ap.parse_args()

    proxy = args.proxy
    insecure = args.insecure
    if proxy:
        if proxy.strip().lower() == "burp":
            proxy = "http://127.0.0.1:8080"
        elif "://" not in proxy:
            proxy = f"http://{proxy}"
        insecure = True
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    cookies: dict[str, str] = {}
    if args.cookie_jar:
        cookies.update(load_cookie_jar(args.cookie_jar))
    for raw in args.cookie:
        name, val = parse_cookie_pair(raw)
        cookies[name] = val

    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"{tag_err()} URL must include scheme + host")

    session = build_session(1, proxy, insecure, retries=2, cookies=cookies)
    try:
        r = session.get(args.url, allow_redirects=args.follow_redirects, timeout=20)
    except requests.exceptions.RequestException as e:
        sys.exit(f"{tag_err()} request failed: {e}")

    # raw_headers preserves Set-Cookie repetition; `headers` is a dict
    # that collapses duplicates. We want both.
    headers = dict(r.headers)
    set_cookies = r.raw.headers.getlist("Set-Cookie") if hasattr(r.raw, "headers") else \
                  r.headers.get("Set-Cookie", "").split("\n")
    set_cookies = [c for c in set_cookies if c]

    findings = []
    findings.extend(audit_required_headers(headers))
    findings.extend(audit_cookies(set_cookies))
    findings.extend(audit_disclosure(headers))

    render_report(r.url, r.status_code, findings)


if __name__ == "__main__":
    main()
