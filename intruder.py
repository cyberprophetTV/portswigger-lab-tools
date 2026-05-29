#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Intended for solving PortSwigger Web Security Academy labs and for
# use against systems you OWN or have EXPLICIT WRITTEN PERMISSION to
# test. Running this against unauthorized systems is illegal in most
# jurisdictions (CFAA in the US, Computer Misuse Act in the UK, etc).
# You are responsible for ensuring your use is lawful. See README.
"""
=====================================================================
intruder.py - General-purpose HTTP request fuzzer modeled on
              Burp Suite's Intruder.
=====================================================================

WHAT THIS DOES
--------------
You give it three things:
  1. A RAW HTTP request template (paste-able from Burp's "Raw" tab)
     with `§MARKER§` placeholders wherever you want payloads
     substituted in.
  2. One or more PAYLOAD WORDLISTS (one entry per line).
  3. An ATTACK MODE that decides how payloads map to markers.

It substitutes the payloads into the markers, fires the resulting
requests in parallel (with optional proxy / jitter / fresh-session
controls borrowed from username_enum_solver.py), filters results
through MATCHER rules, prints hits, and optionally writes every
result to a JSON file for offline analysis.

WHY THIS EXISTS (vs username_enum_solver.py)
--------------------------------------------
username_enum_solver.py is a SOLVER - it has hardcoded knowledge of
the username-enumeration lab (POST to /login, form fields named
`username` + `password`, success = 302 redirect). That makes it
fast to use for that one lab but useless for everything else.

intruder.py is a FUZZER - it has zero hardcoded knowledge of any
specific endpoint. You hand it a request template and a wordlist;
it iterates. That same template+wordlist pattern works for:
  - SQL injection (payloads: `' OR 1=1--`, `'; DROP TABLE--`, ...)
  - XSS (payloads: `<script>alert(1)</script>`, `<img onerror=...>`)
  - Path traversal (payloads: `../etc/passwd`, `....//etc/passwd`)
  - Directory enumeration (payloads: `admin`, `backup`, `config`, ...)
  - Header injection (set the marker in a header value)
  - JWT none-alg, no-sig fuzzing (set the marker in a Bearer token)
  - Any "swap value X in position Y" attack

THE FOUR ATTACK MODES (same as Burp Intruder)
---------------------------------------------
1. SNIPER (single payload list, default mode)
       Iterates ONE marker at a time. For each marker position p
       and each payload v, send a request with v at p and the
       ORIGINAL TEXT at every other marker. Total requests = N*M
       (N markers, M payloads).

       Use case: test each parameter independently. "Which of
       these 3 query parameters is vulnerable to SQLi?"

2. BATTERING RAM (single payload list)
       Substitutes the SAME payload into EVERY marker at once.
       Total requests = M.

       Use case: "what if every input is this SQLi string at once?"
       Useful when several inputs feed the same backend query.

3. PITCHFORK (multiple payload lists, iterated in parallel)
       K lists, advance them together. Iteration i uses
       list[0][i] at marker 0, list[1][i] at marker 1, etc.
       Total requests = min(len(list_k)).

       Use case: credential pairs you DON'T want to cross. Try
       (alice, alice_pass), (bob, bob_pass) - not (alice, bob_pass).

4. CLUSTER BOMB (multiple payload lists, cartesian product)
       Every combination. For two lists of 100 each: 10,000 requests.

       Use case: full brute-force. Every username crossed with
       every password.

MATCHERS - what counts as a "hit"
---------------------------------
A matcher filter decides whether each response is "interesting".
Multiple matchers are AND'd together: a result must satisfy ALL
enabled matchers to count as a hit.

  --match-status SPEC    HTTP status. Examples:
                            "200"        -> exactly 200
                            "200-299"    -> any 2xx
                            "!403"       -> NOT 403
                            "5000-"      -> 5000 or higher (not valid for status, but useful for length)
  --match-length SPEC    Response body length in bytes (same syntax)
  --match-regex PATTERN  Python regex; passes if found in body
  --match-not-regex PAT  Same but inverted (passes if NOT found)
  --match-time SPEC      Response time in seconds (same range syntax)

If no matchers are given, ALL responses count as hits (you'll see
every one printed - use --output and pipe to less/jq).

OUTPUT
------
  --output FILE.json     Write every result (hit OR not) as JSON.
                         Each entry has label/status/length/time/hit.
                         Process offline with jq or pandas.
  --verbose              Print every response (not just hits) AND
                         dump the full request + response body of
                         the first hit. Use this to sanity-check
                         that your template is being substituted
                         the way you expect.

STEALTH + SESSION + PROXY (same flags as username_enum_solver.py)
-----------------------------------------------------------------
  --jitter MIN-MAX       Random delay before each request.
  --fresh-session        New Session per request (defeats per-session
                         lockouts; slower because of TLS handshakes).
  --workers N            Concurrent requests (default 10).
  --proxy URL            Route everything through a proxy. 'burp' is
                         shorthand for http://127.0.0.1:8080.
                         Auto-enables --insecure.
  --insecure             Skip TLS verification. Required when
                         proxying through Burp (it MITMs with its
                         own CA).
  --retries N            Retry on connection error / 5xx (default 2).

EXAMPLE: enumerate usernames via different responses (the same lab
the other script solves, but expressed as a template):

  req.txt:
    POST /login HTTP/1.1
    Host: 0a1b00...web-security-academy.net
    Content-Type: application/x-www-form-urlencoded

    username=§USER§&password=junk

  Run:
    python3 intruder.py req.txt \\
        --payload usernames.txt \\
        --mode sniper \\
        --match-length '!3168'      # show responses whose length isn't 3168

  Reads the template, finds 1 marker (USER), iterates 101 usernames,
  and prints anything whose body is a different length than 3168 -
  which is the valid one.

EXAMPLE: cluster-bomb every (user, pw) combination against the
password brute-force lab:

  req.txt:
    POST /login HTTP/1.1
    Host: target.web-security-academy.net
    Content-Type: application/x-www-form-urlencoded

    username=§USER§&password=§PW§

  Run:
    python3 intruder.py req.txt \\
        --payload usernames.txt \\
        --payload passwords.txt \\
        --mode cluster-bomb \\
        --match-status 302          # successful login = redirect
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import argparse                              # CLI parsing
import base64                                # for --encode base64
import csv                                   # for --output-csv
import html                                  # for --encode html + HTML report escaping
import itertools                             # cartesian product for cluster bomb
import json                                  # --output file format
import random                                # jitter
import re                                    # marker + matcher regexes
import sys                                   # sys.exit on errors
import time                                  # time.sleep + time.monotonic
import urllib.parse                          # for --encode url
from concurrent.futures import (             # parallel request execution
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass, field     # tidy config containers
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3                               # for InsecureRequestWarning suppression
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry         # connection-error retry policy

# Local: color + progress helpers (see _common.py). Importing from a
# private-named module avoids polluting the public surface if someone
# imports * from this file.
from _common import (
    tag_hit, tag_miss, tag_info, tag_ok, tag_warn, tag_err,
    progress, bold, dim,
)


# ---------------------------------------------------------------------
# MARKER REGEX
# ---------------------------------------------------------------------
# `§` is the section sign - matches Burp's choice of payload-position
# delimiter. We capture whatever's between the two § marks so we can
# fall back to that text when a position isn't being substituted (this
# is the Sniper-mode behavior: only one position at a time gets the
# payload; the others keep their literal text).
#
# `re.DOTALL` lets `.` match newlines, so a marker that spans lines
# (rare but possible) still works.
MARKER_RE = re.compile(r"§(.*?)§", re.DOTALL)


# ---------------------------------------------------------------------
# RANGE-SPEC PARSING (used by --match-status, --match-length, --match-time)
# ---------------------------------------------------------------------
def parse_range_spec(s: str) -> tuple[float, float, bool]:
    """
    Turn a user range spec into (lo, hi, negate).

    Supported syntax:
        "404"       -> (404, 404, False)        single value
        "200-299"   -> (200, 299, False)        range
        "5000-"     -> (5000, +inf, False)      lower bound only
        "-1000"     -> (0,    1000, False)      upper bound only
        "!403"      -> (403,  403, True)        negation: passes if NOT 403
        "!200-299"  -> (200,  299, True)        negation of a range

    The match check (range_matches below) returns True when the value
    is inside the range XOR the negate flag - i.e. negation flips it.
    """
    s = s.strip()
    negate = s.startswith("!")
    if negate:
        s = s[1:].strip()
    if "-" in s:
        lo_s, hi_s = s.split("-", 1)
        lo = float(lo_s) if lo_s else 0.0
        hi = float(hi_s) if hi_s else float("inf")
    else:
        v = float(s)
        lo = hi = v
    return (lo, hi, negate)


def range_matches(spec: tuple[float, float, bool] | None, value: float) -> bool:
    """
    True if `value` satisfies the range spec. None spec means "no
    constraint" - always passes.

    XOR with `negate` is the trick that lets us share one function
    for both inclusive ("200-299") and exclusive ("!403") tests.
    """
    if spec is None:
        return True
    lo, hi, negate = spec
    in_range = lo <= value <= hi
    return in_range != negate


# ---------------------------------------------------------------------
# JITTER (stealth delay) - same idea as in username_enum_solver.py
# ---------------------------------------------------------------------
def parse_jitter(s: str) -> tuple[float, float]:
    """
    "0"         -> (0.0, 0.0)   jitter disabled
    "0.5"       -> (0.5, 0.5)   fixed delay
    "0.5-2.0"   -> (0.5, 2.0)   random delay in [0.5, 2.0]
    """
    if "-" in s:
        lo, hi = s.split("-", 1)
        return float(lo), float(hi)
    v = float(s)
    return v, v


def maybe_jitter(jitter: tuple[float, float]) -> None:
    """Sleep a random duration if jitter is configured (otherwise no-op)."""
    lo, hi = jitter
    if hi > 0:
        time.sleep(random.uniform(lo, hi))


# ---------------------------------------------------------------------
# SESSION BUILDER (similar to the other script, but with retries
# baked in so transient 502/503/504s don't kill a long fuzz run)
# ---------------------------------------------------------------------
def build_session(
    workers: int,
    proxy: str | None = None,
    insecure: bool = False,
    retries: int = 2,
    cookies: dict[str, str] | None = None,
) -> requests.Session:
    """
    Construct a requests.Session with:
      - Connection pool sized to `workers` for parallel reuse.
      - Optional proxy (e.g. Burp at 127.0.0.1:8080).
      - Optional TLS verification bypass (needed with Burp's MITM CA).
      - urllib3.Retry policy that auto-retries on connection errors,
        on certain 5xx responses, and on HTTP methods that are safe
        to retry.

    `Retry` notes:
      - total: max total retries across all reasons.
      - backoff_factor: doubling delay between attempts. With 0.5,
        the delays are roughly 0s, 1s, 2s, 4s, ...
      - status_forcelist: status codes that DO get retried even
        though `requests` would normally accept them. 502/503/504
        are transient infrastructure errors worth retrying.
      - allowed_methods: only retry idempotent methods by default.
        We include POST here because in a fuzz context, retrying
        a failed POST is what we want.
    """
    s = requests.Session()

    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        # raise_on_status=False keeps `requests` from raising on a
        # final-attempt 5xx; we want to see and record it.
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=workers,
        pool_maxsize=workers,
        max_retries=retry,
    )
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "portswigger-lab-intruder/1.0"})

    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    if insecure:
        s.verify = False

    # Seed cookies BEFORE returning so every subsequent request from
    # this session includes them. requests' CookieJar.update accepts
    # a plain dict directly.
    if cookies:
        s.cookies.update(cookies)

    return s


def read_wordlist(path: Path) -> list[str]:
    """One entry per line; strip whitespace; drop blank lines."""
    return [w for w in (line.strip() for line in path.read_text().splitlines()) if w]


# ---------------------------------------------------------------------
# PAYLOAD ENCODERS
# ---------------------------------------------------------------------
# Apply transformations to each payload before sending it. The classic
# WAF-evasion move: a filter blocks `' OR 1=1--` but waves through
# `%27%20OR%201%3D1--`. Or the filter URL-decodes once, so you
# double-URL-encode: `%2527%2520OR%25201%253D1--`.
#
# Encodings can be chained: --encode url,base64 applies URL first,
# then base64 to the result. Order matters - "url,base64" is the
# base64 of the URL-encoded payload; "base64,url" is the URL-encoded
# base64.
ENCODERS = {
    # No-op. Useful as the explicit "I checked, I don't want encoding"
    # value, or as a placeholder in a chain.
    "none":       lambda s: s,
    # Percent-encode every byte that isn't an unreserved character.
    # `safe=""` is critical - urllib.parse.quote's default keeps `/`
    # un-encoded, which we don't want for payload values.
    "url":        lambda s: urllib.parse.quote(s, safe=""),
    # Apply URL encoding twice. Common WAF bypass when the filter
    # decodes once but the app decodes again.
    "double-url": lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=""), safe=""),
    # Standard base64. Useful when the parameter expects a base64
    # blob (e.g. Authorization: Basic) or as a WAF-bypass technique.
    "base64":     lambda s: base64.b64encode(s.encode()).decode(),
    # Each byte as two hex chars. Used in some path-traversal bypasses
    # (`%2e%2e%2f` is "..%2f" in single-decoded then "../" in double).
    "hex":        lambda s: s.encode().hex(),
    # HTML entity encoding. Less common as an attack-side transform;
    # more useful when probing XSS reflection points to see if angle
    # brackets get escaped or preserved.
    "html":       lambda s: html.escape(s, quote=True),
}


def parse_encode_chain(s: str) -> list[str]:
    """
    Parse a --encode value into an ordered list of encoder names.

    Empty string / 'none' -> []  (no encoding).
    'url' -> ['url']
    'url,base64' -> ['url', 'base64']

    Validates that every name is a known encoder.
    """
    if not s or s.strip().lower() == "none":
        return []
    names = [name.strip().lower() for name in s.split(",") if name.strip()]
    for n in names:
        if n not in ENCODERS:
            sys.exit(f"[!] unknown encoding {n!r}. "
                     f"Available: {', '.join(sorted(ENCODERS))}")
    return names


def apply_encoding(payload: str, chain: list[str]) -> str:
    """Run the payload through each encoder in order. Empty chain returns input as-is."""
    for name in chain:
        payload = ENCODERS[name](payload)
    return payload


# ---------------------------------------------------------------------
# AUTHENTICATED PROBING + COOKIE JAR
# ---------------------------------------------------------------------
# Real-world pentesting almost always involves authenticated areas:
# admin panels, account pages, internal APIs. The two pieces we need:
#
#   1. LOGIN FLOW: POST credentials to a login endpoint, let the
#      server set a session cookie via Set-Cookie. requests.Session
#      captures those automatically into its .cookies jar.
#   2. COOKIE PERSISTENCE: save the jar to disk after login and
#      reload it on subsequent runs, so you don't re-authenticate
#      every invocation (which both wastes time and trips lockout
#      counters on the login endpoint).
#
# We support three ways to provide cookies, any combination:
#   --login-url + --login-data : do a login POST at startup
#   --cookie-jar FILE          : load saved cookies (and save updated ones)
#   --cookie 'name=value'      : manually set one (repeatable)


def parse_form_data(s: str) -> dict[str, str]:
    """
    Parse 'user=admin&pw=secret&token=abc' into a dict.

    Uses urllib.parse so '+' and '%XX' percent-encoding work correctly -
    important when credentials contain spaces or special chars.
    """
    return dict(urllib.parse.parse_qsl(s, keep_blank_values=True))


def parse_cookie_pair(s: str) -> tuple[str, str]:
    """Parse one 'name=value' into (name, value). Fails on missing '='."""
    if "=" not in s:
        sys.exit(f"[!] --cookie must look like 'name=value', got {s!r}")
    name, _, value = s.partition("=")
    return name.strip(), value.strip()


def load_cookie_jar(path: Path) -> dict[str, str]:
    """
    Load a JSON cookie jar from disk. Missing file -> empty dict (so
    a fresh run with --cookie-jar still works).

    Format is intentionally a simple flat {name: value} dict instead
    of the richer Netscape format that supports per-cookie domain /
    path / expiry. For lab work everything's same-host and we just
    need the values; if we ever need a real jar we'd switch to
    http.cookiejar.MozillaCookieJar.
    """
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as e:
        sys.exit(f"[!] cookie jar {path} is not valid JSON: {e}")
    if not isinstance(data, dict):
        sys.exit(f"[!] cookie jar {path} must contain a JSON object")
    return {str(k): str(v) for k, v in data.items()}


def save_cookie_jar(path: Path, cookies: dict[str, str]) -> None:
    """Persist current cookies to disk for next run."""
    path.write_text(json.dumps(cookies, indent=2, sort_keys=True) + "\n")


def login_and_capture(session: requests.Session, login_url: str,
                      login_data: dict[str, str]) -> dict[str, str]:
    """
    POST credentials to the login endpoint. requests.Session captures
    any Set-Cookie response headers into session.cookies automatically -
    we just need to do the POST and read them back.

    allow_redirects=True so we follow any post-login redirect (most
    apps redirect to /my-account or /dashboard); the cookies set
    during the redirect chain end up in the jar too.
    """
    r = session.post(login_url, data=login_data, allow_redirects=True, timeout=20)
    # `r.status_code` of 200 after a redirect chain is the normal
    # success path. 401/403 means login failed. We don't fail here
    # because some apps still 200 a failed login - we just return
    # whatever cookies got set (may be empty) and let the user see
    # the request didn't work via Burp / --verbose.
    return dict(session.cookies)


# ---------------------------------------------------------------------
# OUTPUT WRITERS (--output / --output-csv / --output-html / --output-md)
# ---------------------------------------------------------------------
# All four take the same `results` list (one dict per request) and a
# Path to write to. The shape is:
#   { "label": str, "status": int|None, "length": int,
#     "time": float, "error": str|None, "hit": bool }
#
# Why ship four formats?
#   - JSON   for scripting (jq, pandas, your own glue)
#   - CSV    for spreadsheets / pandas / sharing with non-coders
#   - HTML   for sending a polished artifact to a client / your team
#   - MD     for pasting into a Slack thread, GitHub issue, or notes
# Each is ~30 lines. Cheap to provide; no reason not to.

def write_json(results: list[dict], path: Path) -> None:
    """Dump as a JSON array. indent=2 keeps it human-readable; drop for compact."""
    path.write_text(json.dumps(results, indent=2) + "\n")


def write_csv(results: list[dict], path: Path) -> None:
    """
    Standard CSV with header row. Field order is fixed (not alpha-
    sorted) so the columns are predictable across runs - matters when
    you're diffing two output files or feeding them to a downstream
    script that expects a specific column order.
    """
    fieldnames = ["label", "status", "length", "time", "hit", "error"]
    with path.open("w", newline="", encoding="utf-8") as f:
        # extrasaction='ignore' silently drops any unexpected fields
        # we don't know about - future-proofing if `results` ever grows.
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def write_markdown(results: list[dict], path: Path) -> None:
    """
    GitHub-flavored Markdown table. Hits get a ✓; misses get a blank
    cell. Errors get rendered in their own column.

    Why MD? It's the lingua franca of dev tooling - paste it into
    Slack, GitHub, your team wiki, a PR description.
    """
    n_total = len(results)
    n_hits = sum(1 for r in results if r["hit"])
    n_errors = sum(1 for r in results if r["error"])

    lines = [
        "# Intruder results",
        "",
        f"- **Total requests:** {n_total}",
        f"- **Hits:** {n_hits}",
        f"- **Errors:** {n_errors}",
        "",
        "| # | Label | Status | Length | Time (s) | Hit | Error |",
        "|---|---|---|---|---|---|---|",
    ]
    for i, r in enumerate(results, start=1):
        hit = "✓" if r["hit"] else ""
        err = (r["error"] or "").replace("|", "\\|").replace("\n", " ")
        # `|` in the label would break the table layout; escape it.
        label = (r["label"] or "").replace("|", "\\|")
        lines.append(
            f"| {i} | {label} | {r['status']} | {r['length']} | "
            f"{r['time']:.3f} | {hit} | {err} |"
        )
    path.write_text("\n".join(lines) + "\n")


# Inline CSS for the HTML report - self-contained so the file works
# anywhere with no external dependencies.
HTML_TEMPLATE_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Intruder results</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 2em; color: #222; }
  h1 { margin-top: 0; }
  .summary { display: flex; gap: 2em; margin: 1em 0; }
  .summary div { background: #f4f4f4; padding: 0.5em 1em; border-radius: 4px; }
  .summary .hits  { background: #d4edda; }
  .summary .errors { background: #f8d7da; }
  table { border-collapse: collapse; width: 100%; font-family: monospace; font-size: 13px; }
  th, td { border: 1px solid #ddd; padding: 4px 8px; text-align: left;
           vertical-align: top; }
  th { background: #f4f4f4; }
  tr.hit { background: #d4edda; }
  tr.error { background: #f8d7da; }
  td.num { text-align: right; }
  td.label { word-break: break-all; max-width: 40em; }
</style>
</head>
<body>
"""

HTML_TEMPLATE_FOOT = """
</tbody>
</table>
</body>
</html>
"""


def write_html(results: list[dict], path: Path) -> None:
    """
    Polished standalone HTML report. Self-contained CSS, no external
    fonts/JS - so it works behind air-gapped firewalls and emails as
    a single attachment.

    Rows get .hit (green) or .error (red) classes so they jump out
    when you skim.

    `html.escape` is non-negotiable: response labels can contain
    arbitrary attacker-controlled payloads (XSS strings, for one).
    Without escaping, opening the report could execute the very XSS
    payloads we were testing. quote=True also escapes `'` and `"`.
    """
    n_total = len(results)
    n_hits = sum(1 for r in results if r["hit"])
    n_errors = sum(1 for r in results if r["error"])

    parts = [HTML_TEMPLATE_HEAD]
    parts.append("<h1>Intruder results</h1>")
    parts.append('<div class="summary">')
    parts.append(f'<div>Total: <b>{n_total}</b></div>')
    parts.append(f'<div class="hits">Hits: <b>{n_hits}</b></div>')
    if n_errors:
        parts.append(f'<div class="errors">Errors: <b>{n_errors}</b></div>')
    parts.append("</div>")

    parts.append("<table>")
    parts.append("<thead><tr>"
                 "<th>#</th><th>Label</th><th>Status</th><th>Length</th>"
                 "<th>Time (s)</th><th>Hit</th><th>Error</th>"
                 "</tr></thead>")
    parts.append("<tbody>")
    for i, r in enumerate(results, start=1):
        cls = "hit" if r["hit"] else ("error" if r["error"] else "")
        cls_attr = f' class="{cls}"' if cls else ""
        parts.append(
            f"<tr{cls_attr}>"
            f"<td class=\"num\">{i}</td>"
            f'<td class="label">{html.escape(str(r["label"] or ""))}</td>'
            f"<td class=\"num\">{r['status']}</td>"
            f"<td class=\"num\">{r['length']}</td>"
            f"<td class=\"num\">{r['time']:.3f}</td>"
            f"<td>{'✓' if r['hit'] else ''}</td>"
            f"<td>{html.escape(str(r['error'] or ''))}</td>"
            f"</tr>"
        )
    parts.append(HTML_TEMPLATE_FOOT)
    path.write_text("".join(parts))


# =====================================================================
# RAW REQUEST PARSER + SUBSTITUTION
# =====================================================================
@dataclass
class RawRequest:
    """
    A parsed HTTP request. Carries:
        method   "GET" | "POST" | ...
        path     "/login?lang=en" (path + query, no scheme/host)
        headers  [(name, value), ...] in original order
        body     str (raw body bytes as text; UTF-8 assumed)

    The parser is intentionally lenient - it accepts requests you'd
    actually paste from Burp's Raw tab without normalizing them. We
    don't validate the request because if the server doesn't like
    it, that's information too.
    """
    method: str
    path: str
    headers: list[tuple[str, str]]
    body: str

    @classmethod
    def parse(cls, text: str) -> "RawRequest":
        """
        Parse a raw HTTP request string into its parts.

        Format (HTTP/1.1):
            METHOD PATH HTTP/VERSION\\r\\n
            Header-Name: value\\r\\n
            Another-Header: value\\r\\n
            \\r\\n                      <- blank line separates headers from body
            ...body bytes...
        """
        # Normalize line endings to \\r\\n (HTTP standard). Users often
        # paste files with \\n only, especially from text editors.
        text = text.replace("\r\n", "\n").replace("\n", "\r\n")

        # Header/body split is at the FIRST blank line ("\\r\\n\\r\\n").
        if "\r\n\r\n" in text:
            head, body = text.split("\r\n\r\n", 1)
        else:
            head, body = text, ""

        lines = head.split("\r\n")

        # Strip whole-line comments from the head section. `#` at start
        # of a line (optionally after whitespace) marks a comment. This
        # is NOT an HTTP feature - it's a convenience for our template
        # files so they can be self-documenting. The body is left alone
        # (a `#` is a valid character in form data, JSON, etc.).
        lines = [l for l in lines if not l.lstrip().startswith("#")]

        if not lines:
            sys.exit("[!] empty request template")

        # First line: "METHOD PATH HTTP/x.y" (we ignore the version).
        first = lines[0].split(" ", 2)
        if len(first) < 2:
            sys.exit(f"[!] malformed request line: {lines[0]!r}")
        method, path = first[0], first[1]

        # Header lines: "Name: Value". We preserve order and tolerate
        # weird casing. Malformed lines are skipped (with a warning).
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                print(f"[!] skipping malformed header line: {line!r}", file=sys.stderr)
                continue
            name, val = line.split(":", 1)
            headers.append((name.strip(), val.strip()))

        return cls(method=method, path=path, headers=headers, body=body)

    def all_text_for_marker_scan(self) -> str:
        """Concatenate path + headers + body so we can count markers."""
        out = self.path
        for name, val in self.headers:
            out += "\n" + name + ": " + val
        out += "\n" + self.body
        return out

    def marker_count(self) -> int:
        """How many §...§ markers does this template contain?"""
        return len(MARKER_RE.findall(self.all_text_for_marker_scan()))

    def host(self) -> str | None:
        """Return the Host header value, or None if no Host header is present."""
        for name, val in self.headers:
            if name.lower() == "host":
                return val
        return None

    def substituted(self, replacements: list[str | None]) -> "RawRequest":
        """
        Return a NEW RawRequest with markers replaced.

        replacements[i] is the value for marker i (counted left-to-right
        across path -> headers -> body). If replacements[i] is None,
        the marker is replaced with its INNER TEXT (the text between
        the two § marks) - that's what Sniper mode wants when a
        marker isn't the target this iteration.

        len(replacements) must be >= marker_count(); extras are ignored.
        """
        # `idx` is a one-element list so the inner sub_one closure can
        # mutate it. (Python closures can read enclosing-scope variables
        # but not rebind them without `nonlocal` - using a list is a
        # common workaround that works on every Python version.)
        idx = [0]

        def sub_one(m: re.Match) -> str:
            i = idx[0]
            idx[0] += 1
            # If we have a substitution value for this marker, use it.
            # Otherwise fall back to the literal text inside the §§.
            if i < len(replacements) and replacements[i] is not None:
                return replacements[i]
            return m.group(1)

        # Substitute through path, every header value, and body. Order
        # matches `marker_count()`'s scan: path -> headers (in order)
        # -> body, so position indices line up.
        new_path = MARKER_RE.sub(sub_one, self.path)
        new_headers = [(name, MARKER_RE.sub(sub_one, val))
                       for name, val in self.headers]
        new_body = MARKER_RE.sub(sub_one, self.body)
        return RawRequest(method=self.method, path=new_path,
                          headers=new_headers, body=new_body)


# =====================================================================
# ATTACK MODES
# =====================================================================
# Each function is a generator that yields (label, RawRequest) pairs.
# `label` is a string used in console + JSON output to identify
# this particular substitution. The fuzz loop sends each yielded
# RawRequest as-is.

def sniper(template: RawRequest, payloads: list[str]):
    """
    Sniper: one marker at a time, single payload list.

    For N markers and M payloads, this yields N*M requests. Each
    iteration sets exactly ONE marker to a payload value; the rest
    keep their literal text (the text between the §§).
    """
    n = template.marker_count()
    for pos in range(n):
        for p in payloads:
            # Build a substitution list of None's with the payload
            # planted at the target position only.
            subs: list[str | None] = [None] * n
            subs[pos] = p
            label = f"sniper pos={pos} value={p!r}"
            yield label, template.substituted(subs)


def battering_ram(template: RawRequest, payloads: list[str]):
    """
    Battering Ram: SAME payload in EVERY marker, single payload list.

    Yields M requests (one per payload). All N markers get the same
    value simultaneously.
    """
    n = template.marker_count()
    for p in payloads:
        subs = [p] * n
        yield f"ram value={p!r}", template.substituted(subs)


def pitchfork(template: RawRequest, payload_sets: list[list[str]]):
    """
    Pitchfork: K payload lists, iterated in parallel (zip).

    Yields min(len(list_k)) requests. Iteration i puts payload_sets[k][i]
    at marker k. If fewer payload sets than markers, extra markers
    keep their literal text.

    Use case: credential PAIRS that mustn't cross-contaminate.
    """
    n = template.marker_count()
    if len(payload_sets) > n:
        sys.exit(f"[!] pitchfork: {len(payload_sets)} payload lists but only {n} markers")

    # zip(*payload_sets) yields tuples (set0[i], set1[i], ...) until
    # the shortest list runs out.
    for combo in zip(*payload_sets):
        subs: list[str | None] = list(combo) + [None] * (n - len(combo))
        yield f"pitchfork {combo}", template.substituted(subs)


def cluster_bomb(template: RawRequest, payload_sets: list[list[str]]):
    """
    Cluster Bomb: K payload lists, FULL cartesian product.

    Yields product(len(set_k)) requests. EVERY combination is tried.
    Two lists of 100 each = 10,000 requests. Be careful: it grows fast.

    Use case: brute force every (user, pw) combination.
    """
    n = template.marker_count()
    if len(payload_sets) > n:
        sys.exit(f"[!] cluster-bomb: {len(payload_sets)} payload lists but only {n} markers")

    for combo in itertools.product(*payload_sets):
        subs: list[str | None] = list(combo) + [None] * (n - len(combo))
        yield f"cluster {combo}", template.substituted(subs)


# =====================================================================
# MATCHERS
# =====================================================================
@dataclass
class Matcher:
    """
    Bundle of match rules. A response satisfies the matcher iff it
    passes EVERY enabled rule (AND logic). Unset rules are skipped.

    To get OR logic between rules, run the fuzzer multiple times
    with different matchers (or filter the --output JSON file with
    `jq` afterwards).
    """
    status: tuple[float, float, bool] | None = None
    length: tuple[float, float, bool] | None = None
    time_range: tuple[float, float, bool] | None = None
    regex: re.Pattern | None = None
    regex_negate: bool = False              # if True, "regex must NOT match"

    def matches(self, status: int, length: int, body: str, elapsed: float) -> bool:
        if not range_matches(self.status, status):
            return False
        if not range_matches(self.length, length):
            return False
        if not range_matches(self.time_range, elapsed):
            return False
        if self.regex is not None:
            found = self.regex.search(body) is not None
            # Pass when found XOR negate.
            if found == self.regex_negate:
                return False
        return True

    def any_enabled(self) -> bool:
        """True if at least one rule is set. Used to decide whether
        to default-print everything or only hits."""
        return any([
            self.status is not None,
            self.length is not None,
            self.time_range is not None,
            self.regex is not None,
        ])


# =====================================================================
# SEND ONE REQUEST
# =====================================================================
def send(session: requests.Session, raw_req: RawRequest,
         host: str, scheme: str) -> tuple[requests.Response, float]:
    """
    Build a real HTTP request from a RawRequest template and send it.
    Returns (Response, elapsed_seconds).

    Notes:
      - We use the Host from outside (from --url or the original Host
        header), not from raw_req.headers, in case the user pointed
        --url somewhere else. requests will set its own Host header
        from the URL.
      - We DROP Content-Length from the headers we send. `requests`
        computes the correct value automatically from the body after
        substitution; sending the wrong one (the original template's)
        would corrupt the request.
      - We DROP Host header similarly - requests sets it from the URL.
      - allow_redirects=False so we see the actual 3xx response
        instead of automatically following it (same reason as in
        username_enum_solver - 302 is often the success signal).
    """
    url = f"{scheme}://{host}{raw_req.path}"

    # Build a dict of headers EXCEPT Content-Length and Host.
    headers = {}
    for name, val in raw_req.headers:
        ln = name.lower()
        if ln in ("content-length", "host"):
            continue
        headers[name] = val

    start = time.monotonic()
    r = session.request(
        method=raw_req.method,
        url=url,
        headers=headers,
        # Body is sent as raw bytes. UTF-8 encode is safe for ASCII +
        # most form data. For binary bodies you'd need bytes input.
        data=raw_req.body.encode("utf-8", errors="surrogateescape"),
        allow_redirects=False,
        timeout=30,
    )
    elapsed = time.monotonic() - start
    return r, elapsed


def dump_request(raw_req: RawRequest, host: str, scheme: str) -> None:
    """Pretty-print a substituted request for --verbose mode."""
    print(f"    {raw_req.method} {scheme}://{host}{raw_req.path}")
    for name, val in raw_req.headers:
        if name.lower() in ("content-length",):
            continue
        print(f"    {name}: {val}")
    if raw_req.body:
        print()
        print("    " + raw_req.body.replace("\n", "\n    "))


# =====================================================================
# CONFIG OBJECT
# =====================================================================
@dataclass
class FuzzConfig:
    request_text: str
    payload_files: list[Path]
    mode: str
    target_url: str | None
    matcher: Matcher
    output: Path | None              # JSON output
    verbose: bool
    workers: int
    jitter: tuple[float, float]
    fresh_session: bool
    proxy: str | None
    insecure: bool
    retries: int
    encode_chain: list[str] = field(default_factory=list)   # see ENCODERS
    # Additional output formats (alongside --output JSON). All default
    # to None = don't write. Multiple can be enabled at once.
    output_csv: Path | None = None
    output_html: Path | None = None
    output_md: Path | None = None
    # Pre-captured cookies (from login flow / loaded jar / --cookie flags),
    # applied to every Session we build.
    cookies: dict[str, str] = field(default_factory=dict)


# =====================================================================
# MAIN FUZZ LOOP
# =====================================================================
def fuzz(cfg: FuzzConfig) -> None:
    template = RawRequest.parse(cfg.request_text)

    # ---- Determine scheme + host ----
    # Priority: --url override > Host header in template > error.
    if cfg.target_url:
        parsed = urlparse(cfg.target_url)
        scheme = parsed.scheme or "https"
        if not parsed.netloc:
            sys.exit("[!] --url must include scheme + host, e.g. https://example.com")
        host = parsed.netloc
    else:
        host = template.host()
        if not host:
            sys.exit("[!] no Host header in request file and no --url given")
        # No scheme info from a raw request; HTTPS is the safe default
        # for modern web pentest targets (including all PortSwigger labs).
        scheme = "https"

    n_markers = template.marker_count()
    if n_markers == 0:
        sys.exit("[!] no §...§ markers found in the request template")

    # ---- Load payload set(s) ----
    payload_sets = [read_wordlist(p) for p in cfg.payload_files]

    # ---- Apply --encode chain to every payload ----
    # We transform here rather than inside the attack iterators so
    # the encoded form is what shows up in --verbose / --output for
    # debugging. The label is "what was actually sent on the wire."
    if cfg.encode_chain:
        payload_sets = [[apply_encoding(p, cfg.encode_chain) for p in ps]
                        for ps in payload_sets]
        print(f"{tag_info()} encoding : {' -> '.join(cfg.encode_chain)}")

    # ---- Pick the attack iterator + validate payload-set count ----
    if cfg.mode in ("sniper", "battering-ram"):
        if len(payload_sets) != 1:
            sys.exit(f"[!] {cfg.mode} attack mode takes EXACTLY ONE --payload "
                     f"(got {len(payload_sets)})")
        iter_fn = sniper if cfg.mode == "sniper" else battering_ram
        iterations = list(iter_fn(template, payload_sets[0]))
    else:
        iter_fn = pitchfork if cfg.mode == "pitchfork" else cluster_bomb
        iterations = list(iter_fn(template, payload_sets))

    print(f"{tag_info()} target  : {bold(scheme + '://' + host)}")
    print(f"{tag_info()} markers : {n_markers} in template")
    print(f"{tag_info()} payloads: {[len(ps) for ps in payload_sets]}")
    print(f"{tag_info()} mode    : {cfg.mode}")
    print(f"{tag_info()} queued  : {len(iterations)} requests")
    print(f"{tag_info()} workers : {cfg.workers}"
          + (f"  jitter {cfg.jitter[0]}-{cfg.jitter[1]}s" if cfg.jitter[1] > 0 else "")
          + ("  fresh-session" if cfg.fresh_session else ""))
    if cfg.proxy:
        print(f"{tag_info()} proxy   : {cfg.proxy} (TLS verification disabled)")

    # ---- Build shared session unless --fresh-session ----
    shared = None if cfg.fresh_session else build_session(
        cfg.workers, cfg.proxy, cfg.insecure, cfg.retries,
        cookies=cfg.cookies)

    results = []
    first_hit_dumped = False

    def worker(item):
        label, req = item
        maybe_jitter(cfg.jitter)
        sess = (build_session(1, cfg.proxy, cfg.insecure, cfg.retries,
                              cookies=cfg.cookies)
                if cfg.fresh_session else shared)
        try:
            r, elapsed = send(sess, req, host, scheme)
            return label, req, r.status_code, len(r.content), r.text, elapsed, None
        except requests.exceptions.RequestException as e:
            # Connection errors, DNS failures, timeouts, etc.
            return label, req, None, 0, "", 0.0, str(e)

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(worker, it) for it in iterations]
        # Wrap the as_completed iterator in a progress bar so long runs
        # (cluster-bomb against big wordlists can easily be 10,000+
        # requests) show progress instead of looking hung. The bar is
        # a no-op when tqdm isn't installed.
        for fut in progress(as_completed(futures), total=len(futures), desc=cfg.mode):
            label, req, status, length, body, elapsed, err = fut.result()

            if err:
                hit = False
                print(f"{tag_err()} {label}: {err}")
            else:
                hit = cfg.matcher.matches(status, length, body, elapsed)
                # Print either:
                #   - every result if --verbose OR no matchers configured
                #   - only hits if matchers configured and not verbose
                if hit or cfg.verbose or not cfg.matcher.any_enabled():
                    flag = tag_hit() if hit else tag_miss()
                    print(f"{flag} {label}  status={status} len={length} time={elapsed:.2f}s")

                # Dump full first hit when --verbose: invaluable for
                # spotting "oh I substituted in the wrong place" bugs.
                if hit and cfg.verbose and not first_hit_dumped:
                    print("    --- first hit, full request ---")
                    dump_request(req, host, scheme)
                    print("    --- first hit, response body (truncated to 2 KB) ---")
                    print("    " + body[:2000].replace("\n", "\n    "))
                    print("    --- end ---")
                    first_hit_dumped = True

            if cfg.output is not None:
                results.append({
                    "label": label,
                    "status": status,
                    "length": length,
                    "time": round(elapsed, 4),
                    "error": err,
                    "hit": hit,
                })

    # ---- write any enabled output format(s) ----
    n_hits = sum(1 for r in results if r["hit"])
    for fmt, path, writer in [
        ("json", cfg.output,      write_json),
        ("csv",  cfg.output_csv,  write_csv),
        ("html", cfg.output_html, write_html),
        ("md",   cfg.output_md,   write_markdown),
    ]:
        if path is not None:
            writer(results, path)
            print(f"{tag_info()} wrote {len(results)} results ({n_hits} hits) "
                  f"to {path}  ({fmt})")


# =====================================================================
# CLI
# =====================================================================
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # ---- Required positional ----
    ap.add_argument("request_file", type=Path,
                    help="File containing the raw HTTP request template "
                         "with §MARKER§ positions")
    # ---- Payload(s) - required, at least one ----
    ap.add_argument("--payload", type=Path, action="append", required=True,
                    metavar="FILE",
                    help="Wordlist file (one entry per line). Repeat the "
                         "flag for pitchfork/cluster-bomb modes.")
    # ---- Attack mode ----
    ap.add_argument("--mode",
                    choices=["sniper", "battering-ram", "pitchfork", "cluster-bomb"],
                    default="sniper",
                    help="Attack mode (default: sniper)")
    # ---- Target override ----
    ap.add_argument("--url",
                    help="Override target URL (otherwise read scheme=https + "
                         "host from the request's Host header)")
    # ---- Matchers ----
    ap.add_argument("--match-status", type=parse_range_spec, metavar="SPEC",
                    help="Filter by status code. Examples: '200', '200-299', "
                         "'!403'")
    ap.add_argument("--match-length", type=parse_range_spec, metavar="SPEC",
                    help="Filter by body length in bytes. Same syntax as "
                         "--match-status")
    ap.add_argument("--match-time", type=parse_range_spec, metavar="SPEC",
                    help="Filter by response time in seconds")
    ap.add_argument("--match-regex", metavar="PATTERN",
                    help="Python regex; passes if found in body")
    ap.add_argument("--match-not-regex", metavar="PATTERN",
                    help="Python regex; passes if NOT found in body")
    # ---- Output ----
    ap.add_argument("--output", type=Path, metavar="FILE.json",
                    help="Write every result (hit or not) as a JSON array")
    ap.add_argument("--output-csv", type=Path, metavar="FILE.csv",
                    help="Same data as --output, formatted as CSV (Excel/pandas)")
    ap.add_argument("--output-html", type=Path, metavar="FILE.html",
                    help="Standalone HTML report - self-contained, "
                         "openable in a browser, shareable as a single file")
    ap.add_argument("--output-md", type=Path, metavar="FILE.md",
                    help="GitHub-flavored Markdown table")
    ap.add_argument("--verbose", action="store_true",
                    help="Print every result; dump first-hit request + body")
    # ---- Stealth / session (same set as username_enum_solver.py) ----
    ap.add_argument("--workers", type=int, default=10,
                    help="Concurrent requests (default 10)")
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX",
                    help="Random delay before each request, seconds. "
                         "'0.5' = fixed; '0.5-2.0' = random in range")
    ap.add_argument("--fresh-session", action="store_true",
                    help="New Session per request (defeats per-session lockouts)")
    ap.add_argument("--retries", type=int, default=2,
                    help="Retry count on connection errors / 5xx (default 2)")
    # ---- Proxy / TLS ----
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy URL. 'burp' = http://127.0.0.1:8080. "
                         "Auto-enables --insecure")
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS verification (auto-on with --proxy)")
    # ---- Payload encoding ----
    ap.add_argument(
        "--encode",
        type=parse_encode_chain,
        default=[],
        metavar="CHAIN",
        help="Encode each payload before sending. Comma-separated chain of "
             "encoders applied in order. Encoders: "
             "none, url, double-url, base64, hex, html. "
             "Examples: --encode url, --encode url,base64 (URL then base64), "
             "--encode double-url",
    )
    # ---- Authenticated probing ----
    ap.add_argument(
        "--login-url", metavar="URL",
        help="Do a login POST to this URL at startup; cookies set by the "
             "response are reused for every fuzz request.",
    )
    ap.add_argument(
        "--login-data", metavar="FORM",
        help="Form data for the login POST, like a query string: "
             "'username=admin&password=secret'. URL-decoded by parse_qsl.",
    )
    ap.add_argument(
        "--cookie", action="append", default=[], metavar="NAME=VALUE",
        help="Set a cookie manually on every request (repeatable). Use when "
             "you already have a session cookie from your browser and don't "
             "want to re-login.",
    )
    ap.add_argument(
        "--cookie-jar", type=Path, metavar="FILE",
        help="JSON cookie jar. Loaded at startup if it exists; updated after "
             "the login flow (if --login-url is set) so subsequent runs "
             "skip the login.",
    )
    args = ap.parse_args()

    # ---- Build the matcher from the four match-* args ----
    # Either match-regex OR match-not-regex (or neither), but not both,
    # so we keep behavior predictable.
    regex_pattern = None
    regex_negate = False
    if args.match_regex and args.match_not_regex:
        sys.exit("[!] --match-regex and --match-not-regex are mutually exclusive")
    if args.match_regex:
        regex_pattern = re.compile(args.match_regex)
    elif args.match_not_regex:
        regex_pattern = re.compile(args.match_not_regex)
        regex_negate = True

    matcher = Matcher(
        status=args.match_status,
        length=args.match_length,
        time_range=args.match_time,
        regex=regex_pattern,
        regex_negate=regex_negate,
    )

    # ---- Proxy shorthand + auto-insecure ----
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

    # ---- Assemble the starting cookie set ----
    # Priority (later overrides earlier):
    #   1. --cookie-jar file (saved from previous run)
    #   2. --login-url POST result (fresh session this run)
    #   3. --cookie NAME=VALUE flags (explicit overrides)
    cookies: dict[str, str] = {}
    if args.cookie_jar:
        cookies.update(load_cookie_jar(args.cookie_jar))
        if cookies:
            print(f"{tag_info()} loaded {len(cookies)} cookie(s) from {args.cookie_jar}")

    if args.login_url:
        if not args.login_data:
            sys.exit("[!] --login-url requires --login-data")
        # Build a one-off session for the login POST. We pass current
        # cookies in case a previous step (jar) already set something
        # (e.g. a CSRF cookie that the login form needs).
        login_session = build_session(1, proxy, insecure, args.retries,
                                       cookies=cookies)
        login_data = parse_form_data(args.login_data)
        print(f"{tag_info()} logging in: POST {args.login_url}")
        new_cookies = login_and_capture(login_session, args.login_url, login_data)
        cookies.update(new_cookies)
        print(f"{tag_info()} captured {len(new_cookies)} cookie(s) from login response")

    for raw in args.cookie:
        name, val = parse_cookie_pair(raw)
        cookies[name] = val

    # Persist for next run, if the user asked us to.
    if args.cookie_jar and cookies:
        save_cookie_jar(args.cookie_jar, cookies)

    cfg = FuzzConfig(
        request_text=args.request_file.read_text(),
        payload_files=args.payload,
        mode=args.mode,
        target_url=args.url,
        matcher=matcher,
        output=args.output,
        verbose=args.verbose,
        workers=args.workers,
        jitter=args.jitter,
        fresh_session=args.fresh_session,
        proxy=proxy,
        insecure=insecure,
        retries=args.retries,
        encode_chain=args.encode,
        output_csv=args.output_csv,
        output_html=args.output_html,
        output_md=args.output_md,
        cookies=cookies,
    )

    fuzz(cfg)


if __name__ == "__main__":
    main()
