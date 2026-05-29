#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
proxy_spider.py - Burp-proxy-routing URL + form-param spider
=====================================================================

WHAT THIS DOES
--------------
Crawls a target site, extracts every link / form action / form input
name it finds, and ALWAYS sends each request through Burp's proxy
listener so the traffic lands in Burp's HTTP History tab.

End result: in a few minutes you've pre-populated Burp with the
target's attack surface - every endpoint your browser would
eventually visit, plus every form input the server accepts. From
there you can drop straight into Repeater / Intruder / Scanner
without manually clicking through the app.

WHY THIS (vs Burp's built-in crawler / spider)
----------------------------------------------
Burp Pro has a built-in crawler. Burp Community does NOT. This is
the free-edition equivalent: explicit, scriptable, and you control
the scope.

Even with Pro, this script is useful for:
  - quickly hydrating Burp with the whole attack surface BEFORE you
    start manual testing (saves clicking through the app)
  - re-running the same crawl with different cookies (admin vs user)
    to see role-gated endpoints
  - controlling scope precisely (same-host only / single-path / etc.)

EXTRACTED EVERYTHING
--------------------
For each page visited we pull URLs from:
  - <a href="...">                anchor links
  - <form action="...">           form submission targets
  - <link href="...">             stylesheet / preload / icon URLs
  - <script src="...">            JS files (often reveal more endpoints
                                  hardcoded inside them - worth fetching)
  - <img src="...">               image URLs (sometimes leak paths)
  - <iframe src="...">            iframed content
  - <source src="...">            video/audio sources

And form parameter names from:
  - <input name="...">
  - <textarea name="...">
  - <select name="...">
  - <button name="...">

Parameter names are valuable because they tell you WHAT the server
accepts even on endpoints you never POST to.

SCOPE CONTROL
-------------
Default scope: same-host only. URLs pointing at a different host
(CDNs, analytics, ad networks) are dropped before being queued.

  --same-host          (default) only crawl URLs on the start host
  --any-host           crawl everything you find (be careful)
  --include-path /api  only follow URLs whose path starts with /api
  --exclude-path /logout
                       drop URLs whose path matches (avoid logging
                       yourself out mid-crawl)

PROXY
-----
By default we route through `http://127.0.0.1:8080` - Burp's default
listener. Override with `--proxy URL`. If you DON'T want proxy
routing (just a local URL discovery), pass `--no-proxy`.

USAGE
-----
  python3 proxy_spider.py https://YOUR-LAB.web-security-academy.net
  python3 proxy_spider.py https://target --proxy http://127.0.0.1:8080
  python3 proxy_spider.py https://target --max-pages 200 --workers 5
  python3 proxy_spider.py https://target --cookie-jar admin.json
  python3 proxy_spider.py https://target --output spider-results.json

For the launcher: pick "Proxy spider (hydrate Burp + map attack surface)".
"""

import argparse
import json
import re
import sys
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

# Reuse helpers from existing tools.
from intruder import (
    build_session, parse_jitter, maybe_jitter, parse_cookie_pair,
    load_cookie_jar, save_cookie_jar, login_and_capture, parse_form_data,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, bold, dim, cyan,
    progress,
)
from _ratelimit import RateLimiter


# ---------------------------------------------------------------------
# HTML PARSERS
# ---------------------------------------------------------------------
# We use regex instead of bs4 / html.parser because:
#  1. No new dependency
#  2. Forgiving on malformed HTML (apps deployed under stress are
#     often partially broken)
#  3. Fast enough for crawling - we don't need full DOM fidelity

# Each pattern captures the URL value in group 1.
URL_PATTERNS = [
    (re.compile(r'<a\b[^>]*\bhref=["\']([^"\']+)["\']',     re.IGNORECASE),  "<a href>"),
    (re.compile(r'<form\b[^>]*\baction=["\']([^"\']+)["\']', re.IGNORECASE),  "<form action>"),
    (re.compile(r'<link\b[^>]*\bhref=["\']([^"\']+)["\']',   re.IGNORECASE),  "<link href>"),
    (re.compile(r'<script\b[^>]*\bsrc=["\']([^"\']+)["\']',  re.IGNORECASE),  "<script src>"),
    (re.compile(r'<img\b[^>]*\bsrc=["\']([^"\']+)["\']',     re.IGNORECASE),  "<img src>"),
    (re.compile(r'<iframe\b[^>]*\bsrc=["\']([^"\']+)["\']',  re.IGNORECASE),  "<iframe src>"),
    (re.compile(r'<source\b[^>]*\bsrc=["\']([^"\']+)["\']',  re.IGNORECASE),  "<source src>"),
]

# Form parameter names: <input/textarea/select/button name="...">
FORM_PARAM_RE = re.compile(
    r'<(?:input|textarea|select|button)\b[^>]*\bname=["\']([^"\']+)["\']',
    re.IGNORECASE,
)


def extract_urls(html: str, base_url: str) -> set[str]:
    """
    Find every URL in `html` and resolve relative paths against
    `base_url`. Fragment-only links (`#section`) and javascript:/mailto:
    are dropped.
    """
    found: set[str] = set()
    for pattern, _label in URL_PATTERNS:
        for m in pattern.finditer(html):
            raw = m.group(1).strip()
            if not raw or raw.startswith(("#", "javascript:", "mailto:",
                                            "tel:", "data:")):
                continue
            # urljoin handles relative paths, ../, missing scheme, etc.
            resolved = urllib.parse.urljoin(base_url, raw)
            # Strip fragment
            resolved = resolved.split("#", 1)[0]
            found.add(resolved)
    return found


def extract_form_params(html: str) -> set[str]:
    """Return every form input name found in the HTML."""
    return set(FORM_PARAM_RE.findall(html))


# ---------------------------------------------------------------------
# SCOPE
# ---------------------------------------------------------------------
def in_scope(url: str, base_host: str, args) -> bool:
    """
    Decide whether a discovered URL is in our crawl scope. Defaults
    to "same-host only" because crawling the whole internet from a
    lab page is rarely what you want.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return False
    if not parsed.netloc:
        return False
    if not args.any_host and parsed.netloc != base_host:
        return False
    if args.include_path and not parsed.path.startswith(args.include_path):
        return False
    if args.exclude_path and parsed.path.startswith(args.exclude_path):
        return False
    return True


# ---------------------------------------------------------------------
# CRAWL
# ---------------------------------------------------------------------
def crawl(args, session: requests.Session) -> dict:
    """
    BFS crawl. Returns a results dict with discovered URLs + form
    parameters + per-URL HTTP status.
    """
    start_parsed = urllib.parse.urlparse(args.url)
    base_host = start_parsed.netloc

    # Visited == URLs we've FETCHED. Discovered == seen anywhere.
    visited: set[str] = set()
    discovered: set[str] = {args.url}
    form_params: set[str] = set()
    statuses: dict[str, int] = {}
    errors: dict[str, str] = {}

    # BFS frontier with depth tracking
    frontier: deque[tuple[str, int]] = deque([(args.url, 0)])

    rate_limiter = RateLimiter(max_rps=args.max_rps)

    print(f"{tag_info()} start: {bold(args.url)}")
    print(f"{tag_info()} routing through: {cyan(args.proxy) if args.proxy else dim('(no proxy)')}")
    print(f"{tag_info()} scope: {'any-host' if args.any_host else f'same-host ({base_host})'}")
    print(f"{tag_info()} limits: max-pages={args.max_pages}  max-depth={args.max_depth}  workers={args.workers}")
    print()

    while frontier and len(visited) < args.max_pages:
        # Pop a batch sized to the worker pool.
        batch = []
        while frontier and len(batch) < args.workers:
            url, depth = frontier.popleft()
            if url in visited:
                continue
            visited.add(url)
            batch.append((url, depth))
        if not batch:
            break

        def fetch(url_depth):
            url, depth = url_depth
            rate_limiter.wait_if_needed()
            maybe_jitter(args.jitter)
            try:
                r = session.get(url, allow_redirects=False, timeout=20)
                rate_limiter.report_response(r.status_code)
                return url, depth, r.status_code, r.text, r.headers.get("Location", ""), None
            except requests.exceptions.RequestException as e:
                rate_limiter.report_response(None)
                return url, depth, None, "", "", str(e)

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(fetch, ud) for ud in batch]
            for fut in as_completed(futures):
                url, depth, status, body, location, err = fut.result()
                if err:
                    errors[url] = err
                    print(f"{tag_err()} {url}: {err}")
                    continue
                statuses[url] = status
                print(f"  [{status}]  depth={depth}  {url}")

                # Follow redirects (count toward depth) so we don't
                # miss content gated by /login -> /my-account etc.
                if location and status in (301, 302, 307, 308):
                    redir_url = urllib.parse.urljoin(url, location).split("#")[0]
                    if redir_url not in visited and in_scope(redir_url, base_host, args):
                        if depth < args.max_depth:
                            frontier.append((redir_url, depth + 1))
                        discovered.add(redir_url)

                # Extract URLs + params from the body
                new_urls = extract_urls(body, url)
                discovered.update(new_urls)
                form_params.update(extract_form_params(body))

                # Queue new URLs that are in scope + below max depth
                if depth < args.max_depth:
                    for new_url in new_urls:
                        if new_url in visited:
                            continue
                        if not in_scope(new_url, base_host, args):
                            continue
                        frontier.append((new_url, depth + 1))

    print()
    print(f"{tag_ok()} crawl complete")
    print(f"{tag_info()} pages fetched : {len(visited)}")
    print(f"{tag_info()} URLs known    : {len(discovered)} (including unfetched)")
    print(f"{tag_info()} form params   : {len(form_params)}")
    if errors:
        print(f"{tag_warn()} errors        : {len(errors)}")
    if args.proxy:
        print(f"{tag_info()} all traffic now in Burp's HTTP History  ({args.proxy})")

    return {
        "start_url": args.url,
        "pages_fetched": sorted(visited),
        "all_discovered_urls": sorted(discovered),
        "form_param_names": sorted(form_params),
        "statuses": statuses,
        "errors": errors,
    }


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("url",
                    help="Target URL to crawl  (example: https://target/admin)")

    # Scope
    ap.add_argument("--any-host", action="store_true",
                    help="Crawl any host you find (default: same-host only)")
    ap.add_argument("--include-path", default="",
                    help="Only follow URLs whose path starts with this prefix")
    ap.add_argument("--exclude-path", default="",
                    help="Drop URLs whose path starts with this  "
                         "(e.g. --exclude-path /logout)")
    ap.add_argument("--max-pages", type=int, default=200,
                    help="Stop after this many pages (default 200)")
    ap.add_argument("--max-depth", type=int, default=5,
                    help="BFS depth limit (default 5)")

    # Proxy
    ap.add_argument("--proxy", default="http://127.0.0.1:8080", metavar="URL",
                    help="Proxy URL (default Burp's listener at 127.0.0.1:8080). "
                         "Pass 'burp' as shorthand. Use --no-proxy to skip.")
    ap.add_argument("--no-proxy", action="store_true",
                    help="Disable proxy routing entirely  "
                         "(useful for testing the spider without Burp running)")
    ap.add_argument("--insecure", action="store_true", default=True,
                    help="Skip TLS verification (default: on - Burp re-signs)")

    # Tuning
    ap.add_argument("--workers", type=int, default=5,
                    help="Concurrent requests (default 5; low to avoid hammering)")
    ap.add_argument("--max-rps", type=float, default=10.0, metavar="N",
                    help="Cap requests per second (default 10)")
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX",
                    help="Random delay before each request")
    ap.add_argument("--retries", type=int, default=2)

    # Auth
    ap.add_argument("--cookie-jar", type=Path,
                    help="Pre-load a JSON cookie jar (e.g. from intruder)")
    ap.add_argument("--cookie", action="append", default=[],
                    metavar="NAME=VALUE", help="Manual cookie (repeatable)")
    ap.add_argument("--login-url",
                    help="Login URL - we POST credentials at startup so the "
                         "crawl runs authenticated")
    ap.add_argument("--login-data",
                    help="Form data for login (e.g. 'user=admin&pass=admin')")

    # Output
    ap.add_argument("--output", type=Path,
                    help="Write results (URLs, params, statuses) as JSON")

    args = ap.parse_args()

    # Proxy URL handling
    proxy = "" if args.no_proxy else args.proxy
    if proxy and proxy.strip().lower() == "burp":
        proxy = "http://127.0.0.1:8080"
    args.proxy = proxy

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Build cookies
    cookies: dict[str, str] = {}
    if args.cookie_jar:
        cookies.update(load_cookie_jar(args.cookie_jar))
    for raw in args.cookie:
        name, val = parse_cookie_pair(raw)
        cookies[name] = val

    session = build_session(args.workers, proxy=proxy, insecure=args.insecure,
                              retries=args.retries, cookies=cookies)

    if args.login_url:
        if not args.login_data:
            sys.exit(f"{tag_err()} --login-url requires --login-data")
        new_cookies = login_and_capture(session, args.login_url,
                                          parse_form_data(args.login_data))
        print(f"{tag_info()} login captured {len(new_cookies)} cookie(s)")

    results = crawl(args, session)

    if args.output:
        args.output.write_text(json.dumps(results, indent=2) + "\n")
        print(f"{tag_info()} wrote results to {args.output}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("interrupted")
        sys.exit(130)
