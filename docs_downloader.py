#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
docs_downloader.py - Offline documentation grabber for your VM
=====================================================================

WHAT THIS DOES
--------------
Crawls a docs site / wiki / blog / GitHub README directory and saves
each page as CLEAN PLAIN TEXT inside a local directory. Strips
scripts, styles, navigation chrome, ads - leaves the actual prose.

You then `grep -r 'sleep' your-vault/portswigger` to find every
mention of `SLEEP()` across the entire saved doc set in under a
second. No browser, no JavaScript, no rendering, no thinking.

WHY THIS MATTERS FOR THE BSCP EXAM
----------------------------------
The exam is open-book. The 4-hour clock means burning 60 seconds on
a Google search to remember the MSSQL time-based-blind payload IS
A REAL COST. Multiply by 20 lookups across the exam and that's
20 minutes of avoidable typing + reading + rejecting irrelevant
results.

Build the vault BEFORE the exam:
  python3 docs_downloader.py https://portswigger.net/web-security \\
      --output docs/portswigger --max-pages 500

Then DURING the exam, instant lookup:
  grep -ri 'time-based' docs/portswigger/ | head -20

TWO FILTER MODES
----------------
Use `--filter critical` to grab ONLY exam/vuln-relevant pages
(skips "About us", "Pricing", "Customer Stories", marketing pages,
etc.). Use the default `--filter all` to mirror everything.

  python3 docs_downloader.py https://portswigger.net/web-security \\
      --output docs/portswigger --filter critical    # focused vault
  python3 docs_downloader.py https://portswigger.net/web-security \\
      --output docs/portswigger --filter all         # full mirror

Tune what counts as "critical" with `--filter-words` (text body
match) or `--filter-url-pattern` (URL path match). Use `--dry-run`
to preview WITHOUT writing files - lets you tune the filter
before a long crawl.

WHY THIS BYPASSES BURP (intentional)
------------------------------------
This tool does NOT route through Burp's proxy. Reasons:
  - You're downloading megabytes of unrelated docs - it would clog
    Burp's HTTP History tab with noise.
  - Burp Community throttles all traffic - downloads would crawl.
  - You want this fast and quiet, not interceptable.

The companion `proxy_spider.py` is the opposite - that one ALWAYS
routes through Burp. Use one for attack-surface mapping, this one
for reference building.

FILENAME SANITIZATION (the "Bad Spider" trap)
---------------------------------------------
A URL like `https://example.com/docs/foo/bar?id=1` would be invalid
as a Linux filename (it has '/' and '?'). We sanitize:
  - The hostname becomes a top-level directory.
  - The path is mirrored as nested directories under that.
  - The final segment becomes the filename.
  - `/` `\\` `?` `*` `<` `>` `:` `"` `|` are all replaced with `_`.
  - Query strings become a `_q_KEY_VAL` suffix.
  - Empty paths become `index.txt`.

So `https://example.com/docs/foo/bar?id=1` becomes:
  example.com/docs/foo/bar_q_id_1.txt

Recursive directory creation safe - never creates a filename with
a `/` that would surprise mkdir.

USAGE
-----
Crawl a docs site, save to `vault/`:
  python3 docs_downloader.py https://portswigger.net/web-security --output vault

Limit depth / pages:
  python3 docs_downloader.py https://target --max-pages 100 --max-depth 4

Restrict to a specific path:
  python3 docs_downloader.py https://wiki.example.com \\
      --include-path /Security/ --output vault

Save raw HTML too (alongside the .txt cleaned version):
  python3 docs_downloader.py https://target --output vault --save-html

Be polite to the docs site:
  python3 docs_downloader.py https://target --max-rps 5 --workers 3
"""

import argparse
import html as html_module
import re
import sys
import time
import urllib.parse
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
import urllib3

# Reuse helpers
from intruder import build_session, parse_jitter, maybe_jitter
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, bold, dim, cyan,
)
from _ratelimit import RateLimiter
from proxy_spider import extract_urls, in_scope


# ---------------------------------------------------------------------
# CRITICAL-CONTENT FILTERING (the "only the pages you need" mode)
# =====================================================================
# When --filter critical is set, we save a page ONLY if it looks
# security/vuln-relevant. Pages are still CRAWLED (we extract URLs
# from them so we can reach nested critical pages buried under a
# non-critical hub) - just not WRITTEN to disk.
#
# Two layers, OR'd:
#   1. URL path contains any CRITICAL_URL_PATTERN (cheap, fast)
#   2. Stripped page text contains any CRITICAL_KEYWORD (slower but
#      catches "Security" articles whose URL doesn't make the topic
#      obvious)
#
# Override either with --filter-url-pattern / --filter-words for
# domain-specific tuning.

# Substrings that, when present in a URL path, mark the page as
# critical even before fetching. Lowercased for case-insensitive
# `in` comparison.
CRITICAL_URL_PATTERNS = [
    "security", "vulnerab", "exploit", "payload", "injection",
    "attack", "xss", "csrf", "ssrf", "xxe", "ssti", "sqli",
    "deseriali", "traversal", "auth", "idor", "jwt", "oauth",
    "smuggl", "cors", "csp", "cache", "redirect", "upload",
    "command-inj", "os-command", "template-inj", "ldap",
    "nosql", "graphql", "race", "broken-access", "directory",
    "file-inclusion", "lfi", "rfi", "mass-assign",
    "param-pollut", "host-header", "session", "privilege",
    "escalation", "bypass", "cve-",
]

# Keywords that, when present in the page's stripped text content,
# mark the page as critical. Case-insensitive substring match.
# Tuned for what PortSwigger Academy / OWASP / HackTricks-style
# vuln write-ups typically contain.
CRITICAL_KEYWORDS = [
    # Vulnerability classes
    "sql injection", "cross-site scripting", "cross-site request forgery",
    "server-side request forgery", "xml external entity",
    "server-side template injection", "command injection", "path traversal",
    "directory traversal", "file inclusion", "deserialization",
    "broken access control", "broken authentication",
    "request smuggling", "cache poisoning", "open redirect",
    "ldap injection", "nosql injection",
    "mass assignment", "parameter pollution", "host header",
    "race condition", "session fixation", "session hijacking",
    "privilege escalation", "idor",
    "json web token", "algorithm confusion", "alg=none",
    # Attack techniques
    "blind injection", "time-based", "boolean-based", "union-based",
    "out-of-band", "oast", "collaborator",
    "stored xss", "reflected xss", "dom xss",
    "polyglot", "payload",
    # Concepts that show up in vuln write-ups
    "vulnerability", "exploit", "bypass", "lab solution",
    "content security policy", "samesite", "httponly", "csrf token",
    "cors", "cve-",
]


def is_critical_url(url: str, url_patterns: list[str]) -> bool:
    """True if the URL path contains any critical pattern."""
    path_lower = urllib.parse.urlparse(url).path.lower()
    return any(p in path_lower for p in url_patterns)


def is_critical_text(text: str, keywords: list[str]) -> bool:
    """True if the stripped page text contains any critical keyword."""
    text_lower = text.lower()
    return any(k in text_lower for k in keywords)


def is_critical(url: str, text: str,
                 url_patterns: list[str], keywords: list[str]) -> tuple[bool, str]:
    """
    Compose URL + text checks. Returns (is_critical, reason). The
    reason string is shown in the log so the user understands WHY a
    page was kept or skipped.
    """
    if is_critical_url(url, url_patterns):
        return True, "URL pattern match"
    if is_critical_text(text, keywords):
        return True, "keyword match in body"
    return False, "no critical signal"


# ---------------------------------------------------------------------
# HTML -> CLEAN TEXT
# ---------------------------------------------------------------------
# These patterns strip everything that's not the actual readable
# content. We're aggressive because docs sites are typically full
# of nav chrome, footers, sidebars, cookie banners.
_NOISE_PATTERNS = [
    # Block-level noise tags (everything inside disappears).
    (re.compile(r"<script\b[^>]*>.*?</script\s*>",   re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<style\b[^>]*>.*?</style\s*>",     re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<noscript\b[^>]*>.*?</noscript\s*>", re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<svg\b[^>]*>.*?</svg\s*>",         re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<nav\b[^>]*>.*?</nav\s*>",         re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<footer\b[^>]*>.*?</footer\s*>",   re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<header\b[^>]*>.*?</header\s*>",   re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<aside\b[^>]*>.*?</aside\s*>",     re.DOTALL | re.IGNORECASE), ""),
    (re.compile(r"<form\b[^>]*>.*?</form\s*>",       re.DOTALL | re.IGNORECASE), ""),
    # HTML comments
    (re.compile(r"<!--.*?-->",                        re.DOTALL),                 ""),
]


def html_to_text(html: str) -> str:
    """
    Convert HTML to readable plain text. Strips noise tags, removes
    all remaining tags, decodes entities, collapses whitespace.
    """
    out = html
    for pattern, replacement in _NOISE_PATTERNS:
        out = pattern.sub(replacement, out)
    # Now strip ALL remaining tags - keep only their text content.
    out = re.sub(r"<[^>]+>", " ", out)
    # Decode HTML entities (&amp; -> &, &lt; -> <, &#65; -> A, etc.)
    out = html_module.unescape(out)
    # Collapse whitespace: runs of spaces/tabs -> single space,
    # runs of >2 newlines -> 2 newlines (preserve paragraph breaks).
    out = re.sub(r"[ \t\f\v]+", " ", out)
    out = re.sub(r"\n\s*\n+", "\n\n", out)
    return out.strip()


# ---------------------------------------------------------------------
# URL -> SAFE LINUX FILENAME (the "Bad Spider" trap fix)
# ---------------------------------------------------------------------
_UNSAFE_CHARS = re.compile(r'[/\\?*<>:"|]')


def url_to_path(url: str, root: Path, ext: str = ".txt") -> Path:
    """
    Convert a URL into a safe nested file path under `root`.

    Examples:
      https://example.com/                 -> root/example.com/index.txt
      https://example.com/docs/foo         -> root/example.com/docs/foo.txt
      https://example.com/docs/foo.html    -> root/example.com/docs/foo.html.txt
      https://example.com/docs/foo?id=1    -> root/example.com/docs/foo_q_id_1.txt
      https://example.com/a//b/../c        -> root/example.com/a/c.txt (normalized)

    Filename invariants we maintain:
      - No `/`, `\\`, `?`, `*`, `<`, `>`, `:`, `"`, `|` in any segment
        EXCEPT the host directory + dir separators we create
      - Empty paths become `index<ext>`
      - Trailing slashes become `<path>/index<ext>`
      - Query strings encoded as `_q_<key>_<val>` suffix
    """
    parsed = urllib.parse.urlparse(url)
    host = _UNSAFE_CHARS.sub("_", parsed.hostname or "unknown")

    # Normalize and split the path. urllib.parse handles `..` resolution
    # somewhat but we still want to clean.
    path = parsed.path or "/"
    # Trailing slash means "directory" - we'll add index
    is_dir_like = path.endswith("/")

    segments = [seg for seg in path.split("/") if seg]
    # Sanitize each segment
    safe_segments = []
    for seg in segments:
        # Resolve `..` by popping
        if seg == "..":
            if safe_segments:
                safe_segments.pop()
            continue
        if seg == ".":
            continue
        # URL-decode then sanitize - `space` -> `_`, special chars -> `_`
        decoded = urllib.parse.unquote(seg)
        clean = _UNSAFE_CHARS.sub("_", decoded)
        # Replace whitespace + control chars
        clean = re.sub(r"\s+", "_", clean)
        # Cap segment length to prevent path-too-long errors
        if len(clean) > 200:
            clean = clean[:200]
        safe_segments.append(clean)

    # Query string -> filename suffix
    if parsed.query:
        suffix_parts = []
        for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
            k_clean = _UNSAFE_CHARS.sub("_", k)
            v_clean = _UNSAFE_CHARS.sub("_", v)[:50]   # cap value length
            suffix_parts.append(f"{k_clean}_{v_clean}")
        query_suffix = "_q_" + "_".join(suffix_parts)
    else:
        query_suffix = ""

    # Build the path
    out = root / host
    for seg in safe_segments[:-1]:
        out = out / seg
    if not safe_segments or is_dir_like:
        # Directory-like: file becomes index<ext>
        if safe_segments:
            out = out / safe_segments[-1]
        out = out / f"index{query_suffix}{ext}"
    else:
        last = safe_segments[-1]
        # Don't append ext if filename already has an extension that
        # makes sense; just append the .txt suffix for clarity.
        out = out / f"{last}{query_suffix}{ext}"

    return out


# ---------------------------------------------------------------------
# CRAWL + SAVE
# ---------------------------------------------------------------------
def download(args, session: requests.Session) -> dict:
    """BFS crawl, save each page's clean text to disk."""
    base_parsed = urllib.parse.urlparse(args.url)
    base_host = base_parsed.netloc

    visited: set[str] = set()
    saved: list[tuple[str, Path]] = []   # (url, path)
    errors: dict[str, str] = {}

    frontier: deque[tuple[str, int]] = deque([(args.url, 0)])
    rate_limiter = RateLimiter(max_rps=args.max_rps)

    # Resolve final filter lists - CLI overrides take precedence.
    url_patterns = (args.filter_url_pattern.split(",") if args.filter_url_pattern
                     else CRITICAL_URL_PATTERNS)
    keywords = (args.filter_words.split(",") if args.filter_words
                else CRITICAL_KEYWORDS)
    url_patterns = [p.strip().lower() for p in url_patterns if p.strip()]
    keywords = [k.strip().lower() for k in keywords if k.strip()]

    print(f"{tag_info()} start: {bold(args.url)}")
    print(f"{tag_info()} output dir: {bold(str(args.output))}")
    print(f"{tag_info()} bypassing proxy (intentional - speed + cleanliness)")
    print(f"{tag_info()} filter mode: {bold(args.filter)}", end="")
    if args.filter == "critical":
        print(f"  ({len(url_patterns)} URL patterns, {len(keywords)} keywords)")
    else:
        print("  (save every page)")
    if args.dry_run:
        print(f"{tag_warn()} dry-run: NO files will be written")
    print(f"{tag_info()} limits: max-pages={args.max_pages} depth={args.max_depth} workers={args.workers}")
    print()

    skipped_filter = 0

    args.output.mkdir(parents=True, exist_ok=True)

    while frontier and len(visited) < args.max_pages:
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
                r = session.get(url, allow_redirects=True, timeout=20)
                rate_limiter.report_response(r.status_code)
                return url, depth, r.status_code, r.text, None
            except requests.exceptions.RequestException as e:
                rate_limiter.report_response(None)
                return url, depth, None, "", str(e)

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futures = [ex.submit(fetch, ud) for ud in batch]
            for fut in as_completed(futures):
                url, depth, status, body, err = fut.result()
                if err:
                    errors[url] = err
                    print(f"{tag_err()} {url}: {err}")
                    continue
                if status >= 400:
                    print(f"  [{status}]  skipping (HTTP error)  {url}")
                    continue

                # Strip to plain text before the critical-filter decision
                # (URL might not look critical but body text might mention
                # "SQL injection" - we still want to keep it).
                text = html_to_text(body)
                out_path = url_to_path(url, args.output)

                # Filter decision
                if args.filter == "critical":
                    keep, reason = is_critical(url, text, url_patterns, keywords)
                    if not keep:
                        skipped_filter += 1
                        print(f"  [{status}]  {dim('skip-filter')}  {url}  "
                              f"{dim('(' + reason + ')')}")
                        # IMPORTANT: still extract URLs + queue them so we
                        # can reach critical pages buried under non-critical
                        # hub pages.
                        if depth < args.max_depth:
                            for new_url in extract_urls(body, url):
                                if new_url in visited:
                                    continue
                                if not in_scope(new_url, base_host, args):
                                    continue
                                frontier.append((new_url, depth + 1))
                        continue
                    log_reason = f" ({reason})"
                else:
                    log_reason = ""

                if args.dry_run:
                    print(f"  [{status}]  would-save  {url}{log_reason}")
                    saved.append((url, out_path))
                else:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.write_text(text, encoding="utf-8")
                    saved.append((url, out_path))
                    print(f"  [{status}]  saved -> {dim(str(out_path))}{log_reason}")
                    if args.save_html:
                        html_path = out_path.with_suffix(".html")
                        html_path.write_text(body, encoding="utf-8", errors="replace")

                # Queue new URLs that are in-scope + below max depth
                if depth < args.max_depth:
                    new_urls = extract_urls(body, url)
                    for new_url in new_urls:
                        if new_url in visited:
                            continue
                        if not in_scope(new_url, base_host, args):
                            continue
                        frontier.append((new_url, depth + 1))

    print()
    print(f"{tag_ok()} download complete")
    print(f"{tag_info()} pages saved : {len(saved)}")
    if errors:
        print(f"{tag_warn()} errors      : {len(errors)}")
    print()
    print(f"{tag_info()} now grep your vault:")
    print(f"  grep -ri 'time-based' {args.output}/")
    print(f"  grep -ri 'CSRF token' {args.output}/")

    return {
        "start_url": args.url,
        "saved_count": len(saved),
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
                    help="Docs URL to start from  "
                         "(example: https://portswigger.net/web-security)")
    ap.add_argument("--output", type=Path, required=True,
                    help="Output directory to mirror the doc tree into")

    # Scope
    ap.add_argument("--any-host", action="store_true",
                    help="Crawl any host you find (default: same-host only)")
    ap.add_argument("--include-path", default="",
                    help="Only follow URLs whose path starts with this prefix")
    ap.add_argument("--exclude-path", default="",
                    help="Drop URLs whose path matches this prefix "
                         "(e.g. --exclude-path /api/  to skip noisy API pages)")
    ap.add_argument("--max-pages", type=int, default=500)
    ap.add_argument("--max-depth", type=int, default=6)

    # Filter mode - the headline feature.
    ap.add_argument("--filter", choices=["all", "critical"], default="all",
                    help="all: save every in-scope page (default, current behavior). "
                         "critical: only save pages whose URL or text content looks "
                         "vuln/exam-relevant. Non-critical pages are still CRAWLED "
                         "(their URLs feed the frontier) but not written to disk - "
                         "so a non-critical hub linking to critical leaf pages still "
                         "works.")
    ap.add_argument("--filter-words", default="",
                    help="Comma-separated list of keywords to OVERRIDE the built-in "
                         "CRITICAL_KEYWORDS list. Match is case-insensitive substring "
                         "against the stripped page text. "
                         "Example: --filter-words 'jwt,oauth,saml'")
    ap.add_argument("--filter-url-pattern", default="",
                    help="Comma-separated list of substrings to OVERRIDE the built-in "
                         "CRITICAL_URL_PATTERNS list. Match is case-insensitive against "
                         "the URL path. "
                         "Example: --filter-url-pattern '/labs/,/cheatsheet/'")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what WOULD be saved without writing any files. "
                         "Useful for tuning --filter-words / --filter-url-pattern "
                         "before committing to a big crawl.")

    # Behavior
    ap.add_argument("--save-html", action="store_true",
                    help="Also save the raw HTML alongside each .txt file "
                         "(useful if you want to view a doc as it originally looked)")
    ap.add_argument("--workers", type=int, default=8)
    ap.add_argument("--max-rps", type=float, default=15.0)
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--insecure", action="store_true")

    args = ap.parse_args()

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # IMPORTANT: no proxy. Speed + don't pollute Burp's history.
    session = build_session(args.workers, proxy=None, insecure=args.insecure,
                              retries=args.retries)

    download(args, session)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        print("interrupted")
        sys.exit(130)
