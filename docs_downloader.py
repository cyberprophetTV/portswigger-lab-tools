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

    print(f"{tag_info()} start: {bold(args.url)}")
    print(f"{tag_info()} output dir: {bold(str(args.output))}")
    print(f"{tag_info()} bypassing proxy (intentional - speed + cleanliness)")
    print(f"{tag_info()} limits: max-pages={args.max_pages} depth={args.max_depth} workers={args.workers}")
    print()

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

                # Save cleaned text
                text = html_to_text(body)
                out_path = url_to_path(url, args.output)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(text, encoding="utf-8")
                saved.append((url, out_path))
                print(f"  [{status}]  saved -> {dim(str(out_path))}")

                # Optionally save raw HTML alongside
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
