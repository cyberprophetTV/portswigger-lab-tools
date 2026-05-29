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
Use `--filter critical` to grab ONLY pages where we DETECT actual
attack surface - real forms, real injectable parameters, real
file uploads, real password fields, real JSON API responses. We
do NOT guess from URL keywords or page text; we look at what's
actually on the page:

  - URL has query params with names like id, q, file, url,
    redirect, token, ...  (the URL itself is an injection point)
  - <input type="file">                    (upload class)
  - <input type="password">                (auth/login class)
  - <form> with <input type="text|email|...">  or  <textarea>
                                           (generic input boundary)
  - Body starts with `{` or `[` or `<?xml`  (API response)

Pages with NONE of those = no attack surface = not saved (but
still crawled, so we can follow links to pages that DO have it).
Use `--filter all` to keep the old behavior and mirror every
in-scope page regardless of surface.

  python3 docs_downloader.py https://target.com \\
      --output target_surface --filter critical    # vulnerable pages only
  python3 docs_downloader.py https://target.com \\
      --output target_full --filter all            # full mirror

Use `--dry-run` to preview which pages would be saved without
writing them - lets you see what surface a target exposes
without committing to a full crawl.

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
# CRITICAL-CONTENT FILTERING - "page has actual attack surface"
# =====================================================================
# `--filter critical` saves a page ONLY if we can detect ACTUAL
# vulnerable surface on it - real forms, real injectable parameters,
# real file uploads, real password fields, real JSON API responses.
# We do NOT guess from URL keywords or page text. If the page has
# nothing you could put a payload into, we don't save it.
#
# Pages without surface are still CRAWLED (we extract their links so
# we can reach attack-surface pages they link to) - just not written
# to disk.
#
# Signals we check, in order they're reported:
#   1. URL query params (?id=1, ?file=, ?q=...) - the URL is itself
#      an injection point. Names matching INJECTABLE_PARAM_NAMES are
#      called out specifically; generic params are still kept.
#   2. <input type="file"> - file upload (RCE / XXE / unrestricted
#      upload class).
#   3. <input type="password"> - login form (auth bypass / SQLi in
#      login / brute force / 2FA logic flaws).
#   4. <form> with text/search/email/url/number/tel inputs or
#      <textarea> - generic input boundary (XSS / SQLi / SSTI).
#      Reported with input names when those look injectable.
#   5. JSON/XML response body - API endpoints are attack surface
#      even without HTML forms.

# Parameter names that historically map to injectable surface across
# vuln classes. Used to decorate URL query params and form input
# names with "looks injectable" callouts. Lowercased for matching.
INJECTABLE_PARAM_NAMES: set[str] = {
    # Identifiers / lookups (IDOR, SQLi)
    "id", "uid", "user_id", "userid", "pid", "item", "item_id",
    "product", "product_id", "order", "order_id", "cat", "cat_id",
    "category", "category_id", "page_id", "post", "post_id",
    "account", "account_id", "comment_id", "blog", "blog_id",
    # Searches / queries (XSS, SQLi)
    "q", "query", "search", "s", "keyword", "kw", "term",
    # File / path (LFI, RFI, traversal, upload)
    "file", "filename", "path", "dir", "directory", "document",
    "include", "template", "load", "read", "download",
    # Redirects (open redirect, SSRF)
    "url", "uri", "redirect", "return", "returnurl", "next", "goto",
    "callback", "continue", "dest", "destination", "rurl", "redir",
    "target", "redirect_uri", "redirecturl",
    # Network (SSRF)
    "host", "hostname", "domain", "site", "website", "addr",
    "server", "endpoint", "feed",
    # Commands (RCE)
    "cmd", "command", "exec", "system", "do", "action",
    # Auth / tokens
    "token", "key", "apikey", "api_key", "access_token",
    "auth", "session", "sessionid", "session_id", "code",
    "csrf", "csrftoken", "csrf_token",
    # Data blobs (deserialization, XXE, NoSQL, prototype pollution)
    "data", "json", "xml", "yaml", "object", "serial", "payload",
    "proto", "__proto__",
    # User input (XSS, comments, stored attacks)
    "name", "username", "user", "email", "comment", "message",
    "subject", "title", "body", "text", "content", "description",
    "address", "phone", "feedback", "review",
    # Locale (template injection, LFI via lang)
    "lang", "language", "locale", "l10n",
    # Generic / catch-all
    "param", "value", "val", "arg", "input",
}

# HTML input types that take user-typed content (i.e. inject-able).
# `hidden` IS included - hidden inputs in forms often hold serialized
# state or CSRF tokens that are still attackable.
INJECTABLE_INPUT_TYPES: set[str] = {
    "text", "search", "email", "url", "number", "tel",
    "password", "hidden",
}

_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form\s*>",
                       re.DOTALL | re.IGNORECASE)
_INPUT_TAG_RE = re.compile(r"<input\b([^>]*?)/?>", re.IGNORECASE)
_TYPE_ATTR_RE = re.compile(r'\btype\s*=\s*["\']?([a-zA-Z]+)["\']?',
                            re.IGNORECASE)
_NAME_ATTR_RE = re.compile(r'\bname\s*=\s*["\']?([^"\'\s>]+)',
                            re.IGNORECASE)
_TEXTAREA_RE = re.compile(r"<textarea\b", re.IGNORECASE)
_FILE_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?file["\']?', re.IGNORECASE)
_PASSWORD_INPUT_RE = re.compile(
    r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?', re.IGNORECASE)


def _input_is_text_like(attrs: str) -> bool:
    """An <input>'s attribute string represents a text-like input
    if type is absent (defaults to text) OR is one of the
    inject-able types listed above."""
    m = _TYPE_ATTR_RE.search(attrs)
    if not m:
        return True
    return m.group(1).lower() in INJECTABLE_INPUT_TYPES


def detect_attack_surface(url: str, html: str) -> list[str]:
    """
    Inspect a URL + HTML body for real attack surface. Returns a
    list of human-readable signal strings. An empty list means NO
    attack surface was found and the page should be skipped in
    critical mode.

    Detection is signature-based, NOT keyword-based - we look at
    what's actually on the page (forms, input types, query params,
    response shape), not at what's written in the prose.
    """
    signals: list[str] = []

    # 1. URL query parameters - the URL is itself an injection point.
    query = urllib.parse.urlparse(url).query
    if query:
        param_names = [k.lower() for k, _ in
                        urllib.parse.parse_qsl(query, keep_blank_values=True)]
        injectable = [p for p in param_names if p in INJECTABLE_PARAM_NAMES]
        if injectable:
            signals.append(f"URL injectable params: {', '.join(injectable[:3])}")
        elif param_names:
            signals.append(f"URL query params: {', '.join(param_names[:3])}")

    # 2. File upload (very high signal: RCE / XXE / unrestricted upload).
    if _FILE_INPUT_RE.search(html):
        signals.append("file upload field")

    # 3. Password input -> login form (auth-class attack surface).
    if _PASSWORD_INPUT_RE.search(html):
        signals.append("password/login form")

    # 4. <form> tags with text-like inputs or <textarea>. Track
    #    injectable-looking input names separately for the report.
    forms_with_text = 0
    injectable_input_names: set[str] = set()
    for form_body in _FORM_RE.findall(html):
        input_attr_blocks = _INPUT_TAG_RE.findall(form_body)
        has_text_input = any(_input_is_text_like(a) for a in input_attr_blocks)
        has_textarea = bool(_TEXTAREA_RE.search(form_body))
        if not (has_text_input or has_textarea):
            continue
        forms_with_text += 1
        # Collect names of inputs / textareas / selects
        for tag in (input_attr_blocks
                     + _TEXTAREA_RE.findall(form_body)):
            if isinstance(tag, str):
                m = _NAME_ATTR_RE.search(tag)
                if m and m.group(1).lower() in INJECTABLE_PARAM_NAMES:
                    injectable_input_names.add(m.group(1).lower())

    if injectable_input_names:
        signals.append("form input names look injectable: "
                       + ", ".join(sorted(injectable_input_names)[:3]))
    elif forms_with_text:
        signals.append(f"{forms_with_text} form(s) with text inputs")

    # 5. JSON / XML response body - API endpoint attack surface.
    leading = html.lstrip()[:6]
    if leading.startswith(("{", "[")):
        signals.append("JSON-shaped response body")
    elif leading.startswith("<?xml"):
        signals.append("XML response body")

    return signals


def decide_critical(url: str, html: str) -> tuple[bool, str]:
    """
    Critical-mode decision: keep the page iff we can detect actual
    attack surface in its URL + HTML.

    Returns (keep, reason). The reason is the joined signal list
    when keeping, or "no attack surface detected" when skipping.
    """
    signals = detect_attack_surface(url, html)
    if signals:
        return True, "; ".join(signals[:3])
    return False, "no attack surface detected"


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
    print(f"{tag_info()} filter mode: {bold(args.filter)}", end="")
    if args.filter == "critical":
        print("  (save ONLY pages with real attack surface: "
              "forms / file uploads / login fields / injectable params / JSON APIs)")
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
                    keep, reason = decide_critical(url, body)
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
                    help="all: save every in-scope page (default). "
                         "critical: keep ONLY pages where we can detect actual "
                         "attack surface - forms with text/password/textarea "
                         "inputs, file upload fields, query params with "
                         "injectable-looking names (id/q/file/url/...), JSON or "
                         "XML response bodies. Pages without surface are still "
                         "CRAWLED for link discovery (so a static landing page "
                         "linking to a form page still works) - just not written.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Show what WOULD be saved without writing any files. "
                         "Useful for seeing which pages on the target actually "
                         "expose attack surface before committing to a crawl.")

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
