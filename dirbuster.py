#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Intended for use against systems you OWN or have EXPLICIT WRITTEN
# PERMISSION to test. Running content-discovery scans against
# unauthorized targets is illegal in most jurisdictions. See README.
"""
=====================================================================
dirbuster.py - Content discovery / path enumeration
=====================================================================

WHAT IS CONTENT DISCOVERY?
--------------------------
Most web apps expose far more endpoints than the public navigation
hints at. Hidden admin panels, .git directories accidentally
deployed, backup files (`config.php.bak`, `database.sql.gz`), dev /
staging endpoints left behind, retired API versions still listening,
debug pages, internal-only routes - these are gold to a pentester.

Content discovery (also called "directory busting", "forced
browsing", or "fuzzing for content") is the systematic attempt to
FIND those hidden endpoints by trying every path in a wordlist and
flagging the ones the server actually serves.

Tools you might use in real engagements:
  ffuf            - the modern speed champion, Go-based
  feroxbuster     - similar; recursive, fast
  dirsearch       - Python, good defaults, well-maintained
  gobuster        - Go, simple, popular
  dirb            - the original; still works, much slower

dirbuster.py is a teaching-focused version of the same idea. It's
intentionally simpler than the production tools above but covers
the techniques you'd use in either.

WHAT THIS TOOL DOES
-------------------
For each path in your wordlist it sends GET base_url/path and
records the response status, body length, and elapsed time. By
default it FLAGS responses with status codes that suggest an
endpoint exists:

  200  serves real content - flag it
  301  redirect - often points at a directory, flag it
  302  redirect - same
  401  unauthorized - the endpoint EXISTS, you just need creds
  403  forbidden - same: it's there, you can't get in (yet)
  500  internal server error - sometimes a leak of an internal route

404 (and similar "not found" codes) is filtered out by default
because that's the negative signal. Override with --match-status.

EXTENSIONS
----------
For each base path you can optionally try a set of extensions, like
trying `admin`, `admin.php`, `admin.bak`, `admin.zip` for one
wordlist entry. Use --extensions ".php,.bak,.zip,.old,.git". The
empty extension is implicit - we always try the bare path too.

Real targets often hide content under common backup/temp extensions:
  .bak  .old  .orig  .swp  .tmp  .save  .copy
  .zip  .tar  .tar.gz  .sql  .db
  .git/  .svn/  .hg/

RECURSION
---------
When --recursive is set, every discovered directory becomes a new
root and gets fuzzed with the same wordlist. So:
  Found /admin           -> next round fuzzes /admin/<word>
  Found /admin/users     -> next round fuzzes /admin/users/<word>
  ...
Bounded by --max-depth to avoid blowing up. Wikis, blogs, CMS
admins often have deep navigation that this uncovers.

WORDLISTS
---------
The de-facto standard wordlists come from `SecLists`. Some
popular picks for content discovery:
  common.txt           ~4,600 entries - quick first pass
  raft-small-words     ~10k - balanced
  raft-medium-words    ~30k - deeper
  raft-large-words     ~120k - exhaustive (long runs)
  big.txt              ~20k - DirBuster's classic
  CMS-specific lists (wordpress, drupal, joomla...)

This repo doesn't bundle them - they're public. To grab common.txt:
  curl -sLO https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt

REUSE OF intruder.py
--------------------
This file imports the heavy-lifting helpers from intruder.py:
  - build_session       (proxy, TLS bypass, retries, cookies)
  - parse_jitter / maybe_jitter
  - parse_form_data / parse_cookie_pair / load_cookie_jar / etc.
  - write_json / write_csv / write_html / write_markdown
That way auth + proxy + stealth + output-format support are
identical across the two tools, and there's no duplication to
keep in sync.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse, urljoin

import requests
import urllib3

# Reuse shared helpers from intruder.py - avoids duplication.
from intruder import (
    build_session, parse_jitter, maybe_jitter, read_wordlist,
    write_json, write_csv, write_html, write_markdown,
    parse_form_data, parse_cookie_pair, load_cookie_jar, save_cookie_jar,
    login_and_capture, parse_range_spec, range_matches,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, tag_miss,
    progress, bold, dim,
)


# ---------------------------------------------------------------------
# DEFAULT "INTERESTING" STATUS CODES
# ---------------------------------------------------------------------
# What we flag by default if --match-status isn't given. Tuned for
# "this is probably a real endpoint" rather than "this might be
# vulnerable" - that's a follow-up step after discovery.
#
# We deliberately INCLUDE 401 and 403: a 401/403 means "the URL is
# valid, the server knows about it, but you need auth (401) or it's
# forbidden (403)." Either way, that's existence info worth surfacing.
DEFAULT_INTERESTING_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 500}


# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
@dataclass
class DirBusterConfig:
    base_url: str                          # e.g. https://target.com
    wordlist: list[str]                    # paths to probe
    extensions: list[str]                  # ['', '.php', '.bak'] - '' is implicit base
    workers: int
    jitter: tuple[float, float]
    proxy: str | None
    insecure: bool
    retries: int
    cookies: dict[str, str]
    verbose: bool

    # Status filtering: either a set of explicit "interesting" codes,
    # or a parsed range_matches spec (--match-status overrides default).
    interesting_statuses: set[int] = field(default_factory=lambda: DEFAULT_INTERESTING_STATUSES.copy())
    match_status: tuple[float, float, bool] | None = None

    recursive: bool = False
    max_depth: int = 3

    output: Path | None = None
    output_csv: Path | None = None
    output_html: Path | None = None
    output_md: Path | None = None


# ---------------------------------------------------------------------
# PROBE
# ---------------------------------------------------------------------
def probe_path(session: requests.Session, base_url: str, path: str
               ) -> tuple[int | None, int, float, str, str | None]:
    """
    GET base_url/path. Returns (status, length, elapsed, location, error).

    allow_redirects=False because:
      - Following a redirect would mask the original status code (302
        becomes 200 after following), and we WANT to know which paths
        triggered the redirect.
      - The Location header is informational by itself (often points
        at where the real content lives - good to see in output).
    """
    # urljoin handles missing/extra slashes correctly. We strip any
    # leading '/' off the path because urljoin treats a path starting
    # with '/' as anchored to host root - which is what we want, but
    # we want to be explicit.
    url = base_url.rstrip("/") + "/" + path.lstrip("/")

    start = time.monotonic()
    try:
        r = session.get(url, allow_redirects=False, timeout=20)
    except requests.exceptions.RequestException as e:
        return None, 0, 0.0, "", str(e)
    elapsed = time.monotonic() - start
    return r.status_code, len(r.content), elapsed, r.headers.get("Location", ""), None


def is_interesting(cfg: DirBusterConfig, status: int) -> bool:
    """
    Decide whether to flag a response as a hit.
    --match-status takes precedence if set; otherwise use the
    DEFAULT_INTERESTING_STATUSES set.
    """
    if cfg.match_status is not None:
        return range_matches(cfg.match_status, status)
    return status in cfg.interesting_statuses


def looks_like_directory(status: int | None, length: int, location: str, path: str) -> bool:
    """
    Heuristic for "this hit is a directory we should recurse into."

    Triggers:
      - status 301/302/307/308 with a Location ending in '/' or
        pointing at path+'/' (the canonical "you forgot the trailing
        slash" redirect for a real directory)
      - status 200/403 with the URL itself ending in '/' - some
        servers serve / for directory roots without redirecting

    Conservative: false negatives are fine (one missed branch), but
    false positives waste a whole recursive round on something
    that isn't really a directory.
    """
    if status in (301, 302, 307, 308) and location.endswith("/"):
        return True
    if status in (200, 403) and path.endswith("/"):
        return True
    return False


# ---------------------------------------------------------------------
# RUN ONE ROUND (a single base path + the wordlist)
# ---------------------------------------------------------------------
def run_round(cfg: DirBusterConfig, session: requests.Session,
              root_path: str) -> tuple[list[dict], list[str]]:
    """
    Run one wave of probes against `root_path`. Returns (results,
    discovered_subdirs).

    `root_path` is "" for the top-level scan, or e.g. "/admin/" for
    a recursive descent into a discovered directory.
    """
    # Build the full list of paths to probe: wordlist x extensions,
    # under the root.
    paths_to_probe: list[str] = []
    for word in cfg.wordlist:
        word = word.lstrip("/")  # word entries shouldn't have leading slash
        for ext in cfg.extensions:
            full = root_path.rstrip("/") + "/" + word + ext
            paths_to_probe.append(full)

    print(f"{tag_info()} round under {root_path or '/'}: probing {len(paths_to_probe)} paths")

    results: list[dict] = []
    discovered_dirs: list[str] = []

    def worker(path: str):
        maybe_jitter(cfg.jitter)
        status, length, elapsed, location, error = probe_path(
            session, cfg.base_url, path)
        return path, status, length, elapsed, location, error

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(worker, p) for p in paths_to_probe]
        for fut in progress(as_completed(futures), total=len(futures), desc="paths"):
            path, status, length, elapsed, location, error = fut.result()

            hit = (status is not None) and is_interesting(cfg, status)

            results.append({
                "label": path,
                "status": status,
                "length": length,
                "time": round(elapsed, 4),
                "location": location,
                "error": error,
                "hit": hit,
            })

            if error:
                if cfg.verbose:
                    print(f"{tag_err()} {path}: {error}")
            elif hit:
                # Format the hit line. Show location if present (the
                # redirect target is often informative).
                loc = f" -> {location}" if location else ""
                print(f"{tag_hit()} {bold(path)}  "
                      f"status={status} len={length}{loc}")
                if cfg.recursive and looks_like_directory(status, length, location, path):
                    # Normalize to trailing-slash form before recursing
                    sub = path if path.endswith("/") else path + "/"
                    discovered_dirs.append(sub)
            elif cfg.verbose:
                print(f"{tag_miss()} {path}  status={status}")

    return results, discovered_dirs


# ---------------------------------------------------------------------
# MAIN ATTACK
# ---------------------------------------------------------------------
def dirbust(cfg: DirBusterConfig) -> list[dict]:
    """Top-level: build a session, run one or more rounds (recursive)."""
    session = build_session(cfg.workers, cfg.proxy, cfg.insecure,
                            cfg.retries, cookies=cfg.cookies)

    all_results: list[dict] = []

    # Queue of (depth, root_path) to process. Start with depth=0 + root.
    queue: list[tuple[int, str]] = [(0, "")]
    seen_roots: set[str] = {""}

    while queue:
        depth, root = queue.pop(0)
        results, discovered = run_round(cfg, session, root)
        all_results.extend(results)

        if cfg.recursive and depth + 1 <= cfg.max_depth:
            for d in discovered:
                if d in seen_roots:
                    continue
                seen_roots.add(d)
                queue.append((depth + 1, d))
                print(f"{tag_info()} queueing depth-{depth + 1} scan: {d}")

    return all_results


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("base_url", help="Target base URL, e.g. https://target.com")
    ap.add_argument("wordlist", type=Path, help="Paths wordlist (one entry per line)")

    # ---- Discovery options ----
    ap.add_argument("--extensions", default="", metavar="LIST",
                    help="Comma-separated extensions to try with each word, "
                         "e.g. '.php,.bak,.zip'. Empty (base path) is always "
                         "tried in addition to extensions.")
    ap.add_argument("--recursive", action="store_true",
                    help="Recurse into discovered directories with the same "
                         "wordlist (capped by --max-depth)")
    ap.add_argument("--max-depth", type=int, default=3,
                    help="Maximum recursion depth (default 3)")
    ap.add_argument("--match-status", type=parse_range_spec, metavar="SPEC",
                    help="Override the default 'interesting status codes' "
                         "set. Same range-spec syntax as intruder.py: "
                         "'200-299', '!404', '5000-', etc.")

    # ---- Tuning ----
    ap.add_argument("--workers", type=int, default=20,
                    help="Concurrent requests (default 20). Higher than "
                         "intruder's default because content discovery is "
                         "usually IO-bound and tolerated by most servers.")
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX",
                    help="Random delay before each request")
    ap.add_argument("--retries", type=int, default=2,
                    help="Retry on connection error / 5xx (default 2)")
    ap.add_argument("--verbose", action="store_true",
                    help="Print every probe (not just hits)")

    # ---- Auth ----
    ap.add_argument("--login-url", metavar="URL",
                    help="Login endpoint to POST to at startup. Cookies "
                         "set by the response are reused for every probe.")
    ap.add_argument("--login-data", metavar="FORM",
                    help="Form data for the login POST, e.g. "
                         "'user=admin&pw=secret'")
    ap.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                    help="Manually set a cookie on every request (repeatable)")
    ap.add_argument("--cookie-jar", type=Path, metavar="FILE",
                    help="JSON cookie jar to load/save")

    # ---- Proxy ----
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy. 'burp' = http://127.0.0.1:8080. "
                         "Auto-enables --insecure.")
    ap.add_argument("--insecure", action="store_true",
                    help="Skip TLS verification")

    # ---- Output ----
    ap.add_argument("--output", type=Path, metavar="FILE.json",
                    help="Write all results as JSON")
    ap.add_argument("--output-csv", type=Path, metavar="FILE.csv")
    ap.add_argument("--output-html", type=Path, metavar="FILE.html")
    ap.add_argument("--output-md", type=Path, metavar="FILE.md")

    args = ap.parse_args()

    # ---- Parse extensions: always include "" (bare path) ----
    exts = [""]
    if args.extensions:
        for e in args.extensions.split(","):
            e = e.strip()
            if not e:
                continue
            # User may type 'php' or '.php' - normalize to '.php'.
            if not e.startswith("."):
                e = "." + e
            exts.append(e)

    # ---- Proxy / insecure resolution ----
    proxy = args.proxy
    insecure = args.insecure
    if proxy:
        if proxy.strip().lower() == "burp":
            proxy = "http://127.0.0.1:8080"
        elif "://" not in proxy:
            proxy = f"http://{proxy}"
        insecure = True
        print(f"{tag_info()} routing through proxy: {proxy} (TLS verification disabled)")
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ---- Cookie assembly: same priority chain as intruder.py ----
    cookies: dict[str, str] = {}
    if args.cookie_jar:
        cookies.update(load_cookie_jar(args.cookie_jar))
        if cookies:
            print(f"{tag_info()} loaded {len(cookies)} cookie(s) from {args.cookie_jar}")
    if args.login_url:
        if not args.login_data:
            sys.exit("[!] --login-url requires --login-data")
        login_session = build_session(1, proxy, insecure, args.retries, cookies=cookies)
        login_data = parse_form_data(args.login_data)
        print(f"{tag_info()} logging in: POST {args.login_url}")
        new_cookies = login_and_capture(login_session, args.login_url, login_data)
        cookies.update(new_cookies)
        print(f"{tag_info()} captured {len(new_cookies)} cookie(s) from login response")
    for raw in args.cookie:
        name, val = parse_cookie_pair(raw)
        cookies[name] = val
    if args.cookie_jar and cookies:
        save_cookie_jar(args.cookie_jar, cookies)

    # ---- URL normalization ----
    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"{tag_err()} base_url must include scheme + host")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cfg = DirBusterConfig(
        base_url=base,
        wordlist=read_wordlist(args.wordlist),
        extensions=exts,
        workers=args.workers,
        jitter=args.jitter,
        proxy=proxy,
        insecure=insecure,
        retries=args.retries,
        cookies=cookies,
        verbose=args.verbose,
        match_status=args.match_status,
        recursive=args.recursive,
        max_depth=args.max_depth,
        output=args.output,
        output_csv=args.output_csv,
        output_html=args.output_html,
        output_md=args.output_md,
    )

    results = dirbust(cfg)
    n_hits = sum(1 for r in results if r["hit"])
    n_errors = sum(1 for r in results if r["error"])

    print()
    print(f"=== {n_hits} hits / {len(results)} probes / {n_errors} errors ===")

    # ---- Write any enabled output format(s) ----
    for fmt, path, writer in [
        ("json", cfg.output,      write_json),
        ("csv",  cfg.output_csv,  write_csv),
        ("html", cfg.output_html, write_html),
        ("md",   cfg.output_md,   write_markdown),
    ]:
        if path is not None:
            writer(results, path)
            print(f"{tag_info()} wrote {len(results)} results to {path}  ({fmt})")


if __name__ == "__main__":
    main()
