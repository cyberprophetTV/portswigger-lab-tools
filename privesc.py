#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
privesc.py - Dual-token privilege-escalation / IDOR comparator
=====================================================================

THE EXAM SCENARIO THIS TARGETS
------------------------------
On the BSCP exam (and in real engagements) you frequently get TWO
sets of credentials: one privileged (admin / manager / target user),
one weak (a basic account you just registered). The question becomes:

  "Can the low-priv account see / change anything that should only
   be accessible to the privileged account?"

That's IDOR / Broken Object Level Authorization / privilege
escalation. Manually checking every endpoint with two browsers
is tedious; this tool automates it.

WHAT IT DOES
------------
For each URL in a list, it sends a GET twice:
  1. With cookies from the ADMIN cookie jar (--admin-jar)
  2. With cookies from the LOW-PRIV cookie jar (--user-jar)

Then it compares the two responses (status code + body content) and
classifies the pair:

  IDOR_LIKELY      Both 200 with body similarity >=0.9.
                   The low-priv user got essentially the same data
                   the admin saw. Strong access-control bypass.
  CONTENT_DELTA    Both 200 but bodies differ significantly. Might
                   still be an IDOR with personalized content
                   (admin sees more rows / fields than user). Worth
                   manual eyeball.
  BYPASS           Admin gets blocked (401/403) but user gets 200.
                   Unusual - might indicate the endpoint trusts a
                   different signal than auth (IP, header).
  EXPECTED_BLOCK   Admin 200, user 401/403/302. Authorization is
                   doing what it should. Boring; not printed unless
                   --verbose.
  EXPECTED_OPEN    Both 200 with very similar bodies and the URL
                   looks public (e.g. /static/, /login). Boring.
  BOTH_BLOCKED     Both 401/403/etc. Boring.
  STATUS_DELTA     Status codes differ but neither is the standard
                   200/40x pattern - flag for review.

WHY BODY-SIMILARITY MATTERS
---------------------------
A page might serve different HTML to admins (more menu items, a
"Delete" button) and to users. If the user can pull up that page
AT ALL, that's still an IDOR even if the admin saw 5KB more HTML.
We use difflib.SequenceMatcher.ratio() to quantify similarity from
0.0 (totally different) to 1.0 (identical). Default threshold for
IDOR_LIKELY is 0.9 (override with --idor-threshold).

OBJECT-ID FUZZING
-----------------
The classic IDOR pattern is /api/orders/§ID§ - admin can see all
order IDs, user can only see their own. Use intruder.py for the
ID fuzzing across each cookie. This tool is for the AUTH-COMPARE
step.

URL LIST
--------
Pass a file with one URL per line (absolute URLs). Crawler output,
sitemap.xml extracts, JS-grep results, burp scope dumps - whatever
URLs you've enumerated as worth testing.

EXAMPLE
-------
  # First, get cookies for both accounts (use intruder's login flow):
  python3 intruder.py examples/login.txt --payload <(echo admin) \\
      --login-url https://t/login --login-data 'u=admin&p=admin' \\
      --cookie-jar admin.json
  python3 intruder.py examples/login.txt --payload <(echo user) \\
      --login-url https://t/login --login-data 'u=user&p=user' \\
      --cookie-jar user.json

  # Then compare every URL in a list:
  python3 privesc.py urls.txt \\
      --admin-jar admin.json --user-jar user.json

  # Or with raw cookies:
  python3 privesc.py urls.txt \\
      --admin-cookie 'session=admin_abc' \\
      --user-cookie 'session=user_xyz'
"""

import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

from intruder import (
    build_session, parse_jitter, maybe_jitter, read_wordlist,
    write_json, write_csv, write_html, write_markdown,
    parse_cookie_pair, load_cookie_jar,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, tag_miss,
    progress, bold, dim, cyan, red, yellow,
)


# ---------------------------------------------------------------------
# CLASSIFICATION
# ---------------------------------------------------------------------
# A response pair is classified into one of these buckets. The verdict
# determines what gets printed (and how loudly) and how the user
# triages results.
VERDICTS = {
    "IDOR_LIKELY":    ("high",   red,    "low-priv saw admin content"),
    "CONTENT_DELTA":  ("medium", yellow, "both 200 but bodies differ - check manually"),
    "BYPASS":         ("high",   red,    "admin blocked, low-priv NOT blocked"),
    "STATUS_DELTA":   ("low",    cyan,   "unusual status combination"),
    "EXPECTED_BLOCK": ("info",   dim,    "admin OK, low-priv blocked (auth working)"),
    "EXPECTED_OPEN":  ("info",   dim,    "both OK + identical (looks public)"),
    "BOTH_BLOCKED":   ("info",   dim,    "neither account can reach this"),
}


@dataclass
class PriveSCConfig:
    urls: list[str]
    admin_cookies: dict[str, str]
    user_cookies: dict[str, str]
    workers: int
    jitter: tuple[float, float]
    proxy: str | None
    insecure: bool
    retries: int
    verbose: bool
    idor_threshold: float = 0.9
    output: Path | None = None
    output_csv: Path | None = None
    output_html: Path | None = None
    output_md: Path | None = None


# ---------------------------------------------------------------------
# REQUEST PAIR
# ---------------------------------------------------------------------
def fetch(session: requests.Session, url: str) -> tuple[int | None, str, str | None]:
    """GET the URL; return (status, body_text, error). Don't follow redirects."""
    try:
        r = session.get(url, allow_redirects=False, timeout=20)
        return r.status_code, r.text, None
    except requests.exceptions.RequestException as e:
        return None, "", str(e)


def classify(status_a: int | None, body_a: str,
             status_b: int | None, body_b: str,
             idor_threshold: float) -> tuple[str, float]:
    """
    Compare admin (A) vs user (B) responses. Return (verdict, similarity).

    Similarity is SequenceMatcher.ratio() between the two bodies -
    1.0 = identical, 0.0 = totally different. We compute it always
    (cheap) so it's available in the output even when the verdict
    doesn't depend on it.
    """
    # Compute similarity once.
    if body_a and body_b:
        # autojunk=False so the matcher doesn't skip "junk" lines -
        # we want a faithful similarity for HTML.
        sim = SequenceMatcher(None, body_a, body_b, autojunk=False).ratio()
    elif not body_a and not body_b:
        sim = 1.0
    else:
        sim = 0.0

    blocked_codes = {401, 403, 302, 303}
    ok_a = status_a == 200
    ok_b = status_b == 200
    blocked_a = status_a in blocked_codes
    blocked_b = status_b in blocked_codes

    # Both got a real page
    if ok_a and ok_b:
        if sim >= idor_threshold:
            return "IDOR_LIKELY", sim
        # Both 200 but content differs significantly - might still be
        # IDOR (personalized content). Flag for manual review.
        return "CONTENT_DELTA", sim

    # Admin got OK, user got blocked - that's auth working as expected
    if ok_a and blocked_b:
        return "EXPECTED_BLOCK", sim

    # Admin got blocked, user got OK - this is highly unusual
    if blocked_a and ok_b:
        return "BYPASS", sim

    # Both blocked
    if blocked_a and blocked_b:
        return "BOTH_BLOCKED", sim

    # Anything else - statuses differ but neither matches the standard
    # pattern. Could be 500/redirects/etc. Worth a look.
    return "STATUS_DELTA", sim


# ---------------------------------------------------------------------
# MAIN
# ---------------------------------------------------------------------
def compare(cfg: PriveSCConfig) -> list[dict]:
    # Two sessions, one per cookie set. We share each across all
    # requests to that role (connection pooling kicks in).
    sess_admin = build_session(cfg.workers, cfg.proxy, cfg.insecure,
                                cfg.retries, cookies=cfg.admin_cookies)
    sess_user = build_session(cfg.workers, cfg.proxy, cfg.insecure,
                               cfg.retries, cookies=cfg.user_cookies)

    print(f"{tag_info()} comparing {len(cfg.urls)} URLs as ADMIN vs LOW-PRIV")

    results: list[dict] = []

    def worker(url: str):
        maybe_jitter(cfg.jitter)
        # Send both fetches; classify locally to keep the main thread
        # cheap.
        status_a, body_a, err_a = fetch(sess_admin, url)
        if err_a:
            return url, None, None, "", "", 0.0, f"admin: {err_a}", "ERROR"
        status_b, body_b, err_b = fetch(sess_user, url)
        if err_b:
            return url, status_a, None, body_a, "", 0.0, f"user: {err_b}", "ERROR"
        verdict, sim = classify(status_a, body_a, status_b, body_b,
                                 cfg.idor_threshold)
        return url, status_a, status_b, body_a, body_b, sim, None, verdict

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(worker, u) for u in cfg.urls]
        for fut in progress(as_completed(futures), total=len(futures),
                            desc="compare"):
            url, status_a, status_b, body_a, body_b, sim, err, verdict = fut.result()

            interesting = verdict in (
                "IDOR_LIKELY", "BYPASS", "CONTENT_DELTA", "STATUS_DELTA", "ERROR"
            )

            if err:
                print(f"{tag_err()} {url}  {err}")
            elif interesting or cfg.verbose:
                if verdict in VERDICTS:
                    sev, color, desc = VERDICTS[verdict]
                else:
                    sev, color, desc = "info", dim, "unknown"
                lengths = f"len_a={len(body_a)} len_b={len(body_b)}"
                line = (f"{color(f'[{verdict}]')} {url}  "
                        f"status_a={status_a} status_b={status_b}  "
                        f"sim={sim:.2f}  {lengths}")
                print(line)
                if cfg.verbose:
                    print(dim(f"    {desc}"))

            results.append({
                "label":       url,
                "status":      status_a,           # admin status (for output schema compat)
                "status_user": status_b,
                "length":      len(body_a),
                "length_user": len(body_b),
                "time":        0.0,                # not tracked separately
                "similarity":  round(sim, 4),
                "verdict":     verdict,
                "hit":         interesting,
                "error":       err,
            })

    # Summary by verdict
    counts: dict[str, int] = {}
    for r in results:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print()
    print(f"=== summary ===")
    for verdict, count in sorted(counts.items(),
                                  key=lambda kv: -VERDICTS.get(kv[0], (None, None, ""))[0:1].count("high")):
        sev = VERDICTS.get(verdict, ("info", None, ""))[0]
        marker = "***" if sev == "high" else ("!" if sev == "medium" else " ")
        print(f"  {marker} {verdict:16s} {count}")

    return results


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("url_list", type=Path,
                    help="File with one URL per line")
    # Admin cookies
    ap.add_argument("--admin-jar", type=Path,
                    help="JSON cookie jar for the admin / target account")
    ap.add_argument("--admin-cookie", action="append", default=[],
                    metavar="NAME=VALUE",
                    help="Cookie to send as admin (repeatable)")
    # User cookies
    ap.add_argument("--user-jar", type=Path,
                    help="JSON cookie jar for the low-priv account")
    ap.add_argument("--user-cookie", action="append", default=[],
                    metavar="NAME=VALUE",
                    help="Cookie to send as low-priv (repeatable)")
    # Tuning
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--idor-threshold", type=float, default=0.9,
                    help="Body similarity >= this and both 200 -> IDOR_LIKELY "
                         "(default 0.9)")
    ap.add_argument("--verbose", action="store_true")
    # Proxy
    ap.add_argument("--proxy", metavar="URL")
    ap.add_argument("--insecure", action="store_true")
    # Output
    ap.add_argument("--output", type=Path, metavar="FILE.json")
    ap.add_argument("--output-csv", type=Path, metavar="FILE.csv")
    ap.add_argument("--output-html", type=Path, metavar="FILE.html")
    ap.add_argument("--output-md", type=Path, metavar="FILE.md")
    args = ap.parse_args()

    # Proxy
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

    # Cookies for each role
    admin_cookies: dict[str, str] = {}
    if args.admin_jar:
        admin_cookies.update(load_cookie_jar(args.admin_jar))
    for raw in args.admin_cookie:
        name, val = parse_cookie_pair(raw)
        admin_cookies[name] = val

    user_cookies: dict[str, str] = {}
    if args.user_jar:
        user_cookies.update(load_cookie_jar(args.user_jar))
    for raw in args.user_cookie:
        name, val = parse_cookie_pair(raw)
        user_cookies[name] = val

    if not admin_cookies and not user_cookies:
        print(f"{tag_warn()} no cookies set for either role - "
              "every request will be unauthenticated. "
              "Pass --admin-jar / --user-jar or --admin-cookie / --user-cookie.")
    elif not admin_cookies:
        print(f"{tag_warn()} no admin cookies - admin requests will be "
              "unauthenticated; results will be misleading.")
    elif not user_cookies:
        print(f"{tag_warn()} no user cookies - user requests will be "
              "unauthenticated; results will be misleading.")

    cfg = PriveSCConfig(
        urls=read_wordlist(args.url_list),
        admin_cookies=admin_cookies,
        user_cookies=user_cookies,
        workers=args.workers,
        jitter=args.jitter,
        proxy=proxy,
        insecure=insecure,
        retries=args.retries,
        verbose=args.verbose,
        idor_threshold=args.idor_threshold,
        output=args.output,
        output_csv=args.output_csv,
        output_html=args.output_html,
        output_md=args.output_md,
    )

    results = compare(cfg)

    for fmt, path, writer in [
        ("json", cfg.output,      write_json),
        ("csv",  cfg.output_csv,  write_csv),
        ("html", cfg.output_html, write_html),
        ("md",   cfg.output_md,   write_markdown),
    ]:
        if path is not None:
            writer(results, path)
            print(f"{tag_info()} wrote results to {path}  ({fmt})")


if __name__ == "__main__":
    main()
