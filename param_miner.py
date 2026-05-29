#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Intended for authorized testing only - PortSwigger labs, CTFs,
# systems you own, or engagements with written authorization. See README.
"""
=====================================================================
param_miner.py - Hidden parameter discovery (Param Miner-style)
=====================================================================

THE EXAM ROADBLOCK THIS TARGETS
-------------------------------
The BSCP exam (and real-world apps) routinely hide administrative or
debug functionality behind parameters that NEVER appear in normal
browser traffic. Things like:

  POST /api/order
  {"item_id":42,"quantity":1}

  but the server ALSO honors:

  POST /api/order
  {"item_id":42,"quantity":1,"admin":true}   <-- reveals all orders
  {"item_id":42,"quantity":1,"role":"admin"} <-- price set to 0
  {"item_id":42,"quantity":1,"debug":1}      <-- leaks stack trace

You can't see these via crawling because no client ever sends them.
You find them by ACTIVELY GUESSING them - try a wordlist of common
admin/debug parameter names, watch for any response that differs
from the baseline.

This is the "Param Miner" pattern - James Kettle's classic Burp
extension. We re-implement the core idea in Python:

  1. Take a request template (same format as intruder.py - raw HTTP).
  2. Send it unmodified to establish a BASELINE response fingerprint
     (status + body length).
  3. For each parameter in the wordlist:
       For each test value (true / 1 / admin / yes):
         Add `param=value` to the request body and send.
         Compare response fingerprint to baseline.
         If it differs, flag it as a hit - "this parameter does
         something."

WHY MULTIPLE TEST VALUES
------------------------
Some servers check the parameter VALUE, not just its presence:

  admin=true   -> elevated
  admin=false  -> normal
  admin=1      -> elevated (some apps)
  admin=admin  -> elevated (some apps)
  admin=yes    -> elevated (some apps)

If we only sent `admin=anything`, we'd miss servers that require a
specific truthy value. Sending each candidate per parameter triples
the request count but catches more.

URL-ENCODED vs JSON
-------------------
The injection mechanics differ:

  URL-encoded body:    append &param=value to the existing body
  JSON body:           parse the body as JSON, add a top-level key

We auto-detect the body format from Content-Type. JSON test values
have to be of the right type - `true` (boolean), `1` (int), and
`"admin"` (string) are all valid JSON literals worth trying.

BASELINE NOISE
--------------
If the server returns slightly different content on every request
(timestamps, dynamic IDs, CSRF tokens), the baseline length will
drift and every probe will look like a "hit." We send the baseline
THREE times and record the range of lengths observed. A probe only
counts as a hit if its length falls OUTSIDE that range - cheap noise
filter that handles minor per-request variation.

THIS COMPLEMENTS intruder.py / dirbuster.py
-------------------------------------------
intruder.py mutates VALUES at known positions (§USER§).
dirbuster.py guesses PATHS.
param_miner.py guesses PARAMETER NAMES - the third axis.

All three reuse build_session, cookies, proxy, output formats from
intruder.py.
"""

import argparse
import json
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

from intruder import (
    RawRequest, build_session, parse_jitter, maybe_jitter, read_wordlist,
    write_json, write_csv, write_html, write_markdown,
    parse_form_data, parse_cookie_pair, load_cookie_jar, save_cookie_jar,
    login_and_capture,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, tag_miss,
    progress, bold, dim,
)


# ---------------------------------------------------------------------
# TEST VALUES PER FORMAT
# ---------------------------------------------------------------------
# When we inject a parameter, we don't know what value the server
# expects to count as "elevated." Try the common ones. Each test
# value triples (~) the request count, so keep the list focused.
#
# URL-encoded: strings only (since URL encoding doesn't distinguish
#              types - everything is text on the wire).
URL_TEST_VALUES = ["true", "1", "admin", "yes"]

# JSON: try the actual JSON types so we cover servers that do strict
#       type-checking ({"admin": true} != {"admin": "true"}).
JSON_TEST_VALUES = [True, 1, "admin", "yes"]


# ---------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------
@dataclass
class MinerConfig:
    base_url: str
    request_text: str
    params: list[str]
    workers: int
    jitter: tuple[float, float]
    proxy: str | None
    insecure: bool
    retries: int
    cookies: dict[str, str]
    verbose: bool
    # Tolerance for baseline noise: how many bytes a probe's length
    # can differ from baseline and STILL be considered "same as
    # baseline" (not a hit). 0 = strict.
    noise_tolerance: int = 0

    output: Path | None = None
    output_csv: Path | None = None
    output_html: Path | None = None
    output_md: Path | None = None


# ---------------------------------------------------------------------
# INJECTION HELPERS
# ---------------------------------------------------------------------
def inject_url_encoded(body: str, param: str, value: str) -> str:
    """
    Append &param=value (or set as first param if body is empty).
    Caller has confirmed Content-Type is form-encoded.
    """
    encoded = f"{urllib.parse.quote(param)}={urllib.parse.quote(value)}"
    if body.strip():
        return body + "&" + encoded
    return encoded


def inject_json(body: str, param: str, value) -> str:
    """
    Parse body as JSON, add the param as a top-level key, re-serialize.

    If the body isn't a JSON object (e.g. it's a list or a primitive),
    we wrap in {} - that handles the common case where the body is
    empty or malformed.
    """
    try:
        parsed = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        # If the original is e.g. a JSON array, we can't naturally add a
        # named parameter - fall back to wrapping. Most APIs that take a
        # bare array won't honor extra fields anyway.
        return body
    parsed[param] = value
    return json.dumps(parsed)


def detect_body_format(headers: list[tuple[str, str]], body: str) -> str:
    """
    Return 'json', 'form', or 'none' based on Content-Type + body shape.

    Priority:
      1. explicit Content-Type header
      2. body-shape sniffing as a fallback
    """
    for name, val in headers:
        if name.lower() == "content-type":
            lower = val.lower()
            if "json" in lower:
                return "json"
            if "form-urlencoded" in lower:
                return "form"
    # No Content-Type. Sniff: starts with { or [ -> json; has = -> form.
    body = body.strip()
    if body.startswith(("{", "[")):
        return "json"
    if "=" in body:
        return "form"
    return "none"


# ---------------------------------------------------------------------
# REQUEST SENDING
# ---------------------------------------------------------------------
def send_request(session: requests.Session, base_url: str,
                 req: RawRequest) -> tuple[int | None, int, float, str | None]:
    """Send a single RawRequest and return (status, length, time, error)."""
    parsed = urlparse(base_url)
    scheme = parsed.scheme or "https"
    host = parsed.netloc
    url = f"{scheme}://{host}{req.path}"

    headers = {}
    for name, val in req.headers:
        if name.lower() in ("content-length", "host"):
            continue
        headers[name] = val

    start = time.monotonic()
    try:
        r = session.request(
            method=req.method, url=url, headers=headers,
            data=req.body.encode("utf-8", errors="surrogateescape"),
            allow_redirects=False, timeout=20,
        )
    except requests.exceptions.RequestException as e:
        return None, 0, 0.0, str(e)
    elapsed = time.monotonic() - start
    return r.status_code, len(r.content), elapsed, None


# ---------------------------------------------------------------------
# MAIN MINING LOOP
# ---------------------------------------------------------------------
def mine(cfg: MinerConfig) -> list[dict]:
    template = RawRequest.parse(cfg.request_text)
    body_format = detect_body_format(template.headers, template.body)

    if body_format == "none":
        sys.exit(f"{tag_err()} can't detect body format (need form-urlencoded "
                 f"Content-Type or JSON body). Adjust the request and retry.")

    print(f"{tag_info()} body format detected: {body_format}")
    test_values = URL_TEST_VALUES if body_format == "form" else JSON_TEST_VALUES

    session = build_session(cfg.workers, cfg.proxy, cfg.insecure,
                            cfg.retries, cookies=cfg.cookies)

    # ---- BASELINE ----
    # Send the original (unmodified) request a few times to establish
    # what "normal" looks like and how much per-request noise there is.
    print(f"{tag_info()} sending 3 baseline probes")
    baseline_samples: list[tuple[int | None, int]] = []
    for _ in range(3):
        status, length, _t, err = send_request(session, cfg.base_url, template)
        if err:
            sys.exit(f"{tag_err()} baseline request failed: {err}")
        baseline_samples.append((status, length))

    # Sanity: all baseline status codes should match. If not, the server
    # is flaky enough that fingerprint comparison won't work.
    baseline_statuses = {s for s, _ in baseline_samples}
    if len(baseline_statuses) > 1:
        print(f"{tag_warn()} baseline status codes vary: {baseline_statuses} "
              f"- results may be unreliable")
    baseline_status = baseline_samples[0][0]
    baseline_lengths = sorted({l for _, l in baseline_samples})
    # Effective length range to ignore: min - tolerance to max + tolerance.
    len_lo = min(baseline_lengths) - cfg.noise_tolerance
    len_hi = max(baseline_lengths) + cfg.noise_tolerance
    print(f"{tag_info()} baseline: status={baseline_status} "
          f"length={baseline_lengths} (ignoring diffs in [{len_lo}, {len_hi}])")

    # ---- PROBE ----
    # Build the work list: every (param, value) pair, each one
    # producing one modified request.
    work: list[tuple[str, str | int | bool]] = []
    for p in cfg.params:
        for v in test_values:
            work.append((p, v))
    print(f"{tag_info()} probing {len(cfg.params)} parameters x "
          f"{len(test_values)} values = {len(work)} requests")

    results: list[dict] = []

    def probe(item):
        param, value = item
        maybe_jitter(cfg.jitter)

        if body_format == "form":
            new_body = inject_url_encoded(template.body, param, str(value))
        else:
            new_body = inject_json(template.body, param, value)

        modified = RawRequest(
            method=template.method, path=template.path,
            headers=template.headers, body=new_body,
        )
        status, length, elapsed, err = send_request(session, cfg.base_url, modified)
        return param, value, status, length, elapsed, err

    with ThreadPoolExecutor(max_workers=cfg.workers) as ex:
        futures = [ex.submit(probe, w) for w in work]
        for fut in progress(as_completed(futures), total=len(futures),
                            desc="param-mining"):
            param, value, status, length, elapsed, err = fut.result()

            if err:
                hit = False
                if cfg.verbose:
                    print(f"{tag_err()} {param}={value!r}: {err}")
            else:
                # A response is a hit if it differs from baseline by:
                #   - a different status code, OR
                #   - a length outside the baseline-noise envelope
                status_changed = status != baseline_status
                length_changed = not (len_lo <= length <= len_hi)
                hit = status_changed or length_changed

                if hit:
                    why = []
                    if status_changed:
                        why.append(f"status {baseline_status}->{status}")
                    if length_changed:
                        why.append(f"length out of [{len_lo},{len_hi}]: {length}")
                    print(f"{tag_hit()} {bold(param)}={value!r}  "
                          f"status={status} len={length}  ({', '.join(why)})")
                elif cfg.verbose:
                    print(f"{tag_miss()} {param}={value!r}  status={status} len={length}")

            results.append({
                "label": f"{param}={value!r}",
                "status": status,
                "length": length,
                "time": round(elapsed, 4),
                "error": err,
                "hit": hit,
            })

    n_hits = sum(1 for r in results if r["hit"])
    print()
    print(f"=== {n_hits} hit(s) in {len(results)} probes ===")

    if n_hits:
        # Group hits by param so the user sees which parameters had
        # any reaction at all.
        print(f"{tag_info()} hit params:")
        hit_params: dict[str, list[str]] = {}
        for r in results:
            if not r["hit"]:
                continue
            param = r["label"].split("=", 1)[0]
            hit_params.setdefault(param, []).append(r["label"])
        for param, items in sorted(hit_params.items()):
            print(f"  - {bold(param)}  ({len(items)} value(s) triggered)")

    return results


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("request_file", type=Path,
                    help="Raw HTTP request template (same format as intruder.py)")
    ap.add_argument("--url", help="Override target URL (otherwise from Host header)")
    ap.add_argument("--params", type=Path, default=Path("hidden-params.txt"),
                    metavar="FILE",
                    help="Parameter wordlist (default: hidden-params.txt)")
    ap.add_argument("--workers", type=int, default=10)
    ap.add_argument("--jitter", type=parse_jitter, default=(0.0, 0.0),
                    metavar="MIN-MAX")
    ap.add_argument("--retries", type=int, default=2)
    ap.add_argument("--noise-tolerance", type=int, default=0, metavar="BYTES",
                    help="Ignore length differences within +/-BYTES of baseline "
                         "(useful when responses have minor per-request variation)")
    ap.add_argument("--verbose", action="store_true")

    # Auth (same as intruder)
    ap.add_argument("--login-url", metavar="URL")
    ap.add_argument("--login-data", metavar="FORM")
    ap.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE")
    ap.add_argument("--cookie-jar", type=Path, metavar="FILE")

    # Proxy
    ap.add_argument("--proxy", metavar="URL")
    ap.add_argument("--insecure", action="store_true")

    # Output
    ap.add_argument("--output", type=Path, metavar="FILE.json")
    ap.add_argument("--output-csv", type=Path, metavar="FILE.csv")
    ap.add_argument("--output-html", type=Path, metavar="FILE.html")
    ap.add_argument("--output-md", type=Path, metavar="FILE.md")
    args = ap.parse_args()

    # Proxy resolution (same pattern as intruder)
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

    # Cookie assembly
    cookies: dict[str, str] = {}
    if args.cookie_jar:
        cookies.update(load_cookie_jar(args.cookie_jar))
    if args.login_url:
        if not args.login_data:
            sys.exit(f"{tag_err()} --login-url requires --login-data")
        login_session = build_session(1, proxy, insecure, args.retries, cookies=cookies)
        cookies.update(login_and_capture(login_session, args.login_url,
                                          parse_form_data(args.login_data)))
    for raw in args.cookie:
        name, val = parse_cookie_pair(raw)
        cookies[name] = val
    if args.cookie_jar and cookies:
        save_cookie_jar(args.cookie_jar, cookies)

    # Figure out target URL: explicit --url > Host header from request
    request_text = args.request_file.read_text()
    template = RawRequest.parse(request_text)
    if args.url:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            sys.exit(f"{tag_err()} --url must include scheme + host")
        base_url = f"{parsed.scheme}://{parsed.netloc}"
    else:
        host = template.host()
        if not host:
            sys.exit(f"{tag_err()} no Host header in request and no --url given")
        base_url = f"https://{host}"

    cfg = MinerConfig(
        base_url=base_url,
        request_text=request_text,
        params=read_wordlist(args.params),
        workers=args.workers,
        jitter=args.jitter,
        proxy=proxy,
        insecure=insecure,
        retries=args.retries,
        cookies=cookies,
        verbose=args.verbose,
        noise_tolerance=args.noise_tolerance,
        output=args.output,
        output_csv=args.output_csv,
        output_html=args.output_html,
        output_md=args.output_md,
    )

    results = mine(cfg)

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
