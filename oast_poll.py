#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
oast_poll.py - Correlate OAST (out-of-band) hits with the requests
              that produced them
=====================================================================

WHAT THIS DOES
--------------
Closes the loop on `intruder.py --oob-host`. Recap of how that flag
works: every request gets a unique 12-char hex token injected into
User-Agent, Referer, and X-Forwarded-For as `<token>.your-oast-host`.
The token + the producing request's label are saved into the JSON
output.

When the OAST listener (interactsh / canarytoken / webhook.site /
self-hosted DNS canary) eventually sees one of those subdomains in
a DNS lookup or HTTP request, it logs it. That hit means SOMETHING
on the server side parsed our payload - SSRF, blind SQLi/XXE,
log4shell, server-side template injection, etc.

This tool:
  1. Reads the intruder JSON output (the list of {label, oob_id, ...} entries).
  2. Fetches the OAST listener's log (from URL or local file).
  3. Finds every oob_id from (1) that appears in the log from (2).
  4. Prints the correlation: "this payload triggered this OAST hit."

Optionally polls forever (--watch SECONDS) for late hits that arrive
hours after the fuzz finished.

WHY NOT BUILT INTO intruder.py?
-------------------------------
Two reasons:
  1. OAST hits are often LATE. A blind SSRF might not trigger until
     a cron job runs hours later. Coupling the polling to the fuzz
     would mean intruder hangs for hours after every run.
  2. Different OAST tools have wildly different APIs. interactsh
     speaks RSA+AES, webhook.site has a REST API, your self-hosted
     thing might be a tail-able log file. Keeping the polling
     separate lets you BYO source - this tool just needs the log
     content as text.

WHY NOT A FULL interactsh CLIENT?
---------------------------------
Implementing the real interactsh protocol (RSA-2048 keypair, AES-CFB
decryption of polled events, etc.) would add the `cryptography`
library as a dependency just for this one tool. The pragmatic
alternative: install ProjectDiscovery's `interactsh-client` binary
separately (`go install github.com/projectdiscovery/interactsh/cmd/
interactsh-client@latest`), run it with `-json -o log.txt`, and
point this script at `log.txt`. You get the full interactsh experience
without us reinventing it.

SUPPORTED SOURCES
-----------------
  --source-file FILE     Local file containing the OAST log
                         (interactsh-client -o output, tail of a
                         self-hosted server's access.log, etc.)

  --source-url URL       HTTP URL that returns the log as text
                         (webhook.site JSON view, your custom log
                         endpoint, etc.)

USAGE
-----
One-shot correlation:
  python3 intruder.py req.txt --payload x.txt --oob-host my.oast \\
      --output results.json --json
  # ... wait for OAST hits to arrive ...
  python3 oast_poll.py results.json --source-file interactsh.log

Watch for late hits:
  python3 oast_poll.py results.json --source-file interactsh.log \\
      --watch 60   # check every 60s, print new hits only
"""

import argparse
import json
import sys
import time
from pathlib import Path

import requests
import urllib3

from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, bold, dim, cyan,
)


# ---------------------------------------------------------------------
# RESULTS LOADER
# ---------------------------------------------------------------------
def load_results(path: Path) -> list[dict]:
    """
    Load intruder's --output JSON OR --json NDJSON stream.

    Accept both formats:
      JSON array       (from --output)
      NDJSON           (from --json piped to a file)
    """
    text = path.read_text()
    text_stripped = text.strip()
    if not text_stripped:
        sys.exit(f"{tag_err()} results file {path} is empty")

    # JSON array starts with `[`. NDJSON starts with `{`.
    if text_stripped[0] == "[":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            sys.exit(f"{tag_err()} not valid JSON: {e}")
        if not isinstance(data, list):
            sys.exit(f"{tag_err()} expected JSON array in {path}, got {type(data).__name__}")
        return data

    # NDJSON: one JSON object per line.
    results = []
    for i, line in enumerate(text.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            results.append(json.loads(line))
        except json.JSONDecodeError as e:
            print(f"{tag_warn()} {path}:{i} not valid JSON: {e}", file=sys.stderr)
    return results


# ---------------------------------------------------------------------
# SOURCE FETCHER
# ---------------------------------------------------------------------
def fetch_source(source_url: str | None, source_file: Path | None,
                 proxy: str | None, insecure: bool) -> str:
    """Get the current OAST log content. URL or file."""
    if source_file:
        if not source_file.exists():
            return ""    # Treat "not yet" as "no hits"
        return source_file.read_text(errors="replace")
    if source_url:
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        try:
            r = requests.get(source_url, proxies=proxies, verify=not insecure, timeout=15)
            return r.text
        except requests.exceptions.RequestException as e:
            print(f"{tag_warn()} failed to fetch {source_url}: {e}", file=sys.stderr)
            return ""
    return ""


# ---------------------------------------------------------------------
# CORRELATION
# ---------------------------------------------------------------------
def find_hits(oob_ids: set[str], log_text: str) -> dict[str, list[str]]:
    """
    For each OAST id, find every line in log_text that mentions it.

    Returns {oob_id: [matching_lines]}. An oob_id with zero matches
    is OMITTED from the result (we only want positive hits).

    Implementation note: we iterate lines (instead of substring-
    searching each id against the whole text) so each match line is
    printable as context. For huge logs this is O(lines * ids) but
    in practice OAST logs are small and id sets are <10k - fine.
    """
    hits: dict[str, list[str]] = {}
    for line in log_text.splitlines():
        # Quick early-out: skip lines that obviously don't contain
        # any of our hex ids (12 hex chars). Saves the inner loop.
        if not any(c in line for c in "0123456789abcdef"):
            continue
        for oob_id in oob_ids:
            if oob_id in line:
                hits.setdefault(oob_id, []).append(line)
    return hits


def correlate(results: list[dict], hits: dict[str, list[str]]) -> list[dict]:
    """
    Map oob_id matches back to the producing result entries.

    Returns one entry per hit:
        {
          "label": "sniper pos=0 value='admin'",
          "oob_id": "abc123...",
          "matching_lines": ["...", "..."],
        }

    Multiple results sharing the same oob_id (shouldn't happen but
    defensively) produce one entry per result.
    """
    by_oob_id: dict[str, list[dict]] = {}
    for r in results:
        oob_id = r.get("oob_id")
        if oob_id:
            by_oob_id.setdefault(oob_id, []).append(r)

    correlated = []
    for oob_id, lines in hits.items():
        for r in by_oob_id.get(oob_id, [{"label": "<unknown - no matching result entry>"}]):
            correlated.append({
                "label": r.get("label"),
                "status": r.get("status"),
                "oob_id": oob_id,
                "matching_lines": lines,
            })
    return correlated


# ---------------------------------------------------------------------
# REPORT
# ---------------------------------------------------------------------
def render(hits_correlated: list[dict], new_only: set[str] | None = None) -> int:
    """
    Print the correlated hits. Returns the count of FRESH hits
    (those whose oob_id is NOT in new_only, if provided).
    """
    if not hits_correlated:
        return 0
    fresh = 0
    for h in hits_correlated:
        if new_only is not None and h["oob_id"] in new_only:
            continue
        fresh += 1
        print()
        print(f"{tag_hit()} {bold(h['label'])}")
        print(f"    oob_id : {h['oob_id']}")
        if h.get("status") is not None:
            print(f"    status : {h['status']}")
        matches = h["matching_lines"]
        for line in matches[:3]:    # cap noisy logs
            print(f"    log    : {dim(line[:200])}")
        if len(matches) > 3:
            print(f"    log    : {dim('... +' + str(len(matches) - 3) + ' more')}")
    return fresh


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("results_file", type=Path,
                    help="intruder.py output file (JSON array from --output, "
                         "or NDJSON from --json piped to a file)")
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--source-file", type=Path,
                     help="Local file containing the OAST log")
    src.add_argument("--source-url",
                     help="HTTP URL returning the OAST log as text")
    ap.add_argument("--watch", type=int, metavar="SECONDS",
                    help="Poll forever, sleeping N seconds between checks. "
                         "Only prints NEW hits each cycle. Ctrl-C to stop.")
    ap.add_argument("--proxy", metavar="URL",
                    help="HTTP proxy for fetching --source-url")
    ap.add_argument("--insecure", action="store_true")

    args = ap.parse_args()

    proxy = args.proxy
    if proxy:
        if proxy.strip().lower() == "burp":
            proxy = "http://127.0.0.1:8080"
        elif "://" not in proxy:
            proxy = f"http://{proxy}"
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Load the producing results once - they don't change.
    results = load_results(args.results_file)
    oob_ids = {r["oob_id"] for r in results if r.get("oob_id")}
    if not oob_ids:
        sys.exit(f"{tag_err()} {args.results_file} has no `oob_id` fields. "
                 f"Re-run intruder with --oob-host to capture them.")
    print(f"{tag_info()} loaded {len(results)} results, {len(oob_ids)} OAST id(s)")

    if not args.watch:
        # ---- One-shot ----
        log_text = fetch_source(args.source_url, args.source_file,
                                 proxy, args.insecure)
        hits = find_hits(oob_ids, log_text)
        correlated = correlate(results, hits)
        fresh = render(correlated)
        print()
        print(f"{tag_info()} {fresh} correlated hit(s) "
              f"({len(hits)} unique OAST id(s) seen)")
        return 0 if fresh else 1

    # ---- Watch mode ----
    print(f"{tag_info()} watching every {args.watch}s (Ctrl-C to stop)")
    seen_ids: set[str] = set()
    cycle = 0
    try:
        while True:
            cycle += 1
            log_text = fetch_source(args.source_url, args.source_file,
                                     proxy, args.insecure)
            hits = find_hits(oob_ids, log_text)
            correlated = correlate(results, hits)
            fresh = render(correlated, new_only=seen_ids)
            seen_ids.update(hits.keys())
            print(f"{tag_info()} cycle {cycle}: {fresh} new, "
                  f"{len(seen_ids)} total unique hits so far. Sleeping {args.watch}s.")
            time.sleep(args.watch)
    except KeyboardInterrupt:
        print()
        print(f"{tag_info()} stopped after {cycle} cycle(s). "
              f"{len(seen_ids)} unique OAST hits.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
