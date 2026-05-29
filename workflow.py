#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
workflow.py - Multi-step request runner with state extraction
=====================================================================

THE PROBLEM
-----------
intruder.py / param_miner / etc. send one shape of request over and
over. Real exploitation often needs a CHAIN of requests where each
step depends on output from the previous:

  Step 1:  POST /login (get session cookie)
  Step 2:  GET /profile (extract CSRF token from form HTML)
  Step 3:  POST /api/change-email with session cookie + CSRF token
           + fuzzed email parameter

The information flow between steps - "find this in step 1's
response, send it in step 2's request" - is what makes the workflow
useful. Without it, you'd have to either run three separate scripts
and copy-paste tokens, or write Python from scratch for every chain.

This script automates the chain:
  1. Define the workflow in a JSON file (steps, requests, extractors).
  2. The runner executes each step in order, sharing one Session
     (cookies + connection pool) across all of them.
  3. After each step, declared EXTRACTORS pull values out of the
     response (regex, cookie, header, JSON path) and store them as
     variables.
  4. Subsequent steps reference those variables via {{var_name}}
     anywhere in their request - URL, header, body.
  5. The LAST step optionally has a `fuzz` block that runs sniper-
     style fuzzing on a §MARKER§ position - with all the captured
     state from previous steps already in place.

WORKFLOW FILE FORMAT
--------------------
{
  "vars": {                         # initial variables (literals)
    "base_url": "https://target.com"
  },
  "steps": [
    {
      "name": "login",
      "request": {
        "method": "POST",
        "url": "{{base_url}}/login",
        "headers": {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "username=admin&password=admin"
      },
      "extract": {
        "session_cookie": {"cookie": "session"}
      }
    },
    {
      "name": "get_csrf",
      "request": {
        "method": "GET",
        "url": "{{base_url}}/profile"
      },
      "extract": {
        "csrf": {"regex": "name=\\"csrf\\" value=\\"([^\\"]+)\\""}
      }
    },
    {
      "name": "fuzz_email",
      "request": {
        "method": "POST",
        "url": "{{base_url}}/api/email",
        "headers": {"Content-Type": "application/x-www-form-urlencoded"},
        "body": "csrf={{csrf}}&email=§EMAIL§"
      },
      "fuzz": {
        "payload": "emails.txt",
        "match_status": "200"
      }
    }
  ]
}

EXTRACTORS
----------
Each value in `extract` is a dict with ONE key:

  {"regex":    PATTERN}   first capture group of PATTERN matched
                          against the response body. Falls back to
                          group 0 if no capture group.
  {"cookie":   NAME}      value of cookie NAME from the response
                          (Set-Cookie header)
  {"header":   NAME}      value of response header NAME (case-insensitive)
  {"jsonpath": "$.a.b"}   simple JSON-path-ish navigation. Only dot
                          notation; no array indexing or filters.

If an extractor doesn't match, the variable stays undefined and
subsequent {{var}} references will leave the literal `{{var}}`
in the request (and the runner warns you).

VARIABLE SUBSTITUTION
---------------------
{{name}} in any string value (URL, header value, body) gets replaced
with the current value of variable `name`. Variables come from:
  - `vars` block of the workflow
  - extracted values from previous steps
  - --var CLI flag (override / add at runtime)

Substitution is plain string replacement, NOT escaping. If you put
a token into a URL or shell command, escape it yourself.

FUZZ STEP
---------
The last step (any step, really - but typically last) may include
a `fuzz` block:

  "fuzz": {
    "payload": "wordlist.txt",      // path to wordlist
    "match_status": "200",          // status filter (intruder syntax)
    "match_length": "!3168",        // optional length filter
    "match_regex":  "admin",        // optional regex matcher
    "workers": 10,                  // optional, default 10
    "max_rps": 0                    // optional, default 0
  }

The step's request must contain a `§MARKER§` (or §...§ with any
inner text - we treat all § blocks as the same marker for fuzz
mode). Each payload from the wordlist is substituted in turn and
the result is matched against the filters.

USE
---
  python3 workflow.py myflow.json
  python3 workflow.py myflow.json --var base_url=https://lab.example
  python3 workflow.py myflow.json --proxy burp
  python3 workflow.py myflow.json --dry-run  # show resolved requests, don't send
"""

import argparse
import json
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

# YAML is OPTIONAL. JSON works on a vanilla `pip install requests`;
# if you prefer hand-editing workflows in YAML (no quotes around
# every key, comments, block strings) install pyyaml as well.
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

from intruder import (
    build_session, parse_range_spec, range_matches, Matcher,
    write_json,
)
from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit, tag_miss,
    progress, bold, dim, cyan,
)


# ---------------------------------------------------------------------
# VARIABLE SUBSTITUTION
# ---------------------------------------------------------------------
# {{name}} - alphanumeric + underscore, no spaces.
VAR_RE = re.compile(r"\{\{(\w+)\}\}")


def substitute_str(text: str, vars: dict[str, str]) -> str:
    """Replace every {{name}} in text with vars[name]. Unknown vars left as-is."""
    if not isinstance(text, str):
        return text
    return VAR_RE.sub(
        lambda m: str(vars[m.group(1)]) if m.group(1) in vars else m.group(0),
        text,
    )


def substitute_deep(obj, vars: dict[str, str]):
    """
    Recurse into dicts/lists/strings and substitute {{name}} in any
    string values. Non-strings pass through unchanged.
    """
    if isinstance(obj, str):
        return substitute_str(obj, vars)
    if isinstance(obj, dict):
        return {k: substitute_deep(v, vars) for k, v in obj.items()}
    if isinstance(obj, list):
        return [substitute_deep(v, vars) for v in obj]
    return obj


def find_unresolved(obj) -> list[str]:
    """Scan an object for any remaining {{var}} markers - returns the var names."""
    found: list[str] = []
    if isinstance(obj, str):
        found.extend(VAR_RE.findall(obj))
    elif isinstance(obj, dict):
        for v in obj.values():
            found.extend(find_unresolved(v))
    elif isinstance(obj, list):
        for v in obj:
            found.extend(find_unresolved(v))
    return found


# ---------------------------------------------------------------------
# EXTRACTORS
# ---------------------------------------------------------------------
def extract_value(extractor: dict, response: requests.Response) -> str | None:
    """
    Run a single extractor against a response. Returns the extracted
    string, or None if it didn't match. Caller decides what to do
    with None (typically: warn and keep the variable undefined).
    """
    if not isinstance(extractor, dict) or len(extractor) != 1:
        raise ValueError(f"extractor must be a dict with exactly one key, got {extractor!r}")
    kind, arg = next(iter(extractor.items()))

    if kind == "regex":
        m = re.search(arg, response.text, re.DOTALL)
        if not m:
            return None
        # If the pattern has a capture group, return group(1). Otherwise
        # return the entire match. Most extractors will use ([^"]+)
        # style captures, but we tolerate either.
        return m.group(1) if m.groups() else m.group(0)

    if kind == "cookie":
        return response.cookies.get(arg)

    if kind == "header":
        # requests headers are case-insensitive.
        return response.headers.get(arg)

    if kind == "jsonpath":
        # Trivial dotted-path: "$.foo.bar" -> response.json()['foo']['bar']
        # Doesn't support array indexing, filters, etc. - for that
        # use a real jsonpath library. Keeping zero-deps here.
        try:
            data = response.json()
        except ValueError:
            return None
        path = arg.lstrip("$.").split(".")
        for segment in path:
            if not segment:
                continue
            if isinstance(data, dict) and segment in data:
                data = data[segment]
            else:
                return None
        return str(data) if data is not None else None

    raise ValueError(f"unknown extractor kind: {kind!r}")


# ---------------------------------------------------------------------
# WORKFLOW FILE LOADER (JSON or YAML)
# ---------------------------------------------------------------------
def load_workflow_file(path: Path) -> dict:
    """
    Load a workflow file. Format inferred from extension:
       .json          json.loads
       .yaml / .yml   yaml.safe_load (requires `pip install pyyaml`)
    Anything else falls back to JSON.

    Why support YAML at all? Workflows with many steps + nested
    extractors get unwieldy in JSON (every key quoted, no comments,
    no multi-line strings). YAML reads much better for humans.
    """
    text = path.read_text()
    if path.suffix.lower() in (".yaml", ".yml"):
        if not _HAS_YAML:
            sys.exit(f"{tag_err()} YAML workflows need PyYAML. "
                     f"Install with: pip install pyyaml")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as e:
            sys.exit(f"{tag_err()} YAML parse error: {e}")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            sys.exit(f"{tag_err()} JSON parse error: {e}")
    if not isinstance(data, dict):
        sys.exit(f"{tag_err()} workflow root must be an object/dict, "
                 f"got {type(data).__name__}")
    return data


# ---------------------------------------------------------------------
# CONDITIONAL `if:` EVALUATOR
# ---------------------------------------------------------------------
# Tiny expression language for the `if:` field on a step. Supports:
#
#   "{{var}} == something"      string equality
#   "{{var}} != something"      string inequality
#   "{{var}}"                   truthy: non-empty string
#   "!{{var}}"                  falsy: empty / unset
#   "{{a}} > 5"                 numeric (>, <, >=, <=) if both sides parse as numbers
#
# We deliberately don't add a full expression parser - those tend to
# accumulate operators and become a security risk. The above five
# patterns cover 95% of real branching needs; for anything more
# elaborate, build a workflow that conditionally INCLUDES different
# sub-workflows.
def eval_condition(expr: str, vars: dict) -> bool:
    """
    Substitute vars into expr, then evaluate as a boolean.
    Whitespace around operators is tolerated.

    In condition context, ANY leftover {{var}} placeholders that
    didn't resolve are treated as empty strings - so a condition
    on a never-set variable returns False (not True from the
    literal text being non-empty). That's the intuitive behavior
    for branching on "did we capture this?".
    """
    resolved = substitute_str(expr, vars).strip()
    # Blank out any unresolved {{name}} - treat missing as empty.
    resolved = VAR_RE.sub("", resolved)

    # Negation prefix: "!{{var}}" - truthy of (not value).
    negate = False
    if resolved.startswith("!"):
        negate = True
        resolved = resolved[1:].strip()

    # Try each operator longest-first so "==" wins over "=" if we
    # ever add the latter; ">=" wins over ">", etc.
    for op in ("==", "!=", ">=", "<=", ">", "<"):
        if op in resolved:
            left, _, right = resolved.partition(op)
            left, right = left.strip(), right.strip()
            if op == "==":
                result = left == right
            elif op == "!=":
                result = left != right
            else:
                # Numeric comparison; treat non-numeric as inequality False.
                try:
                    ln, rn = float(left), float(right)
                except ValueError:
                    result = False
                else:
                    result = {">": ln > rn, "<": ln < rn,
                              ">=": ln >= rn, "<=": ln <= rn}[op]
            return (not result) if negate else result

    # No operator: truthy check. Empty string / "0" / "false" -> falsy.
    truthy = bool(resolved) and resolved.lower() not in ("0", "false", "no")
    return (not truthy) if negate else truthy


# ---------------------------------------------------------------------
# LOOP DRIVER
# ---------------------------------------------------------------------
# A step's `loop:` block tells us to execute the step's body multiple
# times. Supports two flavors:
#
#   {"count": 5}                 fixed N iterations
#   {"count": 5, "var": "page"}  fixed N, expose iteration index as {{page}}
#                                (defaults to {{loop_index}} when var omitted)
#   {"until_status": 200,
#    "max": 10}                  loop until response status == 200,
#                                cap at `max` iterations to prevent
#                                infinite loops on a broken endpoint
#   {"until_extract": "csrf",
#    "max": 5}                   loop until variable `csrf` becomes set
#                                (i.e. step's extractor finally matched)
#
# Always bounded - we never iterate without a `count` or `max`. Refusing
# to spin forever on a server that won't return the expected condition.
def _loop_iterations(loop_def: dict) -> tuple[int, str]:
    """Resolve the iteration cap + index variable name."""
    if "count" in loop_def:
        return int(loop_def["count"]), loop_def.get("var", "loop_index")
    if "max" in loop_def:
        return int(loop_def["max"]), loop_def.get("var", "loop_index")
    # Default ceiling so we don't spin forever - 10 is a sane "real
    # workflow" upper bound.
    return 10, loop_def.get("var", "loop_index")


def _loop_should_break(loop_def: dict, response, state: dict) -> bool:
    """Check the loop's exit condition against the latest response/state."""
    if "until_status" in loop_def and response is not None:
        return response.status_code == int(loop_def["until_status"])
    if "until_extract" in loop_def:
        return loop_def["until_extract"] in state["vars"]
    return False


# ---------------------------------------------------------------------
# STEP EXECUTION
# ---------------------------------------------------------------------
def execute_request(session: requests.Session, request_def: dict,
                    timeout: int = 30) -> requests.Response:
    """
    Send a single request defined by a (resolved - no more {{vars}})
    request dict. Returns the requests.Response.

    allow_redirects=False so workflow steps can extract values from
    redirect responses (Location header, Set-Cookie on intermediate
    302s, etc.). If you want redirect-following, do an extra step.
    """
    method = request_def.get("method", "GET").upper()
    url = request_def.get("url")
    if not url:
        raise ValueError("request must have a `url` field")
    headers = request_def.get("headers", {})
    body = request_def.get("body")
    return session.request(
        method=method, url=url, headers=headers,
        data=body, allow_redirects=False, timeout=timeout,
    )


def run_step(session, step: dict, state: dict, dry_run: bool) -> requests.Response | None:
    """
    Execute one step: substitute variables, send request, run extractors.
    Returns the Response (or None if dry-run).
    """
    name = step.get("name", "<unnamed>")
    print(cyan(f"=== {name} ==="))

    raw_request = step.get("request", {})
    resolved = substitute_deep(raw_request, state["vars"])

    # Warn about anything that didn't resolve.
    unresolved = find_unresolved(resolved)
    if unresolved:
        print(f"{tag_warn()} unresolved variable(s) in this step: "
              f"{sorted(set(unresolved))}")

    method = resolved.get("method", "GET").upper()
    url = resolved.get("url", "")
    print(f"  {method} {url}")
    if resolved.get("body"):
        body_preview = resolved["body"][:200]
        print(f"  body : {body_preview}{'...' if len(resolved['body']) > 200 else ''}")

    if dry_run:
        print(f"{tag_info()} [dry-run] not sending")
        return None

    start = time.monotonic()
    try:
        r = execute_request(session, resolved)
    except requests.exceptions.RequestException as e:
        print(f"{tag_err()} request failed: {e}")
        return None
    elapsed = time.monotonic() - start
    print(f"  status: {r.status_code}  length: {len(r.content)}  "
          f"time: {elapsed*1000:.0f}ms")

    # Run extractors
    for var_name, extractor_def in step.get("extract", {}).items():
        try:
            value = extract_value(extractor_def, r)
        except (ValueError, re.error) as e:
            print(f"{tag_err()} extractor for {var_name!r} failed: {e}")
            continue
        if value is None:
            print(f"{tag_warn()} extractor for {var_name!r} found nothing")
            continue
        state["vars"][var_name] = value
        # Don't print the full value (could be huge HTML); show
        # a truncated preview so the user can sanity-check.
        preview = value[:80] + ("..." if len(value) > 80 else "")
        print(f"  {tag_ok()} extracted {bold(var_name)} = {preview!r}")

    return r


# ---------------------------------------------------------------------
# FUZZ STEP (sniper mode against a §MARKER§ in the resolved request)
# ---------------------------------------------------------------------
# This is intentionally simpler than intruder.py's full attack mode
# library. The workflow shape forces sniper-with-one-marker as the
# common case; for cluster-bomb you'd use intruder.py directly with
# the cookies you captured here.
MARKER_RE = re.compile(r"§(.*?)§", re.DOTALL)


def run_fuzz(session, step: dict, state: dict, dry_run: bool) -> list[dict]:
    """
    Sniper-fuzz a step's request: read payloads, substitute each in
    place of §...§ marker(s), send, apply matcher.
    """
    fuzz_def = step["fuzz"]
    payload_path = Path(substitute_str(fuzz_def["payload"], state["vars"]))
    if not payload_path.exists():
        print(f"{tag_err()} fuzz payload file not found: {payload_path}")
        return []

    payloads = [p for p in (l.strip() for l in payload_path.read_text().splitlines()) if p]

    # Build the matcher from fuzz_def's match_* keys (intruder syntax).
    matcher = Matcher(
        status=parse_range_spec(fuzz_def["match_status"]) if "match_status" in fuzz_def else None,
        length=parse_range_spec(fuzz_def["match_length"]) if "match_length" in fuzz_def else None,
        regex=re.compile(fuzz_def["match_regex"]) if "match_regex" in fuzz_def else None,
    )

    raw_request = step.get("request", {})
    resolved = substitute_deep(raw_request, state["vars"])
    workers = int(fuzz_def.get("workers", 10))

    if dry_run:
        print(f"{tag_info()} [dry-run] would fuzz {len(payloads)} payloads")
        return []

    print(f"{tag_info()} fuzz: {len(payloads)} payloads, {workers} workers")

    def probe(payload: str):
        # Replace EVERY § block in URL + headers + body with this
        # payload. The "all markers get the same value" rule is
        # effectively battering-ram mode against the §...§ positions.
        def sub_one(_match):
            return payload

        request_for_payload = {
            "method": resolved.get("method", "GET"),
            "url":    MARKER_RE.sub(sub_one, resolved.get("url", "")),
            "headers": {k: MARKER_RE.sub(sub_one, v)
                        for k, v in resolved.get("headers", {}).items()},
            "body":   MARKER_RE.sub(sub_one, resolved.get("body", "") or ""),
        }

        start = time.monotonic()
        try:
            r = execute_request(session, request_for_payload)
            elapsed = time.monotonic() - start
            return (payload, r.status_code, len(r.content), r.text, elapsed, None)
        except requests.exceptions.RequestException as e:
            return (payload, None, 0, "", 0.0, str(e))

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(probe, p) for p in payloads]
        for fut in progress(as_completed(futures), total=len(futures), desc="fuzz"):
            payload, status, length, body, elapsed, err = fut.result()
            if err:
                hit = False
                print(f"{tag_err()} {payload!r}: {err}")
            else:
                hit = matcher.matches(status, length, body, elapsed)
                if hit:
                    print(f"{tag_hit()} {bold(payload)!r}  status={status} len={length} time={elapsed:.2f}s")
            results.append({
                "label": payload, "status": status, "length": length,
                "time": round(elapsed, 4), "hit": hit, "error": err,
            })

    n_hits = sum(1 for r in results if r["hit"])
    print(f"{tag_info()} fuzz complete: {n_hits} hit(s) / {len(results)} probes")
    return results


# ---------------------------------------------------------------------
# DRIVER
# ---------------------------------------------------------------------
def run_workflow(workflow: dict, session: requests.Session,
                 initial_vars: dict[str, str], dry_run: bool,
                 _base_path: Path | None = None) -> dict:
    """
    Execute the whole workflow. Returns a summary dict for the JSON
    output (states per step + any fuzz results).

    `_base_path` is used internally for include: directives - it's
    the directory of the OUTER workflow file so relative includes
    resolve correctly.
    """
    state = {"vars": {**workflow.get("vars", {}), **initial_vars}}
    print(f"{tag_info()} starting workflow with vars: {sorted(state['vars'])}")

    summary: dict = {"steps": [], "fuzz_results": []}

    for step in workflow.get("steps", []):
        name = step.get("name", "<unnamed>")

        # ---- include: chain another workflow inline ----
        # Useful for sharing a common "log in" preamble across many
        # workflows. The included workflow runs through the SAME
        # session (cookies propagate) and its final state is merged
        # back into ours.
        if "include" in step:
            included_rel = substitute_str(step["include"], state["vars"])
            included_path = Path(included_rel)
            if _base_path and not included_path.is_absolute():
                included_path = _base_path / included_path
            if not included_path.exists():
                print(f"{tag_err()} include not found: {included_path}")
                summary["steps"].append({"name": name, "include": included_rel,
                                          "error": "file not found"})
                continue
            print(cyan(f"=== {name} (include: {included_path}) ==="))
            try:
                sub_workflow = load_workflow_file(included_path)
            except SystemExit:
                # load_workflow_file already printed a useful error;
                # don't let it abort the parent workflow.
                summary["steps"].append({"name": name, "include": included_rel,
                                          "error": "parse failed"})
                continue
            # Step-level `vars` override the included workflow's defaults
            # (but DON'T pollute the parent state with the overrides -
            # they're scoped to this include).
            extra_vars = {**state["vars"], **step.get("vars", {})}
            sub_summary = run_workflow(sub_workflow, session, extra_vars,
                                        dry_run, _base_path=included_path.parent)
            # Merge any vars the sub-workflow extracted back into ours
            # so subsequent steps can reference them.
            for k, v in sub_summary.get("final_vars", {}).items():
                state["vars"][k] = v
            summary["steps"].append({"name": name, "include": included_rel,
                                      "sub_steps": sub_summary.get("steps", [])})
            continue

        # ---- if: skip when condition is false ----
        if "if" in step:
            cond = step["if"]
            if not eval_condition(cond, state["vars"]):
                resolved = substitute_str(cond, state["vars"])
                print(cyan(f"=== {name} ==="))
                print(f"  {dim('[skipped: if ' + cond + ' resolved to ' + resolved + ' = false]')}")
                summary["steps"].append({"name": name, "skipped": True,
                                          "if": cond})
                continue

        # ---- loop: run the step multiple times ----
        if "loop" in step:
            loop_def = step["loop"]
            max_iter, var_name = _loop_iterations(loop_def)
            iterations_done = 0
            last_response = None
            for i in range(max_iter):
                # Expose the iteration index as a variable so the
                # step's request can use {{loop_index}} / {{page}}.
                state["vars"][var_name] = str(i)
                last_response = run_step(session, step, state, dry_run)
                iterations_done += 1
                if _loop_should_break(loop_def, last_response, state):
                    print(f"  {dim('[loop exit condition met after ' + str(i + 1) + ' iteration(s)]')}")
                    break
            else:
                # Loop ran to its max without the exit condition firing -
                # might or might not be expected, but worth flagging.
                if "until_status" in loop_def or "until_extract" in loop_def:
                    print(f"  {dim('[loop reached max=' + str(max_iter) + ' without satisfying exit condition]')}")

            summary["steps"].append({
                "name": name,
                "loop": True,
                "iterations": iterations_done,
                "status": getattr(last_response, "status_code", None),
            })
            if "fuzz" in step:
                summary["fuzz_results"] = run_fuzz(session, step, state, dry_run)
            continue

        # ---- Plain step (the original code path) ----
        response = run_step(session, step, state, dry_run)
        step_record = {
            "name": name,
            "status": getattr(response, "status_code", None),
        }
        summary["steps"].append(step_record)

        if "fuzz" in step:
            summary["fuzz_results"] = run_fuzz(session, step, state, dry_run)

    # Expose final state vars so an outer workflow that included
    # us can merge them back.
    summary["final_vars"] = dict(state["vars"])
    return summary


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def parse_var(raw: str) -> tuple[str, str]:
    if "=" not in raw:
        sys.exit(f"{tag_err()} --var must look like name=value, got {raw!r}")
    name, _, value = raw.partition("=")
    return name.strip(), value


# ---------------------------------------------------------------------
# --watch MODE: re-run the workflow when the file (or any included
# file) changes on disk
# ---------------------------------------------------------------------
def collect_watched_paths(workflow: dict, base: Path) -> list[Path]:
    """
    Walk the workflow recursively and return every file path we should
    watch: the workflow itself + any include: targets + the includes'
    own includes.

    Best-effort - if an include can't be loaded (missing / parse error)
    we skip its descendants. Caller is expected to also add the
    top-level workflow path.
    """
    paths: list[Path] = []
    for step in workflow.get("steps", []):
        if "include" in step:
            inc_str = step["include"]
            # Strip any {{vars}} from the include path - if it's dynamic,
            # we can't know what to watch. Skip vars-bearing includes.
            if "{{" in inc_str:
                continue
            inc_path = Path(inc_str)
            if not inc_path.is_absolute():
                inc_path = base / inc_path
            if not inc_path.exists():
                continue
            paths.append(inc_path)
            try:
                sub = load_workflow_file(inc_path)
                paths.extend(collect_watched_paths(sub, inc_path.parent))
            except SystemExit:
                # load_workflow_file calls sys.exit on parse error -
                # in watch mode we don't want that to kill us.
                continue
    return paths


def latest_mtime(paths: list[Path]) -> float:
    """Most recent mtime across all paths. 0 if none exist."""
    times = []
    for p in paths:
        try:
            times.append(p.stat().st_mtime)
        except FileNotFoundError:
            continue
    return max(times) if times else 0.0


def watch_loop(workflow_path: Path, run_fn, poll_interval: float = 1.0):
    """
    Run the workflow once, then re-run whenever the workflow file
    (or any of its includes) gets modified.

    Polling approach (no inotify / watchdog dependency) - good enough
    for human-paced editing. 1-second poll = at most 1s of latency
    after you save.

    Ctrl-C ends the loop cleanly.
    """
    # First pass to discover which files to monitor.
    try:
        wf = load_workflow_file(workflow_path)
        watched = [workflow_path] + collect_watched_paths(wf, workflow_path.parent)
    except SystemExit:
        watched = [workflow_path]

    print(f"{tag_info()} watch mode: monitoring {len(watched)} file(s) "
          f"(poll every {poll_interval}s, Ctrl-C to exit)")
    for p in watched:
        print(f"   {dim(str(p))}")

    last_mtime = 0.0
    try:
        while True:
            current = latest_mtime(watched)
            if current > last_mtime:
                if last_mtime > 0:    # not the first run - show divider
                    print()
                    print(cyan("=" * 60))
                    print(cyan(f"=== change detected, re-running ==="))
                    print(cyan("=" * 60))
                try:
                    run_fn()
                except KeyboardInterrupt:
                    raise
                except Exception as e:
                    print(f"{tag_err()} workflow failed: {e}")
                last_mtime = current
                # Re-scan watched files - includes may have been
                # added or removed by the edit.
                try:
                    wf = load_workflow_file(workflow_path)
                    watched = [workflow_path] + collect_watched_paths(
                        wf, workflow_path.parent)
                except SystemExit:
                    pass
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print()
        print(f"{tag_info()} watch stopped")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("workflow_file", type=Path,
                    help="Workflow definition JSON file")
    ap.add_argument("--var", action="append", default=[], metavar="NAME=VALUE",
                    help="Set/override a workflow variable from the CLI (repeatable)")
    ap.add_argument("--dry-run", action="store_true",
                    help="Resolve variables and print each request, but don't send")
    ap.add_argument("--proxy", metavar="URL")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--output", type=Path, metavar="FILE.json",
                    help="Write summary (step statuses + fuzz hits) to this file")
    ap.add_argument("--watch", action="store_true",
                    help="Re-run the workflow whenever the file (or any "
                         "include: file it references) changes on disk. "
                         "Polls mtime every --watch-interval seconds. "
                         "Useful for live-editing a workflow while watching "
                         "results - save the file to trigger a fresh run.")
    ap.add_argument("--watch-interval", type=float, default=1.0,
                    metavar="SEC",
                    help="Mtime poll interval in seconds (default 1.0).")
    args = ap.parse_args()

    if not args.workflow_file.exists():
        sys.exit(f"{tag_err()} workflow file not found: {args.workflow_file}")
    workflow = load_workflow_file(args.workflow_file)

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

    initial_vars: dict[str, str] = {}
    for raw in args.var:
        k, v = parse_var(raw)
        initial_vars[k] = v

    def _run_once():
        """One pass through the workflow. Reloads the file each time
        so --watch picks up edits, and gets a fresh Session so cookies
        from a previous run don't leak into the new one."""
        wf = load_workflow_file(args.workflow_file)
        session = build_session(workers=4, proxy=proxy, insecure=insecure, retries=2)
        summary = run_workflow(wf, session, initial_vars, args.dry_run,
                                _base_path=args.workflow_file.parent)
        if args.output:
            write_json([{"workflow_summary": summary}], args.output)
            print(f"{tag_info()} wrote summary to {args.output}")

    if args.watch:
        watch_loop(args.workflow_file, _run_once, args.watch_interval)
        return 0

    _run_once()
    return 0


if __name__ == "__main__":
    sys.exit(main())
