#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
response_diff.py - Compare two HTTP responses, stripping dynamic noise
=====================================================================

WHAT THIS SOLVES
----------------
`diff response-a.txt response-b.txt` is usually useless on real web
responses because EVERY response has new dynamic noise:
  - CSRF tokens regenerated per request
  - Session IDs in cookies and hidden fields
  - Timestamps (rendered into the HTML)
  - Cache-buster URL params on script/style references
  - Nonces in CSP headers

A naive diff drowns the real signal (the 1-character "Invalid
username" vs "Invalid username." in the BSCP subtle-difference lab)
in 30 lines of "this CSRF token differs."

response_diff.py:
  1. Reads two response bodies (files or stdin).
  2. CANONICALIZES both: regex-substitutes away every dynamic pattern
     you tell it about (plus a sensible default set).
  3. Diffs the canonicalized versions and prints a colored unified
     diff showing ONLY the meaningful changes.

DEFAULT STRIP PATTERNS
----------------------
Out of the box we strip:
  - PortSwigger-style CSRF tokens: name="csrf" value="..."
  - Generic CSRF inputs: name="*csrf*" value="..."
  - ISO 8601 timestamps
  - Unix epoch (10 / 13 digit timestamps in obvious contexts)
  - Cache-buster query params: ?v=..., ?_=..., ?ts=...
  - CSP / SRI nonces and integrity hashes
  - GUIDs / UUIDs
  - JWT-shaped tokens (3 base64url parts with dots)

Add your own with `--strip 'regex pattern'` (repeatable). Anything
the pattern matches becomes literal text "[STRIPPED]" in BOTH
responses before diffing.

USE
---
File vs file:
  python3 response_diff.py a.txt b.txt

Just check if they're effectively identical (exit 0 if same after
canonicalization, 1 if different):
  python3 response_diff.py a.txt b.txt --quiet

Add custom strip patterns for an unusual dynamic value:
  python3 response_diff.py a.txt b.txt \\
      --strip 'requestId":"[a-f0-9-]+"' \\
      --strip 'data-timestamp="[0-9]+"'

Diff intruder.py's --include-body NDJSON output to compare any two
results offline:
  jq '.[0].body' results.json > a.txt
  jq '.[5].body' results.json > b.txt
  python3 response_diff.py a.txt b.txt

DIFF MODES
----------
  unified (default)  Standard +/- line diff with N lines of context.
  char               Side-by-side character-level diff. Use for short
                     responses where line-level granularity is too coarse.
  summary            Just count + locate differences ("3 changes, lines
                     N, M, K"). Use to quickly triage.
"""

import argparse
import difflib
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from _common import (
    tag_info, tag_ok, tag_warn, tag_err, bold, cyan, green, red, dim, yellow,
)


# =====================================================================
# DEFAULT NOISE PATTERNS
# =====================================================================
# Each entry is (description, regex). The regex's match is REPLACED by
# the literal string "[STRIPPED]" in both responses before diffing.
# Patterns are conservative - if in doubt, we'd rather miss noise than
# accidentally strip real content.
DEFAULT_PATTERNS: list[tuple[str, str]] = [
    # CSRF tokens - PortSwigger lab style + common generic variants.
    ("PortSwigger CSRF input",
     r'name=["\']?csrf["\']?\s+value=["\'][^"\']+["\']'),
    ("CSRF value=name swapped",
     r'value=["\'][^"\']+["\']\s+name=["\']?csrf["\']?'),
    ("Generic *csrf* form input",
     r'name=["\'][^"\']*csrf[^"\']*["\']\s+value=["\'][^"\']+["\']'),

    # Cache-buster URL params (the ?v=hash on script tags + ?_=ts on AJAX).
    ("Cache-buster ?v=...",   r'[?&]v=[A-Za-z0-9._-]+'),
    ("Cache-buster ?ts=...",  r'[?&]ts=\d+'),
    ("Cache-buster ?_=...",   r'[?&]_=\d+'),

    # Time stamps.
    ("ISO 8601 timestamp",
     r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
    ("Unix epoch in HTML data-* attr",
     r'data-(?:timestamp|created|updated)=["\'](\d{10,13})["\']'),

    # CSP / Subresource Integrity.
    ("CSP nonce",                 r"nonce-['\"][A-Za-z0-9+/=_-]+['\"]"),
    ("CSP nonce header",          r'nonce-[A-Za-z0-9+/=_-]+'),
    ("SRI integrity hash",        r'integrity=["\']sha\d{3}-[A-Za-z0-9+/=]+["\']'),

    # GUIDs / UUIDs.
    ("UUID / GUID",
     r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),

    # JWT-shaped tokens (rare to embed in HTML, but show up in JSON
    # responses + Authorization headers if we're diffing raw HTTP).
    ("JWT-shaped token",
     r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),

    # Session ID query / hidden form patterns.
    ("Session ID hidden input",
     r'name=["\'](?:JSESSIONID|PHPSESSID|session_id|sessionid)["\']\s+value=["\'][^"\']+["\']'),
]


# =====================================================================
# CANONICALIZATION
# =====================================================================
@dataclass
class CanonConfig:
    """Patterns to strip + whether to also collapse whitespace."""
    patterns: list[tuple[str, str]] = field(default_factory=list)
    collapse_whitespace: bool = False
    placeholder: str = "[STRIPPED]"


def canonicalize(text: str, cfg: CanonConfig) -> str:
    """Apply every strip pattern to text, returning the canonical form."""
    out = text
    for _label, pattern in cfg.patterns:
        out = re.sub(pattern, cfg.placeholder, out, flags=re.IGNORECASE | re.DOTALL)
    if cfg.collapse_whitespace:
        # Replace runs of any whitespace (incl. newlines) with one space.
        out = re.sub(r"\s+", " ", out)
    return out


# =====================================================================
# DIFF MODES
# =====================================================================
def render_unified_diff(a: str, b: str, context: int = 3,
                         a_name: str = "A", b_name: str = "B") -> tuple[bool, str]:
    """
    Standard unified diff, ANSI-colored. Returns (changed, rendered).
    """
    a_lines = a.splitlines(keepends=True)
    b_lines = b.splitlines(keepends=True)
    diff_lines = list(difflib.unified_diff(
        a_lines, b_lines, fromfile=a_name, tofile=b_name,
        n=context, lineterm="",
    ))
    if not diff_lines:
        return False, ""
    out = []
    for line in diff_lines:
        if line.startswith("---") or line.startswith("+++"):
            out.append(bold(line))
        elif line.startswith("@@"):
            out.append(cyan(line))
        elif line.startswith("+"):
            out.append(green(line))
        elif line.startswith("-"):
            out.append(red(line))
        else:
            out.append(dim(line))
    return True, "\n".join(out)


def render_summary(a: str, b: str) -> tuple[bool, str]:
    """
    Compact "where are the differences?" output. Doesn't show CONTENT;
    just counts changes and reports line ranges. Use for triage.
    """
    a_lines = a.splitlines()
    b_lines = b.splitlines()
    matcher = difflib.SequenceMatcher(None, a_lines, b_lines, autojunk=False)
    if matcher.ratio() == 1.0:
        return False, ""
    changes = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        changes.append(f"  {tag:>7s}  A[{i1}:{i2}]  -> B[{j1}:{j2}]"
                        f"  ({i2 - i1} -> {j2 - j1} lines)")
    summary = (f"similarity ratio: {matcher.ratio():.4f}  "
               f"({len(changes)} change region(s))\n" + "\n".join(changes))
    return True, summary


def render_char_diff(a: str, b: str) -> tuple[bool, str]:
    """
    Character-level inline diff. For SHORT strings where line-level
    diff is too coarse (e.g. the BSCP 1-char-difference lab where
    you need to see WHICH character differs).
    """
    if a == b:
        return False, ""
    matcher = difflib.SequenceMatcher(None, a, b, autojunk=False)
    a_out, b_out = [], []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        a_chunk = a[i1:i2]
        b_chunk = b[j1:j2]
        if tag == "equal":
            a_out.append(dim(a_chunk))
            b_out.append(dim(b_chunk))
        elif tag == "delete":
            a_out.append(red(a_chunk))
        elif tag == "insert":
            b_out.append(green(b_chunk))
        elif tag == "replace":
            a_out.append(red(a_chunk))
            b_out.append(green(b_chunk))
    out = (f"{bold('A: ')}{''.join(a_out)}\n"
           f"{bold('B: ')}{''.join(b_out)}")
    return True, out


# =====================================================================
# CLI
# =====================================================================
def _read_input(path_or_dash: str) -> str:
    """Read from file path, or from stdin if the arg is '-'."""
    if path_or_dash == "-":
        return sys.stdin.read()
    p = Path(path_or_dash)
    if not p.exists():
        sys.exit(f"{tag_err()} file not found: {p}")
    return p.read_text(errors="replace")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("file_a",
                    help="First response file (or '-' for stdin if file_b is given)")
    ap.add_argument("file_b",
                    help="Second response file")
    ap.add_argument("--strip", action="append", default=[], metavar="REGEX",
                    help="Additional regex pattern to strip before diffing. "
                         "Repeatable. Adds to the default pattern set.")
    ap.add_argument("--no-default-strips", action="store_true",
                    help="Disable the built-in pattern set (CSRF tokens, "
                         "timestamps, etc.). Use only the --strip patterns "
                         "you provide.")
    ap.add_argument("--mode", choices=["unified", "char", "summary"],
                    default="unified",
                    help="Diff style: unified (default) +/- line diff; "
                         "char = inline char-level diff for short strings; "
                         "summary = count + line ranges only.")
    ap.add_argument("--context", type=int, default=3, metavar="LINES",
                    help="Unified diff context lines (default 3)")
    ap.add_argument("--collapse-whitespace", action="store_true",
                    help="Collapse all whitespace runs to single spaces "
                         "before diffing - useful when only the textual "
                         "content matters, not formatting.")
    ap.add_argument("--quiet", action="store_true",
                    help="Print nothing - just return exit code 0 if "
                         "responses are effectively identical (after "
                         "canonicalization), 1 if they differ.")
    ap.add_argument("--show-strips", action="store_true",
                    help="Print every strip pattern (defaults + --strip) "
                         "before running. Useful for debugging which "
                         "pattern accidentally ate real content.")
    args = ap.parse_args()

    # Build the pattern set: defaults (unless suppressed) + user's --strip.
    patterns = []
    if not args.no_default_strips:
        patterns.extend(DEFAULT_PATTERNS)
    for p in args.strip:
        patterns.append((f"user pattern", p))

    if args.show_strips:
        print(f"{tag_info()} active strip patterns:")
        for label, pat in patterns:
            print(f"  [{label}]  {pat}")
        print()

    cfg = CanonConfig(patterns=patterns, collapse_whitespace=args.collapse_whitespace)

    text_a = _read_input(args.file_a)
    text_b = _read_input(args.file_b)
    canon_a = canonicalize(text_a, cfg)
    canon_b = canonicalize(text_b, cfg)

    if args.mode == "summary":
        changed, out = render_summary(canon_a, canon_b)
    elif args.mode == "char":
        changed, out = render_char_diff(canon_a, canon_b)
    else:
        changed, out = render_unified_diff(canon_a, canon_b,
                                             context=args.context,
                                             a_name=args.file_a,
                                             b_name=args.file_b)

    if args.quiet:
        return 1 if changed else 0

    if not changed:
        print(f"{tag_ok()} responses are identical after canonicalization "
              f"({len(patterns)} strip pattern(s) applied)")
        return 0

    print(out)
    print()
    print(f"{tag_info()} responses DIFFER after canonicalization "
          f"({len(patterns)} strip pattern(s) applied)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
