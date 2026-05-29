#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
decode_tool.py - Decode-side companion to intruder.py's --encode
=====================================================================

USE
---
  python3 decode_tool.py url     '%27%20OR%201%3D1'
  python3 decode_tool.py base64  'YWRtaW4='
  python3 decode_tool.py hex     '6164 6d69 6e'
  python3 decode_tool.py html    '&lt;script&gt;'
  python3 decode_tool.py chain   'base64,url' 'YWRtaW4lM0Q='   # outermost first
  python3 decode_tool.py auto    'somestring'                  # try to guess

WHY
---
Pentesting is full of "what is this string actually?". Cookies and
parameters get URL-encoded, then base64-encoded, then sometimes
again. The browser hands you `dXNlcj1hZG1pbg%3D%3D` and you need
to know it's `user=admin`.

This tool is the reverse of intruder.py's --encode. Same encoders,
applied in reverse. Plus an `auto` mode that guesses likely
encodings and shows you what each one produces.

CHAIN ORDER
-----------
Important: with --encode you specify encoders in APPLY order
("url then base64" means base64(url(payload))). With decode you
specify them in REVERSE-APPLY order = how they're nested OUTERMOST
first.

So if the encoder chain was --encode url,base64, the decoded chain
is --decode base64,url. The tool prints what it's doing for clarity.

AUTO MODE
---------
`auto` tries every single-step decoder and shows whatever produces
"printable readable text". Useful when you don't know what you have.
It does NOT try chains - chain combinations would explode the
output. For chains, decode the outer layer first with `auto`, then
run `auto` again on the result.

DECODERS
--------
The five encoders from intruder.py have inverses here. `none` is
trivially its own inverse.
"""

import argparse
import base64
import binascii
import html
import json
import sys
import urllib.parse

from _common import (
    tag_info, tag_ok, tag_warn, tag_err, bold, cyan, dim,
)


# ---------------------------------------------------------------------
# DECODERS
# ---------------------------------------------------------------------
# Each decoder takes a string and returns a string (or raises a Python
# exception if the input isn't valid for that encoding). `auto` uses
# the exceptions to skip decoders that obviously don't apply.

def _dec_url(s: str) -> str:
    """Standard percent-decoding. '+' is interpreted as a space (urlencoded form rule)."""
    return urllib.parse.unquote_plus(s)


def _dec_double_url(s: str) -> str:
    """Apply URL decode twice."""
    return _dec_url(_dec_url(s))


def _dec_base64(s: str) -> str:
    """
    Standard base64. We pad to a multiple of 4 because pasted tokens
    often have their `=` padding stripped.
    """
    s_clean = s.strip().replace("-", "+").replace("_", "/")  # also tolerate base64url
    pad = (-len(s_clean)) % 4
    return base64.b64decode(s_clean + "=" * pad).decode("utf-8", errors="replace")


def _dec_hex(s: str) -> str:
    """Hex string -> bytes -> text. Tolerate whitespace and 0x prefixes."""
    s_clean = s.strip().replace(" ", "").replace("\n", "").replace("\t", "")
    if s_clean.startswith("0x") or s_clean.startswith("0X"):
        s_clean = s_clean[2:]
    return bytes.fromhex(s_clean).decode("utf-8", errors="replace")


def _dec_html(s: str) -> str:
    """HTML entity decode: &lt; -> <, &amp; -> &, &#65; -> A, etc."""
    return html.unescape(s)


def _dec_none(s: str) -> str:
    return s


DECODERS = {
    "url":        _dec_url,
    "double-url": _dec_double_url,
    "base64":     _dec_base64,
    "hex":        _dec_hex,
    "html":       _dec_html,
    "none":       _dec_none,
}


# ---------------------------------------------------------------------
# CHAIN PARSER (same shape as intruder.parse_encode_chain)
# ---------------------------------------------------------------------
def parse_decode_chain(s: str) -> list[str]:
    if not s or s.strip().lower() == "none":
        return []
    names = [n.strip().lower() for n in s.split(",") if n.strip()]
    for n in names:
        if n not in DECODERS:
            sys.exit(f"{tag_err()} unknown decoder {n!r}. "
                     f"Available: {', '.join(sorted(DECODERS))}")
    return names


def apply_chain(value: str, chain: list[str]) -> str:
    """Apply each decoder in order. Empty chain = identity."""
    for name in chain:
        value = DECODERS[name](value)
    return value


# ---------------------------------------------------------------------
# AUTO MODE
# ---------------------------------------------------------------------
# Heuristic to decide whether a decoder's output is "plausibly text"
# vs garbage. Used by `auto` to filter out decoders that obviously
# didn't apply (e.g. running base64-decode on something that wasn't
# base64 produces binary garbage).
def looks_readable(s: str) -> bool:
    """True if the string is mostly printable ASCII / common Unicode."""
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return (printable / len(s)) > 0.8


def auto_decode(value: str) -> dict[str, str]:
    """
    Try every single-step decoder. Return {decoder_name: result} for
    the decoders that didn't raise AND produced readable output.
    """
    results = {}
    for name, fn in DECODERS.items():
        if name == "none":
            continue  # boring
        try:
            decoded = fn(value)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not looks_readable(decoded):
            continue
        if decoded == value:
            continue  # decoder was a no-op (the input wasn't actually encoded)
        results[name] = decoded
    return results


# ---------------------------------------------------------------------
# JWT QUICK-INSPECT
# ---------------------------------------------------------------------
# JWTs are SO common in real apps that decode_tool gets a one-line
# "is this a JWT? if so, here's the payload" shortcut. For full JWT
# analysis, point users at jwt_tool.py.
def try_jwt_inspect(value: str) -> dict | None:
    """If value looks like a JWT, return {'header': ..., 'payload': ...}; else None."""
    parts = value.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        def b64url(s):
            pad = (-len(s)) % 4
            return base64.urlsafe_b64decode(s + "=" * pad)
        header = json.loads(b64url(parts[0]))
        payload = json.loads(b64url(parts[1]))
        if not isinstance(header, dict) or "alg" not in header:
            return None
        return {"header": header, "payload": payload}
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    # Single-encoding subcommands
    for name in DECODERS:
        if name == "none":
            continue
        p = sub.add_parser(name, help=f"Decode as {name}")
        p.add_argument("value")

    p_chain = sub.add_parser("chain", help="Apply a chain of decoders (outermost first)")
    p_chain.add_argument("chain", help="Comma-separated chain, e.g. 'base64,url'")
    p_chain.add_argument("value")

    p_auto = sub.add_parser("auto", help="Try every decoder, show what produces readable text")
    p_auto.add_argument("value")

    args = ap.parse_args()

    if args.cmd in DECODERS:
        try:
            result = DECODERS[args.cmd](args.value)
        except Exception as e:
            sys.exit(f"{tag_err()} decode failed: {e}")
        print(result)
        # If the result looks like a JWT, surface that.
        jwt = try_jwt_inspect(result)
        if jwt:
            print()
            print(cyan("(looks like a JWT - decoded header + payload:)"))
            print(json.dumps(jwt, indent=2))
        return 0

    if args.cmd == "chain":
        chain = parse_decode_chain(args.chain)
        print(f"{tag_info()} decoding via: {' -> '.join(chain) or '(no-op)'}")
        try:
            result = apply_chain(args.value, chain)
        except Exception as e:
            sys.exit(f"{tag_err()} decode failed: {e}")
        print(result)
        return 0

    if args.cmd == "auto":
        # First, check JWT - that's a common case worth surfacing.
        jwt = try_jwt_inspect(args.value)
        if jwt:
            print(f"{tag_ok()} this is a JWT")
            print(json.dumps(jwt, indent=2))
            print()

        results = auto_decode(args.value)
        if not results:
            print(f"{tag_warn()} no single decoder produced readable output. "
                  f"It may already be plaintext, or it's chain-encoded - try "
                  f"`{sys.argv[0]} chain ...`")
            return 0
        print(f"{tag_info()} readable single-step decodings:")
        for name, decoded in results.items():
            print(f"  {bold(name):>14s}: {decoded!r}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
