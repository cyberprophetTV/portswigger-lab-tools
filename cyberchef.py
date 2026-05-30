#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
cyberchef.py - Offline mini-CyberChef in a TUI
=====================================================================

WHAT THIS IS
------------
CyberChef (https://gchq.github.io/CyberChef/) is GCHQ's web-based
"Cyber Swiss Army Knife" - paste data, chain together transformations
("the recipe"), watch the output update. It's the de-facto tool for
quick encoding / hashing / parsing tasks during web pentesting.

This is a TUI reimplementation of the most useful operations,
running 100% offline in Python. Nothing leaves your machine - no
calls to the live CyberChef instance, no telemetry, no upload of
the (potentially sensitive) tokens / cookies / payloads you're
analyzing.

THE TUI FLOW (REDESIGNED FOR LOW FRICTION)
------------------------------------------
  1. Provide input (paste text, load file, or pipe via stdin).
  2. The prompt asks "What next?" and accepts ANY of:
       - An operation name or short alias:
           b64        -> To Base64
           b64d       -> From Base64
           sha256     -> SHA-256
           url / urld -> To/From URL
           hex / hexd -> To/From Hex
           jwt        -> JWT decode
           magic      -> auto-detect what the input is
           ... (see `help` for the full list)
       - A control command:
           magic / edit / undo / reset / save / help / list / quit
       - Type a few letters and TAB or the arrow keys to autocomplete
         the operation name from the catalog.
  3. For ops that need extra args (HMAC key, byte count) we ask once.
  4. The result becomes the NEW current value, pushed onto the
     history stack. Recipe panel updates.
  5. Undo pops the stack (lossless, not a replay).

Compared to the original two-step menu (category -> operation),
this collapses to ONE prompt and TWO keypresses for the common case
(type alias, hit Enter).

OPERATIONS INCLUDED
-------------------
Encoding:  Base64 / URL / Double-URL / Hex / Binary / HTML entities /
           Base32 / ROT13
Hashing:   MD5 / SHA1 / SHA256 / SHA384 / SHA512 / HMAC-SHA256
String:    Reverse / Upper / Lower / Strip / Count
Data:      JSON pretty / JSON minify / Parse URL / Parse query string
Defang:    Defang URL/email (IOC-safe) + Refang
Time:      Unix epoch ↔ ISO 8601 / Now
Misc:      Random hex / UUID v4 / Magic auto-decode

WHY NOT JUST USE THE WEB CYBERCHEF?
-----------------------------------
You can - for non-sensitive data. But during a BSCP exam or a real
engagement you regularly deal with cookies, JWTs, encrypted payloads,
and parameter values you DON'T want to paste into a third-party
website. Local-only computation removes that concern entirely.

The web CyberChef also has 300+ operations; this implementation
covers the 30 most-used. Adding more is a single OPERATIONS-list
entry away.

LAUNCHED FROM lab_tools.py
--------------------------
Pick "CyberChef (offline TUI)" from the main menu, or run directly:
   python3 cyberchef.py
   python3 cyberchef.py --input some-file.txt
   echo "dXNlcj1hZG1pbg==" | python3 cyberchef.py
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import html
import json
import re
import secrets
import sys
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

# ---- TUI deps ----
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    import questionary
except ImportError as e:
    sys.stderr.write(
        "cyberchef.py needs Rich and questionary:\n"
        "  pip install rich questionary\n"
        f"(missing module: {e.name})\n"
    )
    sys.exit(1)


# =====================================================================
# OPERATION DEFINITIONS
# =====================================================================
# Each operation transforms a string -> string. Operations that need
# extra inputs (a key, a count, a salt) declare them in `args` and
# the TUI prompts for them before applying.
#
# A `fn` signature is fn(current_input: str, args: dict) -> str.
# args is always passed (even if empty); op functions can ignore it.

# ---------------------------------------------------------------------
# ENCODING / DECODING
# ---------------------------------------------------------------------
def op_to_base64(s, args):       return base64.b64encode(s.encode()).decode()

def op_from_base64(s, args):
    # Tolerate stripped padding and base64url characters.
    s_clean = s.strip().replace("-", "+").replace("_", "/")
    pad = (-len(s_clean)) % 4
    return base64.b64decode(s_clean + "=" * pad).decode("utf-8", errors="replace")

def op_to_base32(s, args):       return base64.b32encode(s.encode()).decode()
def op_from_base32(s, args):
    s_clean = s.strip().upper()
    pad = (-len(s_clean)) % 8
    return base64.b32decode(s_clean + "=" * pad).decode("utf-8", errors="replace")

def op_to_url(s, args):          return urllib.parse.quote(s, safe="")
def op_from_url(s, args):        return urllib.parse.unquote_plus(s)
def op_to_double_url(s, args):   return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")
def op_from_double_url(s, args): return urllib.parse.unquote_plus(urllib.parse.unquote_plus(s))

def op_to_hex(s, args):          return s.encode().hex(" ", 1)
def op_from_hex(s, args):
    s_clean = re.sub(r"\s+", "", s).replace(":", "")
    if s_clean.lower().startswith("0x"):
        s_clean = s_clean[2:]
    return bytes.fromhex(s_clean).decode("utf-8", errors="replace")

def op_to_binary(s, args):
    # Space-separated 8-bit chunks. Matches CyberChef's default.
    return " ".join(format(b, "08b") for b in s.encode())

def op_from_binary(s, args):
    s_clean = re.sub(r"\s+", "", s)
    if len(s_clean) % 8:
        # Pad with leading zeros so length is a multiple of 8.
        s_clean = s_clean.zfill(((len(s_clean) // 8) + 1) * 8)
    return bytes(int(s_clean[i:i + 8], 2) for i in range(0, len(s_clean), 8)).decode(
        "utf-8", errors="replace")

def op_to_html_entities(s, args): return html.escape(s, quote=True)
def op_from_html_entities(s, args): return html.unescape(s)

def op_rot13(s, args):
    # ROT13 is its own inverse, so we don't need a separate "from".
    return s.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMabcdefghijklmnopqrstuvwxyz"[:13]
        + "abcdefghijklm"   # tidy: "NOPQRSTUVWXYZABCDEFGHIJKLM" lowercased
    ))

# Cleaner ROT13 using the standard codec.
def op_rot13_clean(s, args):
    import codecs
    return codecs.encode(s, "rot_13")


# ---------------------------------------------------------------------
# HASHING
# ---------------------------------------------------------------------
def _hash(algo):
    """Return an op function that hashes input under the named algorithm."""
    def fn(s, args):
        return hashlib.new(algo, s.encode()).hexdigest()
    return fn

def op_hmac_sha256(s, args):
    key = args.get("key", "").encode()
    return hmac.new(key, s.encode(), hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------
# STRING
# ---------------------------------------------------------------------
def op_reverse(s, args):    return s[::-1]
def op_upper(s, args):      return s.upper()
def op_lower(s, args):      return s.lower()
def op_strip(s, args):      return s.strip()
def op_count(s, args):
    # Special: returns a stats summary as text. Lets the user see
    # length / word count without leaving the TUI.
    return (f"chars: {len(s)}\n"
            f"bytes: {len(s.encode())}\n"
            f"words: {len(s.split())}\n"
            f"lines: {len(s.splitlines())}")

def op_sort_lines(s, args):  return "\n".join(sorted(s.splitlines()))
def op_unique_lines(s, args):
    seen, out = set(), []
    for line in s.splitlines():
        if line not in seen:
            seen.add(line)
            out.append(line)
    return "\n".join(out)


# ---------------------------------------------------------------------
# DATA FORMAT
# ---------------------------------------------------------------------
def op_json_pretty(s, args):
    return json.dumps(json.loads(s), indent=2, sort_keys=False)

def op_json_minify(s, args):
    return json.dumps(json.loads(s), separators=(",", ":"))

def op_parse_url(s, args):
    """Split a URL into its components - readable form."""
    p = urllib.parse.urlparse(s)
    parts = {
        "scheme": p.scheme,
        "netloc": p.netloc,
        "username": p.username,
        "password": p.password,
        "hostname": p.hostname,
        "port": p.port,
        "path": p.path,
        "query": p.query,
        "params": dict(urllib.parse.parse_qsl(p.query, keep_blank_values=True)),
        "fragment": p.fragment,
    }
    return json.dumps(parts, indent=2, default=str)

def op_parse_query_string(s, args):
    return json.dumps(dict(urllib.parse.parse_qsl(s.lstrip("?"), keep_blank_values=True)),
                       indent=2)


# ---------------------------------------------------------------------
# DEFANG (for safely sharing URLs / IOCs in tickets, reports, emails)
# ---------------------------------------------------------------------
def op_defang_url(s, args):
    """https://evil.com → hxxps[:]//evil[.]com   (won't auto-link in tools)"""
    s = re.sub(r"https?://", lambda m: m.group(0).replace("t", "x").replace(":", "[:]"), s)
    s = s.replace(".", "[.]")
    return s

def op_refang_url(s, args):
    s = s.replace("hxxps", "https").replace("hxxp", "http")
    s = s.replace("[:]", ":").replace("[.]", ".")
    return s

def op_defang_email(s, args):
    return s.replace("@", "[at]").replace(".", "[.]")

def op_refang_email(s, args):
    return s.replace("[at]", "@").replace("[.]", ".")


# ---------------------------------------------------------------------
# TIME
# ---------------------------------------------------------------------
def op_epoch_to_iso(s, args):
    """Unix epoch (seconds OR milliseconds) -> ISO 8601 UTC."""
    val = float(s.strip())
    # Heuristic: > 1e12 looks like milliseconds.
    if val > 1e12:
        val /= 1000.0
    return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()

def op_iso_to_epoch(s, args):
    """ISO 8601 -> Unix epoch seconds."""
    # Accept "Z" suffix (Python's fromisoformat is finicky pre-3.11
    # but on 3.10+ it handles +00:00 - normalize "Z" to that).
    iso = s.strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(iso)
    return str(int(dt.timestamp()))

def op_now(s, args):
    """Current UTC time - ignores input."""
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------
# MISC
# ---------------------------------------------------------------------
def op_random_hex(s, args):
    """Generate N random bytes as hex. N from args, default 16."""
    n = int(args.get("bytes", "16"))
    return secrets.token_hex(n)

def op_uuid_v4(s, args):
    """Generate a random UUIDv4. Ignores input."""
    return str(uuid.uuid4())

def op_word_to_jwt_summary(s, args):
    """If the input looks like a JWT, decode + summarize. Else error."""
    parts = s.strip().split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT: expected 3 dot-separated parts")
    def b64u(x):
        pad = (-len(x)) % 4
        return base64.urlsafe_b64decode(x + "=" * pad)
    header = json.loads(b64u(parts[0]))
    payload = json.loads(b64u(parts[1]))
    return json.dumps({"header": header, "payload": payload,
                        "signature_b64": parts[2]}, indent=2)


# ---------------------------------------------------------------------
# OPERATION REGISTRY
# ---------------------------------------------------------------------
@dataclass
class Operation:
    name: str
    category: str
    fn: Callable
    description: str
    # args: list of {name, prompt, default} dicts. Empty for pure ops.
    args: list[dict] = field(default_factory=list)


OPERATIONS: list[Operation] = [
    # Encoding
    Operation("To Base64",         "Encoding", op_to_base64,        "Encode UTF-8 text as standard base64"),
    Operation("From Base64",       "Encoding", op_from_base64,      "Decode base64 (tolerates missing padding + base64url chars)"),
    Operation("To Base32",         "Encoding", op_to_base32,        "Encode as base32"),
    Operation("From Base32",       "Encoding", op_from_base32,      "Decode base32"),
    Operation("To URL",            "Encoding", op_to_url,           "Percent-encode every reserved char (safe='')"),
    Operation("From URL",          "Encoding", op_from_url,         "URL-decode (+ becomes space)"),
    Operation("To URL (double)",   "Encoding", op_to_double_url,    "Apply URL encoding twice"),
    Operation("From URL (double)", "Encoding", op_from_double_url,  "Reverse double-URL encoding"),
    Operation("To Hex",            "Encoding", op_to_hex,           "Hex bytes, space-separated (matches CyberChef default)"),
    Operation("From Hex",          "Encoding", op_from_hex,         "Decode hex (tolerates whitespace, ':' separators, 0x prefix)"),
    Operation("To Binary",         "Encoding", op_to_binary,        "Each byte as 8 bits, space-separated"),
    Operation("From Binary",       "Encoding", op_from_binary,      "Decode space- or contiguously-formatted binary string"),
    Operation("To HTML entities",  "Encoding", op_to_html_entities, "Escape <, >, &, \", ' to HTML entities"),
    Operation("From HTML entities","Encoding", op_from_html_entities, "Unescape HTML entities (named + numeric)"),
    Operation("ROT13",             "Encoding", op_rot13_clean,      "Caesar cipher, shift 13 (self-inverse)"),

    # Hashing
    Operation("MD5",               "Hashing",  _hash("md5"),        "MD5 hex digest - obsolete, but you'll see it"),
    Operation("SHA-1",             "Hashing",  _hash("sha1"),       "SHA-1 hex digest"),
    Operation("SHA-256",           "Hashing",  _hash("sha256"),     "SHA-256 hex digest"),
    Operation("SHA-384",           "Hashing",  _hash("sha384"),     "SHA-384 hex digest"),
    Operation("SHA-512",           "Hashing",  _hash("sha512"),     "SHA-512 hex digest"),
    Operation("HMAC-SHA256",       "Hashing",  op_hmac_sha256,      "HMAC-SHA256 with a secret key",
              args=[{"name": "key", "prompt": "Secret key", "default": ""}]),

    # String
    Operation("Reverse",           "String",   op_reverse,          "Reverse the string character-by-character"),
    Operation("Upper case",        "String",   op_upper,            "Convert to UPPER CASE"),
    Operation("Lower case",        "String",   op_lower,            "Convert to lower case"),
    Operation("Strip whitespace",  "String",   op_strip,            "Trim leading + trailing whitespace"),
    Operation("Count (chars/lines/words)", "String", op_count,      "Report sizes - doesn't modify input"),
    Operation("Sort lines",        "String",   op_sort_lines,       "Sort lines alphabetically"),
    Operation("Unique lines",      "String",   op_unique_lines,     "Dedupe lines, preserving order"),

    # Data format
    Operation("JSON pretty-print", "Data",     op_json_pretty,      "Parse JSON, re-emit with indent=2"),
    Operation("JSON minify",       "Data",     op_json_minify,      "Parse JSON, re-emit with no whitespace"),
    Operation("Parse URL",         "Data",     op_parse_url,        "Split a URL into scheme/host/path/query/etc."),
    Operation("Parse query string","Data",     op_parse_query_string, "Parse k1=v1&k2=v2 into a dict (URL-decoded)"),

    # Defang / refang (IOC-safe sharing)
    Operation("Defang URL",        "Defang",   op_defang_url,       "https://evil.com → hxxps[:]//evil[.]com"),
    Operation("Refang URL",        "Defang",   op_refang_url,       "Reverse defanging"),
    Operation("Defang email",      "Defang",   op_defang_email,     "user@domain.com → user[at]domain[.]com"),
    Operation("Refang email",      "Defang",   op_refang_email,     "Reverse email defanging"),

    # Time
    Operation("Unix epoch → ISO 8601", "Time", op_epoch_to_iso,     "Convert epoch seconds (or ms) to UTC ISO timestamp"),
    Operation("ISO 8601 → Unix epoch", "Time", op_iso_to_epoch,     "Parse ISO 8601 to epoch seconds"),
    Operation("Now (current UTC)",     "Time", op_now,              "Replace input with the current UTC time - ignores input"),

    # Misc
    Operation("Random hex bytes",  "Misc",     op_random_hex,       "Generate N random bytes, hex-encoded",
              args=[{"name": "bytes", "prompt": "How many bytes", "default": "16"}]),
    Operation("UUID v4",           "Misc",     op_uuid_v4,          "Generate a random UUID - ignores input"),
    Operation("JWT decode",        "Misc",     op_word_to_jwt_summary, "If input is a JWT, decode header + payload"),
]


# =====================================================================
# SHORT ALIASES
# =====================================================================
# Map quick-to-type shortcuts to full operation names. Saves the user
# from typing "To Base64" when they really meant b64. Built once at
# module load - we use it for autocomplete + lookup.
ALIASES: dict[str, str] = {
    # Encoding (e=encode, d=decode)
    "b64":     "To Base64",       "b64e":   "To Base64",
    "b64d":    "From Base64",
    "b32":     "To Base32",       "b32d":   "From Base32",
    "url":     "To URL",          "urle":   "To URL",
    "urld":    "From URL",
    "url2":    "To URL (double)", "url2d":  "From URL (double)",
    "hex":     "To Hex",          "hexd":   "From Hex",
    "bin":     "To Binary",       "bind":   "From Binary",
    "html":    "To HTML entities","htmld":  "From HTML entities",
    "rot":     "ROT13",           "rot13":  "ROT13",
    # Hashing
    "md5":     "MD5",
    "sha1":    "SHA-1",
    "sha256":  "SHA-256",         "sha":    "SHA-256",
    "sha384":  "SHA-384",
    "sha512":  "SHA-512",
    "hmac":    "HMAC-SHA256",
    # String
    "rev":     "Reverse",
    "upper":   "Upper case",      "up":     "Upper case",
    "lower":   "Lower case",      "lo":     "Lower case",
    "strip":   "Strip whitespace","trim":   "Strip whitespace",
    "count":   "Count (chars/lines/words)",
    "sort":    "Sort lines",
    "uniq":    "Unique lines",    "dedupe": "Unique lines",
    # Data
    "json":    "JSON pretty-print",
    "minify":  "JSON minify",     "jsonmin": "JSON minify",
    "purl":    "Parse URL",       "parseurl": "Parse URL",
    "pqs":     "Parse query string",
    # Defang
    "defang":  "Defang URL",      "defangu":   "Defang URL",
    "refang":  "Refang URL",      "refangu":   "Refang URL",
    "defange": "Defang email",
    "refange": "Refang email",
    # Time
    "epoch":   "Unix epoch → ISO 8601",
    "iso":     "ISO 8601 → Unix epoch",
    "now":     "Now (current UTC)",
    # Misc
    "rand":    "Random hex bytes","randhex": "Random hex bytes",
    "uuid":    "UUID v4",
    "jwt":     "JWT decode",      "jwtd":   "JWT decode",
}


def resolve_op_name(typed: str) -> Operation | None:
    """Look up an operation by alias OR full name. Case-insensitive."""
    typed = typed.strip()
    if not typed:
        return None
    # Alias lookup is case-insensitive
    target = ALIASES.get(typed.lower(), typed)
    for op in OPERATIONS:
        if op.name.lower() == target.lower():
            return op
    return None


# =====================================================================
# FORMAT IDENTIFICATION (the "this looks like X" detector)
# =====================================================================
# When the user asks "what is this thing?" we run the input through a
# bank of pattern detectors. Each returns a (label, suggestion) hint
# if it matches. Hints tell the user:
#   1. WHAT the data appears to be (MD5, JWT, IPv4, cookie format, etc.)
#   2. WHAT they should probably do next (crack it, decode it, tamper it)
#
# These are heuristic - same string can match multiple detectors
# ("32 hex chars" is BOTH a valid MD5 hash AND valid hex-encoded
# bytes). We just return everything that matches and let the user
# decide which interpretation is right for their context.

@dataclass
class FormatHint:
    label: str          # short identifier ("MD5 hash", "JWT", ...)
    suggestion: str = ""  # what to do next, optional


def identify_format(text: str) -> list[FormatHint]:
    """Return zero or more FormatHints describing what `text` looks like."""
    hints: list[FormatHint] = []
    s = text.strip()
    if not s:
        return hints

    # ---- HTTP auth header prefix stripping ----
    # If the user pastes a full `Bearer eyJ...` or `Basic YWRtaW4=`
    # auth-header value, recognize the prefix AND recurse on the
    # actual token so the user gets BOTH "this is a Bearer token" AND
    # "the inner token looks like a JWT" hints.
    for prefix, kind in (("Bearer ",  "HTTP Bearer (often JWT or opaque OAuth token)"),
                          ("bearer ",  "HTTP Bearer (often JWT or opaque OAuth token)"),
                          ("Basic ",   "HTTP Basic (base64 of user:pass)"),
                          ("Token ",   "HTTP Token (custom auth header value)"),
                          ("token ",   "HTTP Token (custom auth header value)")):
        if s.startswith(prefix):
            hints.append(FormatHint(
                f"HTTP Authorization header value ({kind.split('(', 1)[0].strip()})",
                f"prefix is `{prefix.strip()}`. The remaining part is the actual "
                f"credential - identifying it below."))
            # Recurse on the token portion so the user gets the inner
            # interpretation (JWT, base64, opaque).
            inner_hints = identify_format(s[len(prefix):])
            for h in inner_hints:
                # Tag inner hints so they're distinguishable from outer.
                hints.append(FormatHint(f"(inner credential) {h.label}",
                                          h.suggestion))
            return hints

    # ---- Modern password-hash formats (structured, very distinctive) ----
    # Bcrypt: $2a$ / $2b$ / $2x$ / $2y$  $cost$  22-char salt + 31-char hash
    if re.fullmatch(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}", s):
        hints.append(FormatHint(
            "Bcrypt password hash",
            "VERY slow to crack - hashcat -m 3200, only worth a tiny targeted wordlist"))
    # crypt(3) family: $1$ MD5, $5$ SHA-256, $6$ SHA-512, $y$ yescrypt
    if re.match(r"\$(1|5|6|y|sha1)\$", s):
        algo_map = {"1": "MD5-crypt", "5": "SHA256-crypt", "6": "SHA512-crypt",
                     "y": "yescrypt", "sha1": "SHA1-crypt"}
        algo_id = s.split("$")[1]
        hints.append(FormatHint(
            f"crypt(3) hash ({algo_map.get(algo_id, 'unknown')}, /etc/shadow format)",
            "format is $algo$rounds$salt$hash - hashcat -m 500/7400/1800/29800"))
    # Argon2 (modern)
    if s.startswith("$argon2"):
        hints.append(FormatHint(
            "Argon2 password hash",
            "memory-hard - virtually uncrackable without leaked passwords / context"))

    # ---- Cryptographic hashes (length-based) ----
    # These run BEFORE the generic "hex bytes" detector below so we
    # surface the more-specific hash interpretation first.
    if re.fullmatch(r"[a-fA-F0-9]{32}", s):
        hints.append(FormatHint(
            "MD5 hash (32 hex chars)",
            "try cracking against a wordlist (hashcat / john / jwt_tool brute for HMAC)"))
    if re.fullmatch(r"[a-fA-F0-9]{40}", s):
        hints.append(FormatHint(
            "SHA-1 hash (40 hex chars)",
            "obsolete but still common - try cracking against a wordlist"))
    if re.fullmatch(r"[a-fA-F0-9]{64}", s):
        hints.append(FormatHint(
            "SHA-256 hash (64 hex chars)",
            "modern standard - cracking only works for short / known-pattern inputs"))
    if re.fullmatch(r"[a-fA-F0-9]{96}", s):
        hints.append(FormatHint(
            "SHA-384 hash (96 hex chars)",
            "less common than SHA-256/512 - same cracking difficulty as SHA-256"))
    if re.fullmatch(r"[a-fA-F0-9]{128}", s):
        hints.append(FormatHint(
            "SHA-512 hash (128 hex chars)",
            "expensive to crack - try a small targeted wordlist only"))

    # ---- JWT (3 base64url parts WITH valid JSON header containing alg) ----
    # Shape alone is ambiguous: Discord bot tokens have the same 3-parts-
    # dot-separated structure. To avoid false positives we ALSO verify
    # the first part is base64url-decodable JSON with an `alg` field
    # (the universal JWT header marker).
    parts = s.split(".")
    if len(parts) == 3 and all(parts) and all(
            re.fullmatch(r"[A-Za-z0-9_-]+", p) for p in parts):
        try:
            pad = (-len(parts[0])) % 4
            header_dict = json.loads(
                base64.urlsafe_b64decode(parts[0] + "=" * pad))
            if isinstance(header_dict, dict) and "alg" in header_dict:
                hints.append(FormatHint(
                    "JWT (3 base64url-encoded parts)",
                    "use `jwt` here, OR run jwt_tool.py for full attacks "
                    "(none-alg, HS256 brute, kid injection)"))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass

    # ---- UUID v4 (and v1-v5 fallback) ----
    if re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}"
            r"-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}", s):
        hints.append(FormatHint(
            "UUID v4 (random)",
            "session id - usually unguessable, but check for predictability"))
    elif re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
            r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", s):
        hints.append(FormatHint(
            "UUID (v1/v3/v5 variant)",
            "v1 leaks the MAC + timestamp of issuance - extract via uuid lib"))

    # ---- IPv4 ----
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)", s)
    if m and all(0 <= int(o) <= 255 for o in m.groups()):
        hints.append(FormatHint(
            "IPv4 address",
            "candidate for SSRF target, X-Forwarded-For spoof, IP-based ACL bypass"))

    # ---- IPv4 CIDR range ----
    m = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)\.(\d+)/(\d+)", s)
    if m and all(0 <= int(o) <= 255 for o in m.groups()[:4]) \
           and 0 <= int(m.group(5)) <= 32:
        hints.append(FormatHint(
            "IPv4 CIDR range (network block)",
            "useful for scope definition / sweeping a subnet"))

    # ---- IPv6 (compressed or full) ----
    # Stricter than just "hex+colons" - require EITHER the '::'
    # compression marker OR exactly 7 colons (full 8-group form).
    # This excludes MAC addresses (5 colons, 6 chunks) which would
    # otherwise match the looser pattern.
    if (re.fullmatch(r"[0-9a-fA-F:]+", s)
            and all(len(chunk) <= 4 for chunk in s.split(":"))
            and ("::" in s or s.count(":") == 7)
            and s.count(":") >= 2):
        hints.append(FormatHint(
            "IPv6 address",
            "many filters miss IPv6 - test for SSRF / parser bypass via ::1, ::ffff:..."))

    # ---- MAC address ----
    if re.fullmatch(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", s):
        hints.append(FormatHint(
            "MAC address",
            "first 3 bytes are vendor OUI - lookup to identify the hardware. "
            "UUID v1 contains a MAC too."))

    # ---- Unix epoch ----
    # 10 digits: seconds since 1970. Plausible range: 2001-2286.
    if re.fullmatch(r"\d{10}", s) and 1_000_000_000 <= int(s) <= 9_999_999_999:
        hints.append(FormatHint(
            "Unix epoch seconds",
            "use `epoch` to convert to ISO date - tokens / cookies often embed iat/exp"))
    # 13 digits: milliseconds (JavaScript Date.now() default).
    if re.fullmatch(r"\d{13}", s):
        hints.append(FormatHint(
            "Unix epoch milliseconds",
            "use `epoch` to convert (auto-detects ms when value > 1e12)"))

    # ---- ISO 8601 timestamp ----
    if re.match(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", s):
        hints.append(FormatHint(
            "ISO 8601 timestamp",
            "use `iso` to convert to unix epoch"))

    # ---- Email ----
    if re.fullmatch(r"[\w.+-]+@[\w.-]+\.\w+", s):
        hints.append(FormatHint(
            "Email address",
            "candidate for username-enumeration probes / 'forgot password' flows"))

    # ---- URL ----
    if re.match(r"https?://", s):
        hints.append(FormatHint(
            "URL",
            "use `purl` to split into scheme/host/path/query, or `defang` "
            "for safe sharing in reports"))

    # ---- JSON ----
    if (s.startswith("{") and s.endswith("}")) or \
       (s.startswith("[") and s.endswith("]")):
        try:
            json.loads(s)
            hints.append(FormatHint(
                "JSON",
                "use `json` to pretty-print, `minify` to compact"))
        except (json.JSONDecodeError, ValueError):
            pass

    # ---- XML / HTML ----
    if re.match(r"<\?xml|<!DOCTYPE|<html", s, re.IGNORECASE):
        hints.append(FormatHint(
            "HTML / XML document",
            "inspect for forms, hidden inputs, CSP meta tags, comments"))

    # ---- Cookie-shape detection ----
    # username:MD5(password) is the classic 'stay-logged-in' lab format.
    if re.fullmatch(r"[\w.+-]+:[a-fA-F0-9]{32}", s):
        hints.append(FormatHint(
            "Looks like `username:MD5(password)` session cookie",
            "tamper: change username + re-MD5 a guessed password + re-encode (b64)"))
    if re.fullmatch(r"[\w.+-]+:[a-fA-F0-9]{40}", s):
        hints.append(FormatHint(
            "Looks like `username:SHA1(password)` session cookie",
            "tamper: change username + re-SHA1 a guessed password + re-encode"))
    if re.fullmatch(r"[\w.+-]+\|[\w.+:%-]+", s):
        hints.append(FormatHint(
            "Looks like pipe-separated cookie (`name|value`)",
            "common cookie format - inspect each part for tampering opportunities"))

    # ---- URL query string ----
    if "=" in s and "&" in s and not s.startswith("http"):
        # Don't make the user type `pqs` - just parse it inline and
        # show the pairs as part of the hint. Falls back to the
        # "use pqs" suggestion only if nothing parsed.
        parsed = urllib.parse.parse_qsl(s.lstrip("?"), keep_blank_values=True)
        if parsed:
            preview = "  ".join(f"{k}={v}" for k, v in parsed[:6])
            if len(parsed) > 6:
                preview += f"   (+{len(parsed) - 6} more)"
            hints.append(FormatHint(
                f"URL query string ({len(parsed)} pairs)",
                preview))
        else:
            hints.append(FormatHint(
                "Looks like URL query string",
                "use `pqs` to parse into key/value pairs"))

    # ---- MongoDB ObjectId (24 hex chars - not the same as MD5 / SHA-1) ----
    if re.fullmatch(r"[a-fA-F0-9]{24}", s):
        hints.append(FormatHint(
            "MongoDB ObjectId (12 bytes)",
            "first 4 bytes = timestamp (decode as hex epoch), next 5 = machine+pid, "
            "last 3 = counter. Sequential IDs leak when records were created."))

    # ---- Vendor-specific API keys / tokens (high-confidence prefixes) ----
    if re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{16}", s):
        kind = "permanent" if s.startswith("AKIA") else "temporary (STS)"
        hints.append(FormatHint(
            f"AWS access key ID ({kind})",
            "CRITICAL if exposed. Pair with a 40-char secret = full AWS access. "
            "Don't actually use it; report immediately."))
    if re.fullmatch(r"gh[pousr]_[A-Za-z0-9]{36,}", s):
        kind = {"p": "Personal Access Token", "o": "OAuth", "u": "User-to-server",
                "s": "Server-to-server", "r": "Refresh"}.get(s[2], "")
        hints.append(FormatHint(
            f"GitHub token ({kind})",
            "CRITICAL if exposed - revoke at github.com/settings/tokens. "
            "Test scope with `gh api user`."))
    if re.fullmatch(r"(sk|pk|rk)_(test|live)_[A-Za-z0-9]{20,}", s):
        kind = "SECRET" if s.startswith("sk_") else (
               "publishable (intended public)" if s.startswith("pk_") else "restricted")
        env = "TEST sandbox" if "_test_" in s else "LIVE production"
        hints.append(FormatHint(
            f"Stripe API key ({kind}, {env})",
            "sk_live_ exposed = real money on the line - report immediately"))
    if re.match(r"xox[abprs]-\d+-\d+-", s):
        kind_map = {"b": "Bot", "p": "User", "a": "OAuth-app", "r": "Refresh", "s": "Server"}
        kind = kind_map.get(s[3], "unknown")
        hints.append(FormatHint(
            f"Slack token ({kind})",
            "CRITICAL if exposed - try `https://slack.com/api/auth.test` to validate"))
    if re.fullmatch(r"glpat-[A-Za-z0-9_-]{20}", s):
        hints.append(FormatHint(
            "GitLab personal access token",
            "CRITICAL if exposed - revoke at GitLab user settings"))
    # OpenAI: sk-..., sk-proj-..., sk-svcacct-...
    # Negative lookahead for `ant-` so we don't also match sk-ant-X
    # which is Anthropic (handled below).
    if re.match(r"sk-(?!ant-)(proj-|svcacct-)?[A-Za-z0-9_-]{20,}$", s):
        kind = ("project key" if s.startswith("sk-proj-") else
                "service account" if s.startswith("sk-svcacct-") else
                "user / org key")
        hints.append(FormatHint(
            f"OpenAI API key ({kind})",
            "CRITICAL if exposed - revoke at platform.openai.com/api-keys. "
            "Bills per-token usage; leaked key = immediate financial damage."))
    # Anthropic: sk-ant-... (api / admin keys both share this prefix)
    if re.match(r"sk-ant-[A-Za-z0-9_-]{50,}$", s):
        hints.append(FormatHint(
            "Anthropic API key",
            "CRITICAL if exposed - revoke at console.anthropic.com. "
            "Same financial-damage profile as OpenAI."))
    # Google service account file - the JSON has telltale fields. We
    # check string-prefix because it's the most distinctive part.
    if '"type": "service_account"' in s or '"type":"service_account"' in s:
        hints.append(FormatHint(
            "Google Cloud service-account JSON key",
            "CRITICAL if exposed - revoke at console.cloud.google.com/iam-admin/"
            "serviceaccounts. Contains a private_key field that grants the "
            "whole service account's permissions."))
    # Google API key (not OAuth) - AIza prefix is distinctive
    if re.fullmatch(r"AIza[A-Za-z0-9_-]{35}", s):
        hints.append(FormatHint(
            "Google API key (AIza prefix)",
            "Often public-by-design (Maps/embed keys), but check if scoped to "
            "billing-enabled APIs. Restrict by HTTP referrer / IP / SDK."))
    # Twilio
    if re.fullmatch(r"SK[a-fA-F0-9]{32}", s):
        hints.append(FormatHint(
            "Twilio API key SID (SK...)",
            "Pairs with a separate secret. Used to send SMS/WhatsApp."))
    if re.fullmatch(r"AC[a-fA-F0-9]{32}", s):
        hints.append(FormatHint(
            "Twilio Account SID (AC...)",
            "Account ID - not secret by itself, but reveals the account."))
    # SendGrid: SG.<22 chars>.<43 chars>
    if re.fullmatch(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", s):
        hints.append(FormatHint(
            "SendGrid API key",
            "Lets the bearer send email as the account - phishing risk."))
    # Mailgun
    if re.fullmatch(r"key-[a-f0-9]{32}", s):
        hints.append(FormatHint(
            "Mailgun API key (legacy format)",
            "Lets the bearer send email as the account."))
    # npm tokens
    if re.fullmatch(r"npm_[A-Za-z0-9]{36}", s):
        hints.append(FormatHint(
            "npm access token",
            "CRITICAL if has 'publish' scope - supply-chain attack vector. "
            "Revoke at npmjs.com -> Access Tokens."))
    # Docker Hub PAT
    if re.fullmatch(r"dckr_pat_[A-Za-z0-9_-]{27,}", s):
        hints.append(FormatHint(
            "Docker Hub personal access token",
            "Lets the bearer push images = supply-chain attack."))
    # Discord bot token - 3 base64url-ish parts separated by dots,
    # but DIFFERENT shape than JWT (specific length pattern).
    if re.fullmatch(r"[MN][A-Za-z0-9_-]{23}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,}", s):
        hints.append(FormatHint(
            "Discord bot token",
            "Lets the bearer control the bot account fully. "
            "Revoke at discord.com/developers/applications/<app>/bot."))
    # Heroku API key - looks like a UUID. Handled by UUID detector
    # already (we noted UUID v4 above); no extra hint needed.

    # ---- Private keys / certificates (PEM-armored) ----
    if "-----BEGIN " in s and "PRIVATE KEY-----" in s:
        algo = "RSA" if "RSA PRIVATE KEY" in s else (
               "EC" if "EC PRIVATE KEY" in s else (
               "OpenSSH" if "OPENSSH PRIVATE KEY" in s else
               "generic PKCS#8"))
        hints.append(FormatHint(
            f"PEM-armored {algo} private key",
            "CRITICAL - the private half of an asymmetric keypair. "
            "Whatever uses the public key trusts the holder of this."))
    if "-----BEGIN CERTIFICATE-----" in s:
        hints.append(FormatHint(
            "PEM X.509 certificate",
            "Public - the cert itself isn't sensitive, but if paired with a "
            "private key in the same file or directory, that IS."))
    if "-----BEGIN PGP " in s and "PRIVATE KEY" in s.upper():
        hints.append(FormatHint(
            "PGP private key block",
            "CRITICAL - decrypts messages encrypted to the corresponding public key."))

    # ---- Attack-payload signals (the user pasted a payload to see if it looks right) ----
    if re.search(r"\.\.[/\\]", s) or "%2e%2e" in s.lower() or "..%2f" in s.lower():
        hints.append(FormatHint(
            "Path traversal payload (../ or %2e%2e variant)",
            "test against file-reading endpoints: file=, page=, include=, view=, etc."))
    # `--` SQL comment: tightened with a negative lookbehind so PEM
    # delimiters like `-----` don't trip it. Also accept the `-- `
    # (dash-dash-space) variant which is the SQL standard.
    if re.search(r"(\bUNION\s+SELECT\b|\bOR\s+\d+\s*=\s*\d+|(?<!-)--\s+|(?<!-)--$|"
                 r"/\*[^*]*\*/|;\s*DROP\b|"
                 r"information_schema|SLEEP\s*\(|BENCHMARK\s*\()", s, re.IGNORECASE):
        hints.append(FormatHint(
            "SQL injection payload",
            "test against any DB-bound input. SLEEP() variant = time-based blind "
            "(use intruder --baseline-samples + --match-time-delta)"))
    if re.search(r"<script\b|<img[^>]+\bonerror\b|javascript:|on(load|click|error|focus)\s*=",
                  s, re.IGNORECASE):
        hints.append(FormatHint(
            "XSS payload",
            "test in any input that gets reflected back into HTML. "
            "Use intruder --detect-reflection to find the reflection points first"))
    if re.search(r"\{\{[^}]+\}\}|\$\{[^}]+\}|<%[^%]+%>|#\{[^}]+\}", s):
        hints.append(FormatHint(
            "Template injection probe ({{ }}, ${}, <% %>, #{})",
            "if the server renders this and the output reflects, you have RCE. "
            "Test against Jinja2 / ERB / Velocity / Freemarker / Thymeleaf"))
    if re.search(r"(jndi|ldap):/?/", s, re.IGNORECASE):
        hints.append(FormatHint(
            "JNDI / LDAP injection probe (think log4shell)",
            "test against any logged input. Pair with --oob-host to catch outbound calls"))

    # ---- Possible HTTP Basic auth value: base64 of user:pass ----
    # Only flag when the base64-decoded result has a single ':' and is
    # printable - avoids false-positives on every random base64 blob.
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", s) and len(s) >= 8 and len(s) % 4 == 0:
        try:
            decoded = base64.b64decode(s).decode("utf-8")
            if decoded.count(":") == 1 and all(c.isprintable() for c in decoded):
                hints.append(FormatHint(
                    "Possibly HTTP Basic auth value (base64 of user:pass)",
                    "decode with b64d to see the credentials directly"))
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    # ---- Structured-data shapes the BSCP exam throws at you ----

    # PHP serialized data: a:N:{...}, s:N:"...", O:N:"ClassName":...
    # Format starts with one of [aOdbiNsr]:NUMBER:... Crucial for
    # deserialization labs - feed to phpggc.
    if re.match(r"^(a|s|i|d|b|O|N|r):\d+:", s) and ";" in s:
        hints.append(FormatHint(
            "PHP serialized data (unserialize() input)",
            "deserialization sink - generate a gadget chain with phpggc "
            "(`phpggc Laravel/RCE5 system id -b`)"))

    # HTTP request first line: "METHOD /path HTTP/x.y"
    if re.match(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE|CONNECT)\s+\S+\s+HTTP/[\d.]+\s*$",
                 s, re.IGNORECASE):
        hints.append(FormatHint(
            "HTTP request line (method + path + version)",
            "this is the first line of a raw request - save the whole request "
            "to a file + feed to intruder.py / sqlmap -r"))

    # HTTP response status line: "HTTP/x.y NNN REASON"
    if re.match(r"^HTTP/[\d.]+\s+\d{3}\b", s):
        hints.append(FormatHint(
            "HTTP response status line",
            "first line of a raw response - the rest tells you headers + body"))

    # Set-Cookie response header (full form with attributes).
    if re.search(r"=.+?;\s*(Path|Domain|Expires|Max-Age|HttpOnly|Secure|SameSite)",
                  s, re.IGNORECASE):
        missing = []
        if not re.search(r"\bHttpOnly\b", s, re.IGNORECASE):
            missing.append("HttpOnly")
        if not re.search(r"\bSecure\b", s, re.IGNORECASE):
            missing.append("Secure")
        if not re.search(r"\bSameSite=", s, re.IGNORECASE):
            missing.append("SameSite")
        suggestion = ("inspect for tampering opportunities" if not missing
                       else f"missing security flags: {', '.join(missing)} "
                            "- chained-attack enabler (XSS reads cookie, CSRF, etc.)")
        hints.append(FormatHint("Set-Cookie header value", suggestion))

    # Cookie header form: "k=v; k=v; k=v" (multiple cookies in one string).
    # Distinct from Set-Cookie because no attribute keywords appear.
    if (s.count("=") >= 2 and "; " in s and ";" in s
            and not re.search(r"\b(Path|Domain|HttpOnly|Secure|SameSite)\b", s, re.IGNORECASE)
            and all(re.match(r"\s*[\w._-]+=", part) for part in s.split(";") if part.strip())):
        hints.append(FormatHint(
            "Cookie header value (k=v; k=v; ...)",
            "list of cookies sent by client - inspect each value for "
            "tampering / format identification"))

    # GraphQL query / mutation / subscription
    if re.search(r"\b(query|mutation|subscription|fragment)\b\s*\w*\s*[({]", s):
        hints.append(FormatHint(
            "GraphQL operation",
            "test for introspection: POST {\"query\":\"{__schema{types{name}}}\"} "
            "- if accepted, the whole API surface is yours"))
    # Plain GraphQL body (just braces with field names)
    if re.match(r"^\s*\{\s*\w+", s) and s.rstrip().endswith("}") and ":" not in s.split("\n", 1)[0]:
        if not any("GraphQL" in h.label for h in hints):
            hints.append(FormatHint(
                "Possibly a GraphQL query body",
                "look for field selectors like `{ user(id:1) { name email } }`"))

    # JWK (JSON Web Key)
    if (s.strip().startswith("{") and
            ('"kty"' in s or '"kid"' in s or '"alg"' in s) and
            any(k in s for k in ('"e"', '"n"', '"k"', '"x"', '"y"'))):
        hints.append(FormatHint(
            "JWK (JSON Web Key) - public key in JSON form",
            "if this is the verification key for a JWT, use it for algorithm "
            "confusion attack (RS256 -> HS256 with the key bytes as HMAC secret)"))

    # YAML document (heuristic: multi-line with `key: value` pattern AND
    # NOT a JSON object).
    if (("\n" in s) and
            not s.strip().startswith(("{", "[")) and
            re.search(r"^[\w-]+:\s*\S", s, re.MULTILINE)):
        hints.append(FormatHint(
            "YAML document",
            "common in config files / K8s manifests / OpenAPI specs - "
            "grep for `password`, `secret`, `token`, `key`"))

    # XML / SOAP envelope
    if re.match(r"^\s*<\?xml\s", s) or re.search(r"<soap(?:env)?:Envelope", s, re.IGNORECASE):
        hints.append(FormatHint(
            "XML / SOAP envelope",
            "candidate for XXE injection - inject <!DOCTYPE+ENTITY into the XML "
            "if the server parses it"))

    # IPv6 CIDR
    if re.fullmatch(r"[0-9a-fA-F:]+/\d+", s) and ":" in s.split("/")[0]:
        prefix = s.split("/")[0]
        if all(len(chunk) <= 4 for chunk in prefix.split(":")):
            try:
                bits = int(s.split("/")[1])
                if 0 <= bits <= 128:
                    hints.append(FormatHint(
                        "IPv6 CIDR range",
                        "network block - useful for scope definition"))
            except ValueError:
                pass

    # Host:port form (hostname:NNN).
    m = re.fullmatch(r"([a-zA-Z0-9.-]+):(\d{1,5})", s)
    if m and 1 <= int(m.group(2)) <= 65535 and "." in m.group(1):
        hints.append(FormatHint(
            f"host:port  ({m.group(1)}:{m.group(2)})",
            "SSRF target candidate - especially useful for internal hostnames "
            "(metadata, internal-api, etc.)"))

    # Pure numeric ID - small heuristic for "looks like a database key"
    if re.fullmatch(r"\d{1,12}", s) and not re.fullmatch(r"\d{10}|\d{13}", s):
        # Exclude epoch-shaped (already handled above as Unix epoch).
        n_digits = len(s)
        if 1 <= n_digits <= 12:
            hints.append(FormatHint(
                f"Numeric value ({n_digits} digit{'s' if n_digits != 1 else ''})",
                "if used as an object identifier, test for IDOR by incrementing/"
                "decrementing the value"))

    # Short hex blobs (8, 12, 16, 20, 24 hex chars) - probably some kind
    # of checksum or short ID, not yet covered by the longer-hash detectors.
    if (re.fullmatch(r"[a-fA-F0-9]{8}", s) and
            not any("hash" in h.label or "Mongo" in h.label for h in hints)):
        hints.append(FormatHint(
            "8 hex chars  (CRC32 / file checksum / short ID)",
            "8-char hex = 32 bits. CRC32 of something? A short DB ID? "
            "Without context, guess CRC32 first."))
    if (re.fullmatch(r"[a-fA-F0-9]{16}", s) and
            not any("hash" in h.label or "Mongo" in h.label for h in hints)):
        hints.append(FormatHint(
            "16 hex chars  (could be: 64-bit ID / partial hash / short token)",
            "non-standard hash length. If you found it in a session cookie, "
            "try cracking small wordlists vs MD5/SHA1 truncated to 16 chars."))

    # ---- Generic base64 (only if not already classified above) ----
    # De-noise list: skip the base64 hint when something more specific
    # (JWT, vendor key, HTTP Basic) has already matched - those are
    # also alphanumeric+ but the base64-decoding suggestion would be
    # actively wrong for them (an AWS key isn't base64 of anything).
    _SPECIFIC_PREFIXES = ("JWT", "AWS", "GitHub", "Stripe", "Slack", "GitLab",
                           "HTTP Basic", "Bcrypt", "Argon2", "crypt(3)",
                           "MongoDB", "MD5", "SHA-",
                           "OpenAI", "Anthropic", "Google", "Twilio",
                           "SendGrid", "Mailgun", "npm", "Docker", "Discord",
                           "PEM-armored", "PEM X.509", "PGP private",
                           "8 hex chars", "16 hex chars")
    if (re.fullmatch(r"[A-Za-z0-9+/_-]+=*", s) and len(s) >= 8 and len(s) % 4 == 0
            and not any(h.label.startswith(_SPECIFIC_PREFIXES) for h in hints)):
        hints.append(FormatHint(
            "Looks like base64-encoded data",
            "use `b64d` to decode (works for standard base64 and base64url)"))

    # ---- Hex bytes (only if not already classified as something more specific) ----
    # Skip when we already identified the exact role - MD5/SHA hashes,
    # MongoDB ObjectId, and short-hex (8/16 chars with their own hints)
    # are all valid hex but each has a richer interpretation we'd
    # rather lead with.
    if (re.fullmatch(r"[0-9a-fA-F]+", s) and len(s) >= 8 and len(s) % 2 == 0
            and not any("hash" in h.label or "ObjectId" in h.label
                         or "hex chars" in h.label for h in hints)):
        hints.append(FormatHint(
            "Hex-encoded bytes",
            "use `hexd` to decode to bytes / ASCII"))

    # ---- Last-resort fallback: opaque high-entropy token ----
    # Fires ONLY when nothing else matched AND the input is a single
    # line of high-entropy alphanumeric/url-safe characters - matches
    # the shape of random session IDs, opaque OAuth tokens, refresh
    # tokens, API keys without a vendor prefix.
    # Length-gated to avoid flagging short identifiers like "abc123".
    if (not hints
            and "\n" not in s
            and len(s) >= 16
            and re.fullmatch(r"[A-Za-z0-9_.+/=-]+", s)):
        # Approximate entropy: count unique-char ratio + presence of
        # both letter cases. Real opaque tokens are usually
        # >0.4 unique-char ratio.
        unique_ratio = len(set(s)) / max(1, len(s))
        has_upper = any(c.isupper() for c in s)
        has_lower = any(c.islower() for c in s)
        has_digit = any(c.isdigit() for c in s)
        char_classes = sum((has_upper, has_lower, has_digit))
        if unique_ratio > 0.3 and char_classes >= 2:
            hints.append(FormatHint(
                "Looks like an opaque token / session ID / random secret",
                "no specific vendor pattern matched. Try `b64d` (it might "
                "be base64 of something readable), `magic` (auto-tries every "
                "decoder), or just check if it's a session cookie value you "
                "should tamper with."))

    return hints


# =====================================================================
# MAGIC AUTO-DECODER
# =====================================================================
# Run a small set of "likely" decoders against the input and return
# the ones that produce plausibly-readable output. Used by the
# "Magic" menu entry - inspired by CyberChef's built-in Magic op.
def _looks_readable(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
    return (printable / len(s)) > 0.85


def magic_decode(text: str) -> list[tuple[str, str]]:
    """Try each decoder; return [(op_name, result)] for readable results."""
    candidates = [
        ("From Base64",        op_from_base64),
        ("From URL",           op_from_url),
        ("From URL (double)",  op_from_double_url),
        ("From Hex",           op_from_hex),
        ("From Base32",        op_from_base32),
        ("From HTML entities", op_from_html_entities),
        ("From Binary",        op_from_binary),
        ("ROT13",              op_rot13_clean),
    ]
    out = []
    for name, fn in candidates:
        try:
            result = fn(text, {})
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if result == text or not _looks_readable(result):
            continue
        out.append((name, result))
    # Also try JWT detect
    if text.count(".") == 2:
        try:
            jwt_out = op_word_to_jwt_summary(text, {})
            out.append(("JWT decode", jwt_out))
        except (ValueError, binascii.Error, UnicodeDecodeError):
            pass
    # Also try query-string parse. Tight shape guard so we don't
    # claim `hello=world I have spaces` is a query string:
    #   - must contain `=`
    #   - must contain `&` OR start with `?` (single-pair `?id=1` is fine,
    #     bare `id=1` is too ambiguous)
    #   - must have NO raw whitespace (real query strings encode spaces)
    #   - must not be a full URL (urlparse handles those better)
    has_kv     = "=" in text
    multi_pair = "&" in text or text.startswith("?")
    is_url     = text.startswith(("http://", "https://"))
    no_spaces  = not any(c.isspace() for c in text)
    if has_kv and multi_pair and no_spaces and not is_url:
        try:
            parsed_pairs = urllib.parse.parse_qsl(
                text.lstrip("?"), keep_blank_values=True)
            if parsed_pairs:
                out.append(("Parse query string",
                            op_parse_query_string(text, {})))
        except (ValueError, UnicodeDecodeError):
            pass
    return out


# =====================================================================
# TUI
# =====================================================================
THEME = Theme({
    "primary":  "bold cyan",
    "accent":   "bold magenta",
    "success":  "bold green",
    "warning":  "bold yellow",
    "error":    "bold red",
    "muted":    "dim white",
    "banner":   "bold cyan",
    "recipe":   "bold yellow",
})

# Truncate displayed input/output in the panels so a 10 MB blob
# doesn't overwhelm the terminal. The FULL value is what's operated
# on; only the display is clipped.
DISPLAY_TRUNCATE = 800


def truncate_display(s: str, limit: int = DISPLAY_TRUNCATE) -> str:
    if len(s) <= limit:
        return s
    return s[:limit] + f"\n[...truncated, {len(s) - limit} more chars]"


def show_state(console: Console, current: str, recipe: list[tuple[str, dict]]) -> None:
    """Print the current input + the recipe stack."""
    console.print()
    # Current value panel
    body = Text(truncate_display(current) or "<empty>")
    title = f"Current value  ({len(current)} chars)"
    console.print(Panel(body, title=title, border_style="primary", padding=(1, 2)))
    # Recipe panel (if any operations have been applied)
    if recipe:
        # Build the joined string first - avoids a trailing newline
        # AND avoids Text.rstrip() which mutates in place and returns
        # None (would crash Panel rendering).
        recipe_lines = []
        for i, (name, args) in enumerate(recipe, start=1):
            args_str = ""
            if args:
                args_str = " (" + ", ".join(f"{k}={v!r}" for k, v in args.items()) + ")"
            recipe_lines.append(f"{i:>2}. {name}{args_str}")
        recipe_text = Text("\n".join(recipe_lines), style="recipe")
        console.print(Panel(recipe_text, title="Recipe", border_style="accent"))


# ----- LIST + HELP commands (printed when user types `list` / `help`) -----
def render_help(console: Console) -> None:
    """Print the cheat sheet so the user can see what's available."""
    console.print()
    console.print(Panel(
        Text.assemble(
            ("Control commands:\n", "primary"),
            ("  magic    ", "accent"), "auto-detect: try every decoder, annotate each result\n",
            ("  identify ", "accent"), "(aliases: id, what) just say what the value LOOKS LIKE\n",
            ("           ", "accent"), "(MD5? JWT? IPv4? cookie format?) without decoding\n",
            ("  edit     ", "accent"), "replace the current value\n",
            ("  undo     ", "accent"), "roll back the last operation\n",
            ("  reset    ", "accent"), "go back to the original input\n",
            ("  save     ", "accent"), "write current value to a file\n",
            ("  list     ", "accent"), "show every operation grouped by category\n",
            ("  help     ", "accent"), "show this help\n",
            ("  q / quit ", "accent"), "exit\n",
            "\n",
            ("Operation aliases (or type the full name):\n", "primary"),
            ("  b64 / b64d        ", "accent"), "Base64 encode / decode\n",
            ("  url / urld        ", "accent"), "URL encode / decode\n",
            ("  url2 / url2d      ", "accent"), "double-URL encode / decode\n",
            ("  hex / hexd        ", "accent"), "Hex encode / decode\n",
            ("  bin / bind        ", "accent"), "Binary encode / decode\n",
            ("  html / htmld      ", "accent"), "HTML entity encode / decode\n",
            ("  b32 / b32d        ", "accent"), "Base32 encode / decode\n",
            ("  rot / rot13       ", "accent"), "ROT13 cipher (self-inverse)\n",
            ("  md5 / sha1 /      ", "accent"), "hash to hex digest\n",
            ("  sha256 / sha512   ", "accent"), "\n",
            ("  hmac              ", "accent"), "HMAC-SHA256 (prompts for key)\n",
            ("  rev / upper /     ", "accent"), "Reverse / Upper case / Lower case\n",
            ("  lower / strip     ", "accent"), "\n",
            ("  json / minify     ", "accent"), "JSON pretty-print / minify\n",
            ("  purl / pqs        ", "accent"), "Parse URL / parse query string\n",
            ("  defang / refang   ", "accent"), "URL defang/refang for IOC sharing\n",
            ("  epoch / iso / now ", "accent"), "Time conversions\n",
            ("  uuid / rand       ", "accent"), "Generate UUID / random hex bytes\n",
            ("  jwt               ", "accent"), "JWT decode + show header/payload\n",
            "\n",
            ("Tip: type a few letters and the prompt autocompletes. "
             "Use `list` for the full operation catalog.", "muted"),
        ),
        title="cyberchef quick reference",
        border_style="primary",
        padding=(1, 2),
    ))


def render_op_list(console: Console) -> None:
    """Print every operation, grouped by category, as a table."""
    console.print()
    by_cat: dict[str, list[Operation]] = {}
    for op in OPERATIONS:
        by_cat.setdefault(op.category, []).append(op)
    for cat in sorted(by_cat):
        table = Table(title=cat, border_style="muted", title_style="primary",
                       show_lines=False)
        table.add_column("Name", style="accent")
        table.add_column("Aliases", style="success")
        table.add_column("Description", style="muted")
        for op in by_cat[cat]:
            aliases = [a for a, name in ALIASES.items() if name == op.name]
            table.add_row(op.name, ", ".join(aliases) or "-", op.description)
        console.print(table)


def collect_op_args(op: Operation, q_style) -> dict | None:
    """Prompt for any extra args the operation requires."""
    args = {}
    for arg_def in op.args:
        val = questionary.text(
            arg_def["prompt"], default=arg_def.get("default", ""),
            qmark="", style=q_style,
        ).ask()
        if val is None:
            return None  # Ctrl-C
        args[arg_def["name"]] = val
    return args


def _format_hints_short(hints: list[FormatHint], decoded_value: str = "") -> str:
    """
    Compact one-cell display of hint labels. If no hints matched,
    return a useful "what is this?" descriptor based on the value's
    SHAPE rather than just a dash - so the magic table never shows
    a row that means nothing.
    """
    if hints:
        return "  •  ".join(h.label for h in hints)
    if not decoded_value:
        return "(empty)"
    # Heuristic descriptors when no specific format matched.
    if all(c.isprintable() or c in "\n\t" for c in decoded_value):
        if len(decoded_value) < 80 and " " in decoded_value:
            return "(plain text)"
        if "\n" in decoded_value:
            return "(multi-line text)"
        if all(c.isalnum() or c in "-_" for c in decoded_value):
            return "(opaque alphanumeric blob)"
        return "(readable text, no specific format)"
    return "(binary / non-printable)"


def run_magic_picker(console, current: str, q_style) -> str | None:
    """
    Try every decoder; for each readable result, ALSO run format
    identification so the user sees not just "From Base64 → wiener:51dc..."
    but "From Base64 → wiener:51dc... → looks like username:MD5(password)
    cookie".

    The table layout has 4 columns:
        # / Decoder used / Result preview / What it looks like
    Followed by a "Suggestion" block for whichever result the user
    is most likely to pick.
    """
    # First, show what the INPUT itself looks like (in case nothing
    # needs decoding - the input might already be identifiable).
    input_hints = identify_format(current)
    if input_hints:
        console.print()
        console.print("[primary]Your input looks like:[/primary]")
        for h in input_hints:
            console.print(f"  • [accent]{h.label}[/accent]")
            if h.suggestion:
                console.print(f"      [muted]→ {h.suggestion}[/muted]")

    candidates = magic_decode(current)
    if not candidates:
        if not input_hints:
            console.print("[warning]No single-step decoder produced readable output. "
                          "It may already be plaintext, or chain-encoded.[/warning]")
        return None

    # Pre-compute hints for each candidate result.
    annotated = [(name, result, identify_format(result))
                 for name, result in candidates]

    console.print()
    console.print("[primary]Decoded candidates  "
                  "(each row = one possible interpretation):[/primary]")
    table = Table(show_lines=True, border_style="muted")
    table.add_column("#", style="accent", width=3)
    table.add_column("Decoder", style="primary")
    table.add_column("Result preview", style="success")
    table.add_column("Looks like", style="warning")
    for i, (name, result, hints) in enumerate(annotated, start=1):
        table.add_row(
            str(i), name,
            truncate_display(result, 80),
            _format_hints_short(hints, decoded_value=result),
        )
    console.print(table)

    # If any candidate had hints with suggestions, print them in a
    # separate block - the table cells truncate them otherwise.
    suggestions = [(i, name, hints)
                   for i, (name, _, hints) in enumerate(annotated, start=1)
                   if any(h.suggestion for h in hints)]
    if suggestions:
        console.print()
        console.print("[primary]Suggested next steps:[/primary]")
        for i, name, hints in suggestions:
            for h in hints:
                if h.suggestion:
                    console.print(f"  [accent]#{i}[/accent] ({name}) → "
                                  f"[muted]{h.suggestion}[/muted]")

    choices = [f"{i}. {name}"
               for i, (name, _, _) in enumerate(annotated, start=1)] + ["[ Cancel ]"]
    pick = questionary.select("Apply which?", choices=choices,
                                qmark="", style=q_style).ask()
    if not pick or pick == "[ Cancel ]":
        return None
    idx = int(pick.split(".", 1)[0]) - 1
    return annotated[idx][1]


def _format_diagnostic(value: str) -> Text:
    """Build a 'here's what to try next' block when identify finds nothing."""
    body = Text()
    body.append("No specific format recognized. ", style="warning")
    body.append(f"({len(value)} chars)\n\n", style="muted")
    body.append("Things to try:\n", style="primary")
    body.append("  1. ", style="accent")
    body.append("magic", style="accent")
    body.append("      auto-decode: tries every decoder, shows readable results\n",
                style="muted")
    body.append("  2. ", style="accent")
    body.append("b64d", style="accent")
    body.append("      decode as base64 (most common - try first if it's "
                "letters+digits+/+=)\n", style="muted")
    body.append("  3. ", style="accent")
    body.append("urld", style="accent")
    body.append("      URL-decode (try if you see %XX sequences)\n",
                style="muted")
    body.append("  4. ", style="accent")
    body.append("hexd", style="accent")
    body.append("      hex-decode (try if it's all 0-9 and a-f)\n",
                style="muted")
    body.append("  5. ", style="accent")
    body.append("list", style="accent")
    body.append("      browse all 40 operations\n", style="muted")
    body.append("\n")
    # Length-based hints for things the user might not have realized.
    if len(value) < 20:
        body.append("Note: short strings often have no distinctive format. "
                    "It may simply be plaintext or an opaque identifier.\n",
                    style="muted")
    elif len(value) > 1000:
        body.append("Note: large blob - might be a full HTTP response / "
                    "encoded image / serialized object. Try `b64d` first; "
                    "if it decodes, identify the result.\n", style="muted")
    elif all(c.isalnum() or c in "-_+/=" for c in value):
        body.append("Note: this is high-entropy alphanumeric text - "
                    "an opaque token, session ID, or encoded blob. "
                    "Try `magic` first.\n", style="muted")
    return body


def run_identify(console: Console, current: str) -> None:
    """
    Standalone `identify` command - show what the CURRENT value looks
    like without applying anything. Useful for "I have this string,
    what is it?" without committing to a decoder.
    """
    console.print()
    if not current.strip():
        console.print(Panel(
            Text("The current value is empty. Use `edit` to paste in "
                 "the value you want to identify.", style="warning"),
            title="identify", border_style="warning", padding=(1, 2),
        ))
        return

    hints = identify_format(current)
    if not hints:
        console.print(Panel(
            _format_diagnostic(current),
            title="identify",
            border_style="warning",
            padding=(1, 2),
        ))
        return
    body = Text()
    body.append(f"The current value ({len(current)} chars) looks like:\n\n",
                style="primary")
    for h in hints:
        body.append(f"  •  {h.label}\n", style="accent")
        if h.suggestion:
            body.append(f"       → {h.suggestion}\n", style="muted")
    console.print(Panel(body.rstrip(), title="identify",
                          border_style="primary", padding=(1, 2)))


def make_questionary_style():
    return questionary.Style([
        ("qmark",       "fg:#00ffff bold"),
        ("question",    "fg:#ffffff bold"),
        ("answer",      "fg:#ff00ff bold"),
        ("pointer",     "fg:#00ffff bold"),
        ("highlighted", "fg:#00ffff bold"),
        ("selected",    "fg:#ff00ff"),
    ])


def show_banner(console: Console):
    body = Text.assemble(
        ("cyberchef.py", "banner"),
        ("  —  ", "muted"),
        ("offline mini-CyberChef\n\n", "primary"),
        ("Type an alias to apply an op, or a control command:\n", "muted"),
        ("  magic ", "accent"), "(auto-decode + annotate)   ",
        ("identify ", "accent"), "(what IS this thing?)\n",
        ("  b64 / b64d ", "accent"), "(base64)   ",
        ("url / urld ", "accent"), "(URL)   ",
        ("hex / hexd ", "accent"), "(hex)\n",
        ("  sha256 / md5 ", "accent"), "(hash)   ",
        ("jwt ", "accent"), "(JWT decode)   ",
        ("json ", "accent"), "(pretty-print)\n",
        ("  help ", "accent"), "= full cheat sheet   ",
        ("list ", "accent"), "= every operation   ",
        ("undo ", "accent"), "/ ",
        ("save ", "accent"), "/ ",
        ("q ", "accent"), "= quit\n\n",
        ("All computation is local — nothing leaves your machine.", "warning"),
    )
    console.print(Panel(body, border_style="primary", padding=(1, 2)))


# Reserved keywords - these route to control actions, not operations.
CONTROL_COMMANDS = {
    "magic", "identify", "id", "what",
    "edit", "undo", "reset", "save",
    "help", "list", "q", "quit", "exit",
}


def _prompt_choices() -> list[str]:
    """All valid autocomplete suggestions: control commands + op names + aliases."""
    return (
        sorted(CONTROL_COMMANDS)
        + sorted(ALIASES.keys())
        + sorted(op.name for op in OPERATIONS)
    )


def tui_loop(initial: str):
    console = Console(theme=THEME, highlight=False)
    q_style = make_questionary_style()
    show_banner(console)

    # History stack: each entry is the value AFTER that step. history[0]
    # is the initial input. history[-1] is "current". Undo pops.
    history: list[str] = [initial]
    recipe: list[tuple[str, dict]] = []

    completer_choices = _prompt_choices()

    while True:
        current = history[-1]
        show_state(console, current, recipe)

        # ONE prompt for everything. Autocomplete suggests as you type
        # so you don't have to remember exact names; we validate in
        # code below so unrecognized input gets a friendly error
        # rather than blocking the user.
        #
        # Prompt text spells out exactly what's expected - earlier
        # the prompt was "› cyberchef >" which read as gibberish to
        # anyone who hadn't seen a REPL prompt before.
        cmd = questionary.autocomplete(
            "What do you want to do?  (type an alias, op name, or command — "
            "try `help` if you're stuck, `q` to quit):",
            choices=completer_choices,
            meta_information={c: "" for c in completer_choices},
            ignore_case=True,
            match_middle=True,
            validate=lambda x: True,
            qmark="",          # no leading symbol - the prompt text is self-explanatory
            style=q_style,
        ).ask()

        if cmd is None:
            console.print("[muted]bye[/muted]")
            break

        cmd_lower = cmd.strip().lower()
        if not cmd_lower:
            continue

        # ---- Control commands ----
        if cmd_lower in ("q", "quit", "exit"):
            console.print("[muted]bye[/muted]")
            break

        if cmd_lower == "help":
            render_help(console)
            continue

        if cmd_lower == "list":
            render_op_list(console)
            continue

        if cmd_lower == "undo":
            if len(history) <= 1:
                console.print("[muted]nothing to undo[/muted]")
            else:
                history.pop()
                recipe.pop()
                console.print(f"[muted]undone[/muted]")
            continue

        if cmd_lower == "reset":
            if len(history) == 1:
                console.print("[muted]already at original input[/muted]")
            else:
                history = [history[0]]
                recipe = []
                console.print(f"[muted]reset to original input[/muted]")
            continue

        if cmd_lower == "edit":
            new = questionary.text(
                "Replace current value (multiline, Esc + Enter to finish):",
                default=current, qmark="", style=q_style, multiline=True,
            ).ask()
            if new is None:
                continue
            history.append(new)
            recipe.append(("Edit", {}))
            continue

        if cmd_lower == "save":
            path = questionary.path("Save to (example: out.txt):",
                                     qmark="", style=q_style).ask()
            if not path:
                continue
            try:
                Path(path).write_text(current)
                console.print(f"[success]wrote {len(current)} chars to {path}[/success]")
            except OSError as e:
                console.print(f"[error]write failed: {e}[/error]")
            continue

        if cmd_lower == "magic":
            result = run_magic_picker(console, current, q_style)
            if result is not None:
                history.append(result)
                recipe.append(("Magic (auto)", {}))
            continue

        if cmd_lower in ("identify", "id", "what"):
            run_identify(console, current)
            continue

        # ---- Operation by alias or name ----
        op = resolve_op_name(cmd)
        if op is None:
            console.print(f"[warning]unknown: {cmd!r}. "
                          f"Type [bold]help[/bold] for the cheat sheet, "
                          f"or [bold]list[/bold] for every operation.[/warning]")
            continue

        args = collect_op_args(op, q_style)
        if args is None:
            continue
        try:
            result = op.fn(current, args)
        except Exception as e:
            console.print(f"[error]{op.name} failed: {e}[/error]")
            continue
        history.append(result)
        recipe.append((op.name, args))


# =====================================================================
# CLI
# =====================================================================
def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--input", type=Path, metavar="FILE",
                     help="Load initial input from FILE (default: prompt interactively, "
                          "or read stdin if it's not a TTY)")
    src.add_argument("--text", metavar="STRING",
                     help="Set initial input to this string literally")
    args = ap.parse_args()

    if args.input:
        if not args.input.exists():
            sys.exit(f"[!] input file not found: {args.input}")
        initial = args.input.read_text(errors="replace")
    elif args.text is not None:
        initial = args.text
    elif not sys.stdin.isatty():
        # Pipe mode: cat foo.txt | python3 cyberchef.py
        initial = sys.stdin.read()
        # After consuming stdin we need a TTY back for the interactive
        # prompts. On *nix re-open /dev/tty; on weird platforms just
        # error out gracefully.
        try:
            sys.stdin = open("/dev/tty")
        except OSError:
            sys.exit("[!] piped stdin + no /dev/tty available - "
                     "use --input FILE or --text 'string' instead")
    else:
        # Interactive: prompt for initial input.
        initial = questionary.text(
            "Initial input  (paste / type; empty to start blank):",
            default="", multiline=False,
            qmark="",
        ).ask() or ""

    try:
        tui_loop(initial)
    except KeyboardInterrupt:
        print()
        print("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
