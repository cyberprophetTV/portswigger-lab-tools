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

THE TUI FLOW
------------
  1. Provide input (paste text, load file, or pipe via stdin).
  2. Pick an operation from the categorized menu.
  3. (For ops that need args - HMAC key, salt, AES IV - prompt for them.)
  4. The result becomes the NEW current input.
  5. Repeat - chain operations into a recipe.
  6. Undo to peel back the last operation.
  7. "Magic" mode tries every single-step decoder on the current
     input and shows which produce readable output.
  8. Save the final output to a file when done, or just copy from
     the terminal.

The history stack is per-step, so undo restores the exact state
before the last operation (not a replay - cheap, lossless).

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


def pick_operation(q_style) -> Operation | None:
    """Two-step pick: category, then operation within category."""
    categories = sorted(set(op.category for op in OPERATIONS))
    category = questionary.select(
        "Category:", choices=categories + ["[ Cancel ]"], qmark="›", style=q_style,
    ).ask()
    if not category or category == "[ Cancel ]":
        return None
    in_cat = [op for op in OPERATIONS if op.category == category]
    # Display: "name - description" so the user picks knowing what it does.
    labels = [f"{op.name}  —  {op.description}" for op in in_cat]
    pick = questionary.select(
        "Operation:", choices=labels + ["[ Back ]"], qmark="›", style=q_style,
    ).ask()
    if not pick or pick == "[ Back ]":
        return None
    return next(op for op in in_cat if pick.startswith(op.name + "  —"))


def collect_op_args(op: Operation, q_style) -> dict | None:
    """Prompt for any extra args the operation requires."""
    args = {}
    for arg_def in op.args:
        val = questionary.text(
            arg_def["prompt"], default=arg_def.get("default", ""),
            qmark="›", style=q_style,
        ).ask()
        if val is None:
            return None  # Ctrl-C
        args[arg_def["name"]] = val
    return args


def run_magic_picker(console, current: str, q_style) -> str | None:
    """Try every decoder; if any produced readable output, let user pick one."""
    candidates = magic_decode(current)
    if not candidates:
        console.print("[warning]No single-step decoder produced readable output. "
                      "It may already be plaintext, or it's chain-encoded.[/warning]")
        return None
    # Print previews so the user picks knowing what each produces.
    console.print()
    console.print("[primary]Magic candidates (each row = one possible decoder):[/primary]")
    table = Table(show_lines=False, border_style="muted")
    table.add_column("#", style="accent")
    table.add_column("Decoder", style="primary")
    table.add_column("Result preview", style="success")
    for i, (name, result) in enumerate(candidates, start=1):
        table.add_row(str(i), name, truncate_display(result, 100))
    console.print(table)

    choices = [f"{i}. {name}" for i, (name, _) in enumerate(candidates, start=1)] + ["[ Cancel ]"]
    pick = questionary.select("Apply which?", choices=choices, qmark="›", style=q_style).ask()
    if not pick or pick == "[ Cancel ]":
        return None
    idx = int(pick.split(".", 1)[0]) - 1
    return candidates[idx][1]


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
        ("offline mini-CyberChef\n", "primary"),
        ("Chain operations on the current value. ", "muted"),
        ("Undo to roll back the last step.\n", "muted"),
        ("All computation is local - nothing leaves your machine.", "warning"),
    )
    console.print(Panel(body, border_style="primary", padding=(1, 2)))


def tui_loop(initial: str):
    console = Console(theme=THEME, highlight=False)
    q_style = make_questionary_style()
    show_banner(console)

    # History stack: each entry is the value AFTER that step. history[0]
    # is the initial input. history[-1] is "current". Undo pops.
    history: list[str] = [initial]
    recipe: list[tuple[str, dict]] = []

    while True:
        current = history[-1]
        show_state(console, current, recipe)

        action = questionary.select(
            "Next:",
            choices=[
                "Apply operation",
                "Magic (auto-decode)",
                "Edit current value",
                "Save to file",
                "Undo last operation",
                "Reset to original input",
                "Quit",
            ],
            qmark="›", style=q_style,
        ).ask()

        if action is None or action == "Quit":
            console.print("[muted]bye[/muted]")
            break

        if action == "Apply operation":
            op = pick_operation(q_style)
            if op is None:
                continue
            args = collect_op_args(op, q_style)
            if args is None:
                continue
            try:
                result = op.fn(current, args)
            except Exception as e:
                # Operation failed (bad input, etc.) - report and don't push.
                console.print(f"[error]operation failed: {e}[/error]")
                continue
            history.append(result)
            recipe.append((op.name, args))

        elif action == "Magic (auto-decode)":
            result = run_magic_picker(console, current, q_style)
            if result is not None:
                history.append(result)
                recipe.append(("Magic (auto)", {}))

        elif action == "Edit current value":
            new = questionary.text("Replace current value:", default=current,
                                    qmark="›", style=q_style, multiline=True).ask()
            if new is None:
                continue
            history.append(new)
            recipe.append(("Edit", {}))

        elif action == "Save to file":
            path = questionary.path("Save to:", qmark="›", style=q_style).ask()
            if not path:
                continue
            try:
                Path(path).write_text(current)
                console.print(f"[success]wrote {len(current)} chars to {path}[/success]")
            except OSError as e:
                console.print(f"[error]write failed: {e}[/error]")

        elif action == "Undo last operation":
            if len(history) <= 1:
                console.print("[muted]nothing to undo[/muted]")
                continue
            history.pop()
            recipe.pop()

        elif action == "Reset to original input":
            history = [history[0]]
            recipe = []


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
            qmark="›",
        ).ask() or ""

    try:
        tui_loop(initial)
    except KeyboardInterrupt:
        print()
        print("interrupted")
        sys.exit(130)


if __name__ == "__main__":
    main()
