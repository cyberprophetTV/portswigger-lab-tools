#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY.
# Intended for solving PortSwigger Web Security Academy labs and for
# use against systems you OWN or have EXPLICIT WRITTEN PERMISSION to
# test. Running this against unauthorized systems is illegal in most
# jurisdictions. See README.
"""
=====================================================================
lab_tools.py - Interactive launcher / menu for the toolkit
=====================================================================

WHAT THIS IS
------------
A friendly TUI (text user interface) that gives you a menu of every
tool in the repo, prompts for the inputs each one needs, and runs the
selected tool for you. It's an alternative entry point to the
individual CLI scripts - same outcome, different ergonomics.

  $ python3 lab_tools.py            # interactive launcher
  $ python3 username_enum_solver.py LAB_URL ...   # direct CLI

If you're scripting, use the direct CLI. If you're exploring the
toolkit or you forget the exact flags, use the launcher.

TUI vs CLI - WHAT'S THE DIFFERENCE?
-----------------------------------
A CLI ("command line interface") takes its inputs as arguments on a
single shell command. You type the whole thing up front, hit enter,
the program runs and exits. Great for scripting, automation, and
power users who already know the commands.

A TUI ("text user interface") draws on the terminal interactively -
menus, prompts, panels, sometimes mouse support. You navigate with
the keyboard. Examples: htop, vim, lazygit, nethack. TUIs are
discoverable (you can see your options) but harder to automate.

This launcher is a SIMPLE TUI - it's not a full-screen interactive
app like htop. It just prints a banner, shows menus, prompts for
inputs, and dispatches. Think of it as "guided CLI."

THE LIBRARIES
-------------
We use two third-party libraries to make this look good:

  rich
      The de-facto standard for nice terminal output in Python.
      Provides Console (smart print()), Panel (boxed text),
      Table (formatted columns), Text (styled strings), Theme
      (color-scheme objects), Progress (progress bars), and a
      ton more. Author also wrote Textual (full TUI framework).
      Install: pip install rich

  questionary
      Interactive prompts built on prompt_toolkit. Gives you
      arrow-key-navigable select menus, autocompleting text
      inputs, yes/no confirmations, etc. Used by Poetry and
      a bunch of other CLI tools.
      Install: pip install questionary

Both are OPTIONAL for the rest of the toolkit but REQUIRED for
this launcher. If they're missing the launcher fails fast with
a clear install message rather than mysteriously breaking.

THEMES
------
A "theme" is a named mapping from semantic style roles (e.g.
"primary", "success", "warning") to concrete colors. Decoupling
roles from colors lets us swap the whole color scheme by picking
a different theme - the code never hardcodes "green", it uses
"success" and the theme decides what color success looks like.

This launcher ships with three themes:
  neon        cyan/magenta/green - punchy, dark-terminal default
  matrix      all-green - classic "hacker movie" aesthetic
  monochrome  no color - for accessibility, screen readers,
              or terminals where colors look bad

You're prompted to pick one on first launch.

THE LAUNCHER'S DESIGN
---------------------
We declare each tool as a Tool dataclass: name, script path,
description, lab URL, list of input prompts. Adding a new tool to
the menu is a single dict literal - no need to touch the menu code.

When the user picks a tool we:
  1. Show its description + the lab URL it targets
  2. Prompt for each input in turn (with sensible defaults)
  3. Optionally take an "extra flags" string for advanced users
  4. Build the equivalent CLI command, SHOW IT to the user
     (educational: now they know how to run it directly next time)
  5. Run the tool via subprocess.run() so its own output streams
     through normally

After the tool exits, we loop back to the main menu.
"""

# ---------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------
import argparse
import os
import shlex                                 # for quoting CLI args correctly
import subprocess
import sys
import time                                  # monotonic elapsed-time tracker
from dataclasses import dataclass, field, replace
from pathlib import Path

# ---- Optional deps with friendly install message ----
# We import Rich + questionary at module level, but wrap in a try/except
# so a missing dep gives a clear error instead of a cryptic ImportError.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    from rich.align import Align
    from rich.padding import Padding
    import questionary
    from questionary import Style as QStyle
except ImportError as e:
    sys.stderr.write(
        f"lab_tools.py needs Rich and questionary:\n"
        f"  pip install rich questionary\n\n"
        f"(missing module: {e.name})\n"
    )
    sys.exit(1)


# ---------------------------------------------------------------------
# THEMES
# ---------------------------------------------------------------------
# A Rich Theme is a dict mapping "style names" (strings you can use
# inside Rich markup like [primary]hello[/primary]) to color/attribute
# specs. Themes share the same KEY set so any code that styles via
# "primary" / "success" / etc. works with any theme.
#
# Style spec syntax (Rich):
#   "color"                     foreground color
#   "color on bgcolor"          fg + bg
#   "bold color"                bold + fg
#   "italic dim color"          multi-attribute
THEMES: dict[str, Theme] = {
    # NEON - vibrant default, easy to read on dark backgrounds.
    "neon": Theme({
        "primary":   "bold cyan",
        "accent":    "bold magenta",
        "success":   "bold green",
        "warning":   "bold yellow",
        "error":     "bold red",
        "muted":     "dim white",
        "banner":    "bold cyan",
        "url":       "underline blue",
        "kbd":       "reverse cyan",
    }),
    # MATRIX - all-green, dark background, classic Hollywood hacker.
    "matrix": Theme({
        "primary":   "bold green",
        "accent":    "green",
        "success":   "bold bright_green",
        "warning":   "bold yellow",
        "error":     "bold red",
        "muted":     "dim green",
        "banner":    "bold bright_green",
        "url":       "underline green",
        "kbd":       "reverse green",
    }),
    # MONOCHROME - no color. For screen readers, output redirection,
    # or terminals where colors render badly.
    "monochrome": Theme({
        "primary":   "bold",
        "accent":    "bold",
        "success":   "bold",
        "warning":   "bold",
        "error":     "bold",
        "muted":     "dim",
        "banner":    "bold",
        "url":       "underline",
        "kbd":       "reverse",
    }),
}


def make_questionary_style(theme_name: str) -> QStyle:
    """
    Translate our theme name into a questionary Style.

    Questionary uses prompt_toolkit's class system - you set styles
    by "class name" (e.g. "qmark", "selected") rather than by Rich's
    inline markup. We map our theme palette into the prompt_toolkit
    classes that questionary actually paints with.

    The hex colors below approximate the named colors our Rich theme
    uses - questionary/prompt_toolkit don't read Rich themes directly.
    """
    if theme_name == "matrix":
        return QStyle([
            ("qmark",     "fg:#00ff00 bold"),
            ("question",  "fg:#00ff00 bold"),
            ("answer",    "fg:#00cc00 bold"),
            ("pointer",   "fg:#00ff00 bold"),
            ("highlighted", "fg:#00ff00 bold"),
            ("selected",  "fg:#00ff00"),
            ("separator", "fg:#005500"),
            ("instruction", "fg:#005500"),
        ])
    if theme_name == "monochrome":
        return QStyle([
            ("qmark",     "bold"),
            ("question",  "bold"),
            ("answer",    "bold"),
            ("pointer",   "bold"),
            ("highlighted", "bold"),
        ])
    # neon (default)
    return QStyle([
        ("qmark",     "fg:#00ffff bold"),
        ("question",  "fg:#ffffff bold"),
        ("answer",    "fg:#ff00ff bold"),
        ("pointer",   "fg:#00ffff bold"),
        ("highlighted", "fg:#00ffff bold"),
        ("selected",  "fg:#ff00ff"),
        ("separator", "fg:#555555"),
        ("instruction", "fg:#aaaaaa"),
    ])


# ---------------------------------------------------------------------
# TOOL CATALOG
# ---------------------------------------------------------------------
# Each Tool is a self-describing record: name, the script that
# implements it, what it does, which PortSwigger lab it targets, and
# what inputs the user needs to provide.
#
# A "prompt" is one input the launcher asks the user for. Positional
# args have no flag and become bare arguments to the script.
# Optional flags start with "--" and are passed through as --flag value.
@dataclass
class Prompt:
    arg: str                # arg name; positional like "base_url", or flag like "--workers"
    question: str           # human-readable text shown in the prompt
    default: str | None = None       # default value (Enter to accept)
    kind: str = "text"      # "text" | "select" | "path"
    choices: list[str] = field(default_factory=list)  # for kind="select"
    required: bool = True
    # If set, the value is pulled from / saved into SessionState by
    # this key. Use for inputs that the user provides ONCE and reuses
    # across many tool invocations (lab URL, cookie jars, proxy, OAST
    # host). Speed matters in a 4-hour exam - retyping the lab URL
    # into every tool is wasted minutes.
    shared_var: str | None = None


# =====================================================================
# SESSION STATE - things the user enters ONCE and reuses across tools
# =====================================================================
# The launcher remembers per-session values so prompts can default to
# the most recently used input. Specifically:
#
#   lab_url      The lab's https://...web-security-academy.net URL.
#                Almost every tool wants this; entering it once and
#                having every subsequent prompt default to it saves
#                10+ typing seconds per tool invocation.
#   cookie_jar   Path to a saved cookie jar (admin or default session).
#                Used by intruder, dirbuster, param_miner, security_audit.
#   admin_jar    Specifically for privesc's --admin-jar slot.
#   user_jar     Specifically for privesc's --user-jar slot.
#   proxy        Proxy URL (e.g. "burp" or "http://127.0.0.1:8080").
#   oast_host    Out-of-band host for blind-vuln probes.
#   request_file Default raw HTTP request template path.
#
# Lazy semantics: nothing is set until you enter it. After you enter
# it, future prompts with the matching `shared_var` use it as default.
# You can wipe it with `--reset-defaults` at launch.
@dataclass
class SessionState:
    lab_url:      str = ""
    cookie_jar:   str = ""
    admin_jar:    str = ""
    user_jar:     str = ""
    proxy:        str = ""
    oast_host:    str = ""
    request_file: str = ""

    def snapshot(self) -> dict[str, str]:
        """Return the currently-set values for display purposes."""
        return {k: v for k, v in self.__dict__.items() if v}

    def has_any(self) -> bool:
        return bool(self.snapshot())


@dataclass
class Tool:
    key: str                # short id (used internally)
    name: str               # menu label
    script: str             # filename of the underlying tool
    description: str        # 2-3 line summary shown after selection
    lab_url: str | None     # PortSwigger lab URL, if any
    prompts: list[Prompt]
    # Which vulnerability classes this tool targets. Shown in the tool
    # intro panel + in the "vulnerability matrix" menu entry, so the
    # user knows WHEN to reach for which tool.
    vulnerabilities: list[str] = field(default_factory=list)
    # Tool category for color-coding in the menu + intro panel.
    # One of: "active" (actively probing the target, yellow),
    #         "solver" (purpose-built lab solver, cyan),
    #         "analysis" (passive local analysis, green),
    #         "reference" (read-only reference, magenta).
    # Color shorthand: AT a GLANCE which menu entries are which.
    category: str = "active"


# Category definitions: display label + Rich style + 3-letter abbrev
# used in the questionary select prefix. Centralized here so a future
# theme change touches one place.
TOOL_CATEGORIES = {
    "active":    {"label": "active",  "style": "warning",  "abbrev": "ACT"},
    "solver":    {"label": "solver",  "style": "primary",  "abbrev": "SOL"},
    "analysis":  {"label": "analyze", "style": "success",  "abbrev": "ANA"},
    "reference": {"label": "ref",     "style": "accent",   "abbrev": "REF"},
}


TOOLS: list[Tool] = [
    Tool(
        key="enum_diff",
        name="Username enum (different responses)",
        script="username_enum_solver.py",
        description=(
            "Two-phase attack: find a valid username by spotting the response "
            "whose body length differs from the rest, then brute-force its "
            "password. Targets labs where invalid/valid usernames produce "
            "obviously different error pages."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses",
        prompts=[
            Prompt("base_url",  "Lab URL  (example: https://0a1b00ab.web-security-academy.net)",
                   shared_var="lab_url"),
            Prompt("usernames", "Usernames wordlist path  (one username per line, e.g. usernames.txt)",
                   default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path  (one password per line, e.g. passwords.txt)",
                   default="passwords.txt", kind="path"),
        ],
        vulnerabilities=[
            "Username enumeration (response-content leak)",
            "Authentication / credential brute-force",
        ],
        category="solver",
    ),
    Tool(
        key="enum_subtle",
        name="Username enum (subtly different responses)",
        script="subtle_response_solver.py",
        description=(
            "Same goal but for labs where the response only differs by ~1 "
            "character. Uses difflib.SequenceMatcher + CSRF-token "
            "canonicalization to find the outlier when naive length "
            "comparison won't cut it."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses",
        prompts=[
            Prompt("base_url",  "Lab URL  (example: https://0a1b00ab.web-security-academy.net)",
                   shared_var="lab_url"),
            Prompt("usernames", "Usernames wordlist path  (one username per line, e.g. usernames.txt)",
                   default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path  (one password per line, e.g. passwords.txt)",
                   default="passwords.txt", kind="path"),
        ],
        vulnerabilities=[
            "Username enumeration (subtle content delta)",
            "Authentication / credential brute-force",
        ],
        category="solver",
    ),
    Tool(
        key="enum_timing",
        name="Username enum (response timing)",
        script="timing_attack_solver.py",
        description=(
            "Detects valid usernames via response-time differences (server "
            "runs bcrypt on a real hash for valid users). Uses a long junk "
            "password to amplify the timing oracle, samples each candidate "
            "N times, and rotates X-Forwarded-For to defeat per-IP rate "
            "limiting."
        ),
        lab_url="https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing",
        prompts=[
            Prompt("base_url",  "Lab URL  (example: https://0a1b00ab.web-security-academy.net)",
                   shared_var="lab_url"),
            Prompt("usernames", "Usernames wordlist path  (one username per line, e.g. usernames.txt)",
                   default="usernames.txt", kind="path"),
            Prompt("passwords", "Passwords wordlist path  (one password per line, e.g. passwords.txt)",
                   default="passwords.txt", kind="path"),
            Prompt("--samples", "Samples per candidate  (integer; more = slower + more reliable, e.g. 3, 5, 10)",
                   default="3"),
        ],
        vulnerabilities=[
            "Username enumeration (response-time / timing oracle)",
            "Authentication / timing-oracle attacks",
        ],
        category="solver",
    ),
    Tool(
        key="proxy_spider",
        name="Proxy spider (hydrate Burp + map attack surface)",
        script="proxy_spider.py",
        description=(
            "Crawl a target site, extract every link + form action + "
            "form input name, and route ALL traffic through Burp's "
            "proxy at 127.0.0.1:8080 so it lands in Burp's HTTP History. "
            "In minutes you've pre-populated Burp with the whole attack "
            "surface before manual testing."
        ),
        lab_url=None,
        prompts=[
            Prompt("url", "Start URL  (example: https://target.com)",
                   shared_var="lab_url"),
            Prompt("--max-pages", "Page cap  (stop after N pages, default 200)",
                   default="200", required=False),
            Prompt("--max-depth", "BFS depth limit  (default 5)",
                   default="5", required=False),
            Prompt("--proxy", "Proxy URL  ('burp' = http://127.0.0.1:8080)",
                   default="burp", required=False),
        ],
        category="active",
        vulnerabilities=[
            "Attack-surface mapping (Burp-Community equivalent of Burp Pro's crawler)",
            "Hidden-endpoint enumeration via link/form discovery",
            "Form-parameter inventory (input/textarea/select/button names)",
            "Pre-flight for SQLi / XSS / auth-bypass hunting on discovered endpoints",
        ],
    ),
    Tool(
        key="docs_downloader",
        name="Docs downloader (offline payload vault, BSCP exam prep)",
        script="docs_downloader.py",
        description=(
            "Crawls a docs site / wiki / blog / GitHub README directory "
            "and saves each page as CLEAN plain text in a local "
            "directory. Strips scripts/styles/nav chrome - leaves the "
            "prose. Build BEFORE the exam, grep DURING the exam. "
            "Bypasses Burp on purpose (speed + clean proxy history). "
            "Sanitizes URLs to safe Linux filenames so recursive "
            "directory writes don't break."
        ),
        lab_url=None,
        prompts=[
            Prompt("url", "Docs URL to crawl  "
                          "(example: https://portswigger.net/web-security)"),
            Prompt("--output", "Output directory  (e.g. docs/portswigger)",
                   kind="path"),
            Prompt("--max-pages", "Page cap  (default 500)",
                   default="500", required=False),
        ],
        category="analysis",
        vulnerabilities=[
            "Reference building for ALL vuln classes - the vault you grep "
            "during the exam to find the exact syntax for the payload you need",
        ],
    ),
    Tool(
        key="exploit_server",
        name="Exploit server (host payloads + tunnel for victim browser)",
        script="exploit_server.py",
        description=(
            "Local HTTP server + optional public tunnel (cloudflared / "
            "serveo / localhost.run) for delivering XSS / CSRF / file "
            "payloads to a victim browser that can't reach your VM "
            "directly. Logs every hit live with full path + query "
            "string - so payloads that exfiltrate cookies via /log?c=... "
            "show up in your terminal immediately."
        ),
        lab_url=None,
        prompts=[
            Prompt("serve_cmd", "Subcommand", default="serve", kind="select",
                   choices=["serve"]),
            Prompt("directory", "Directory to serve  "
                                "(holds your XSS/CSRF .html/.js payloads, e.g. ./payloads)",
                   kind="path"),
            Prompt("--port", "Local port to bind  (default 8000)",
                   default="8000", required=False),
            Prompt("--tunnel", "Public tunnel  "
                               "(cloudflared = most reliable; serveo / localhost.run = SSH-based, zero install)",
                   default="cloudflared", kind="select",
                   choices=["cloudflared", "serveo", "localhost.run"]),
        ],
        vulnerabilities=[
            "Stored / reflected XSS (cookie exfil)",
            "CSRF (host the attacker's form)",
            "File-upload delivery (webshells, polyglots)",
            "Open redirect chain landing pages",
        ],
        category="active",
    ),
    Tool(
        key="cheatsheet",
        name="Cheatsheet (browsable payload reference)",
        script="cheatsheet.py",
        description=(
            "Categorized offline payload reference: SQLi, XSS, SSRF, JWT, "
            "command injection, SSTI, XXE, file upload, CSRF, NoSQLi, LDAP, "
            "race conditions, web cache poisoning, path traversal, open "
            "redirect, deserialization, plus more. Browse by category, "
            "search by keyword, or `list` all entries. Curated for what "
            "actually shows up on the BSCP exam."
        ),
        lab_url=None,
        prompts=[],
        vulnerabilities=[
            "ALL classes - reference for SQLi/XSS/SSRF/JWT/SSTI/XXE/"
            "command-inj/file-upload/CSRF/NoSQLi/LDAP/race/cache-poison/"
            "path-traversal/open-redirect/deserialization",
        ],
        category="reference",
    ),
    Tool(
        key="cyberchef",
        name="CyberChef (offline TUI - encode/decode/hash/parse)",
        script="cyberchef.py",
        description=(
            "TUI mini-CyberChef. Paste a value, then chain operations: "
            "Base64 / URL / Hex / Binary encoding, MD5/SHA hashing, "
            "JSON pretty-print, URL parsing, defang/refang for IOC "
            "sharing, time conversions, JWT decode, magic auto-decoder. "
            "Everything runs locally - no calls to the live CyberChef "
            "site. Safe for tokens / cookies / credentials."
        ),
        lab_url=None,
        prompts=[
            Prompt("--input", "Load initial input from a file  "
                              "(blank to type interactively in the TUI)",
                   default="", kind="path", required=False),
        ],
        vulnerabilities=[
            "Token / cookie / payload analysis (decode, hash, identify)",
            "JWT inspection (decode + flag security observations)",
            "Encoded-blob recognition (magic auto-detect mode)",
        ],
        category="analysis",
    ),
    Tool(
        key="workflow",
        name="Workflow runner (multi-step + state extraction + fuzz)",
        script="workflow.py",
        description=(
            "Execute a chain of HTTP requests defined in a JSON workflow "
            "file. Each step can extract values from its response (regex, "
            "cookie, header, JSON path) into variables that subsequent "
            "steps reference via {{name}}. The last step can include a "
            "`fuzz` block that runs sniper-mode fuzzing with all the "
            "captured state in place. See examples/workflow-login-csrf-fuzz.json."
        ),
        lab_url=None,
        prompts=[
            Prompt("workflow_file", "Workflow JSON or YAML file  "
                                    "(see examples/workflow-*.json for templates)",
                   default="examples/workflow-login-csrf-fuzz.json", kind="path"),
        ],
        vulnerabilities=[
            "Multi-step CSRF (login -> fetch CSRF -> submit forged)",
            "Cross-app SSRF (App A's SSRF pivots to App B's internal endpoints)",
            "Stateful auth flows (OAuth, multi-factor, password reset)",
            "Session-pinning logout traps (via clear_cookies)",
            "Any vuln that requires per-iteration state refresh",
        ],
        category="active",
    ),
    Tool(
        key="privesc",
        name="Privilege-escalation / IDOR comparator (dual cookies)",
        script="privesc.py",
        description=(
            "Replay the same URL list as TWO different cookie jars "
            "(admin + low-priv) and classify each response pair. Flags "
            "IDOR_LIKELY (both 200, similar body), CONTENT_DELTA "
            "(both 200, different), and BYPASS (admin blocked, user "
            "not). Auth-control bug finder."
        ),
        lab_url=None,
        prompts=[
            Prompt("url_list", "File with one URL per line  "
                                "(absolute URLs, e.g. urls.txt with lines like "
                                "https://target/admin, https://target/api/users)",
                   kind="path"),
            Prompt("--admin-jar", "Admin cookie jar  (JSON file, blank to skip; "
                                  "e.g. admin.json from `intruder --cookie-jar`)",
                   default="", kind="path", required=False, shared_var="admin_jar"),
            Prompt("--user-jar",  "Low-priv cookie jar  (JSON file, blank to skip; "
                                  "e.g. user.json)",
                   default="", kind="path", required=False, shared_var="user_jar"),
        ],
        vulnerabilities=[
            "IDOR / Broken Object-Level Authorization (BOLA)",
            "Broken access control",
            "Privilege escalation (horizontal + vertical)",
            "Forced browsing past per-role restrictions",
        ],
        category="solver",
    ),
    Tool(
        key="security_audit",
        name="Security audit (headers + cookies)",
        script="security_audit.py",
        description=(
            "Passive analysis of a URL. Reports missing security headers "
            "(CSP, HSTS, X-Frame-Options, etc.), insecure cookies "
            "(no HttpOnly / Secure / SameSite), and tech-stack disclosure "
            "(Server, X-Powered-By). One GET request; takes seconds."
        ),
        lab_url=None,
        prompts=[
            Prompt("url", "Target URL  (example: https://target.com/dashboard)",
                   shared_var="lab_url"),
        ],
        vulnerabilities=[
            "Missing security headers (CSP, HSTS, X-Frame-Options, etc.)",
            "Insecure cookies (no HttpOnly / Secure / SameSite)",
            "Tech-stack disclosure (Server / X-Powered-By leaks)",
            "Chained vuln pre-condition: XSS, CSRF, clickjacking, "
            "session hijacking risk indicators",
        ],
        category="analysis",
    ),
    Tool(
        key="param_miner",
        name="Hidden parameter discovery (param miner)",
        script="param_miner.py",
        description=(
            "Find hidden admin/debug parameters that don't appear in normal "
            "browser traffic. For each name in a wordlist (admin, debug, "
            "role, isAdmin, ...), append it to your request with truthy "
            "values (true/1/admin/yes) and flag responses that diverge "
            "from baseline. Auto-handles URL-encoded and JSON bodies."
        ),
        lab_url=None,
        prompts=[
            Prompt("request_file", "Raw HTTP request template  "
                                   "(must have a POST body; see examples/login.txt)",
                   default="examples/login.txt", kind="path", shared_var="request_file"),
            Prompt("--params", "Parameter wordlist  (one param name per line; "
                               "e.g. hidden-params.txt has admin, debug, role, ...)",
                   default="hidden-params.txt", kind="path"),
            Prompt("--noise-tolerance", "Ignore length diffs within +/-N bytes  "
                                       "(integer; e.g. 5 for noisy responses, 0 for strict)",
                   default="0", required=False),
        ],
        vulnerabilities=[
            "Mass assignment / parameter pollution",
            "Hidden admin / debug functionality (admin=true, debug=1, ...)",
            "Privilege escalation via undocumented backend params",
            "HTTP method override (_method, X-HTTP-Method-Override)",
            "Prototype pollution (__proto__, constructor) entry points",
            "SSRF / open-redirect via undocumented URL params",
        ],
        category="active",
    ),
    Tool(
        key="dirbuster",
        name="Content discovery (dirbusting)",
        script="dirbuster.py",
        description=(
            "Find hidden endpoints by trying every path in a wordlist "
            "and flagging the ones the server actually serves. Default "
            "interesting statuses: 200/301/302/401/403/500. Supports "
            "extension fuzzing (.php/.bak/.zip), recursion into "
            "discovered directories, and the same auth + proxy + "
            "output-format options as intruder."
        ),
        lab_url=None,
        prompts=[
            Prompt("base_url", "Target base URL  (example: https://target.com)",
                   shared_var="lab_url"),
            Prompt("wordlist", "Path wordlist  (one path per line, no leading slash; "
                               "e.g. common-paths.txt, SecLists raft-small-words.txt)",
                   default="common-paths.txt", kind="path"),
            Prompt("--extensions", "Extensions to try, comma-separated  "
                                   "(e.g. '.php,.bak,.zip' or blank to skip)",
                   default="", required=False),
        ],
        vulnerabilities=[
            "Forced browsing (admin panels, dev endpoints)",
            "Information disclosure (.git, .env, backup files)",
            "Hidden API endpoints (/api/v1, internal/, debug/)",
            "Source code exposure (WEB-INF/, .git/config, package.json)",
            "Pre-condition for many other vulns (you can't exploit "
            "what you haven't found)",
        ],
        category="active",
    ),
    Tool(
        key="intruder",
        name="Intruder (general-purpose fuzzer)",
        script="intruder.py",
        description=(
            "Burp-Intruder-style HTTP request fuzzer. Give it a raw request "
            "template with §MARKER§ payload positions, a wordlist, and an "
            "attack mode (sniper / battering-ram / pitchfork / cluster-bomb). "
            "Use it for SQLi, XSS, path traversal, dir enum, or any other "
            "'swap X into Y' attack."
        ),
        lab_url=None,
        prompts=[
            Prompt("request_file", "Raw HTTP request template file  "
                                   "(paste from Burp's Raw tab; mark payload positions "
                                   "with §...§; see examples/login.txt)",
                   default="examples/login.txt", kind="path", shared_var="request_file"),
            Prompt("--payload", "Payload wordlist path  "
                                "(one payload per line; e.g. usernames.txt, "
                                "your-sqli-list.txt, your-xss-list.txt)",
                   default="usernames.txt", kind="path"),
            Prompt("--mode", "Attack mode  "
                             "(sniper = 1 marker at a time; cluster-bomb = cartesian product)",
                   default="sniper", kind="select",
                   choices=["sniper", "battering-ram", "pitchfork", "cluster-bomb"]),
            Prompt("--match-status", "Match status  "
                                     "(examples: '200', '200-299', '!403'; blank = no filter)",
                   default="", required=False),
            Prompt("--match-length", "Match body length  "
                                     "(examples: '!3168' = anything-but-3168, "
                                     "'5000-' = 5000+; blank = no filter)",
                   default="", required=False),
        ],
        vulnerabilities=[
            "SQL Injection (all flavors: error / boolean / time-based / OOB)",
            "XSS (with --detect-reflection)",
            "Path traversal (with path-traversal-payloads.txt)",
            "SSRF (with --oob-host + a URL/host wordlist)",
            "OS command injection (--match-time-delta for blind)",
            "Server-side template injection (test-payload wordlist)",
            "Open redirect",
            "Authentication brute force (credentials wordlist)",
            "Web cache poisoning (with unkeyed-headers.txt)",
            "ANY 'swap X into position Y' fuzzing",
        ],
        category="active",
    ),
]


# ---------------------------------------------------------------------
# UI HELPERS
# ---------------------------------------------------------------------
def show_banner(console: Console) -> None:
    """
    Print the project banner: a bordered panel with the project name,
    a one-line tagline, and the educational-use disclaimer.

    Rich.Panel draws a Unicode box around its content. The `border_style`
    pulls from the active theme, so the box color matches the theme.
    """
    title = Text.assemble(
        ("portswigger", "banner"),
        ("-", "muted"),
        ("lab-tools", "banner"),
    )
    body = Text.assemble(
        "Educational pentesting toolkit for the ",
        ("PortSwigger Web Security Academy", "accent"),
        "\n",
        ("FOR EDUCATIONAL USE ONLY", "error"),
        ".  Authorized targets only.\n",
        ("Repo: ", "muted"),
        ("github.com/cyberprophetTV/portswigger-lab-tools", "url"),
    )
    panel = Panel(
        Align.center(body, vertical="middle"),
        title=title,
        border_style="primary",
        padding=(1, 4),
    )
    console.print(panel)


def show_disclaimer_acceptance(console: Console) -> bool:
    """
    Make the user explicitly accept the educational-use disclaimer
    before they can use the launcher. This is the "are you authorized?"
    speed bump that responsible security tools include.

    Returns True if they accepted.
    """
    console.print()
    console.print(
        "[warning]By continuing, you confirm that you are using this tool against "
        "systems you own or have written authorization to test.[/warning]"
    )
    return questionary.confirm(
        "Continue?",
        default=False,
        # `instruction` shows next to the question - here we use it
        # to remind people that the safe answer is "No, I'm not sure".
        instruction="(y/N)",
        auto_enter=False,
    ).ask() is True


def pick_theme(console: Console) -> str:
    """
    Show a small preview of each theme, then let the user pick one.
    The preview is a tiny panel rendered with that theme so they can
    see what they're choosing.
    """
    console.print("[primary]Choose a theme:[/primary]")
    for name in THEMES:
        # Build a one-off Console using this candidate theme so the
        # preview is rendered with the theme's actual colors.
        preview = Console(theme=THEMES[name], width=60, highlight=False)
        sample = Text.assemble(
            ("[+] success message  ", "success"),
            ("[!] warning  ", "warning"),
            ("[-] error  ", "error"),
            ("[*] info", "primary"),
        )
        preview.print(Panel(sample, title=f"theme: {name}", border_style="accent",
                            padding=(0, 1)))

    choice = questionary.select(
        "Theme:",
        choices=list(THEMES.keys()),
        default="neon",
        # `qmark` is the leading icon character; "?" is the default,
        # we use "›" because it reads as a pointer.
        qmark="›",
    ).ask()
    return choice or "neon"


def make_console(theme_name: str) -> Console:
    """
    Build the main Rich Console wired up to the chosen theme.

    `highlight=False` disables Rich's auto-syntax-highlighting of
    numbers/URLs in printed strings - it can look messy in CLI output
    and we want our explicit styling to be the only style applied.
    """
    return Console(theme=THEMES[theme_name], highlight=False)


_MOTIVATION_ACTION = "Show motivation (Brain Unloader)"
_VULN_MATRIX_ACTION = "Show tool → vulnerability matrix"
_QUICK_SETUP_ACTION = "Quick setup (set lab URL + cookies + proxy + OAST host)"
_RESET_DEFAULTS_ACTION = "Reset session defaults"


def show_tool_menu(console: Console) -> Tool | None | str:
    """
    Present the main menu of tools + 'Quit'. Returns the chosen Tool,
    None to quit, or the literal string _MOTIVATION_ACTION when the
    user wants to view the Brain Unloader.
    """
    console.print()
    console.print("[primary]Available tools[/primary]  "
                  "[muted](color/prefix = category)[/muted]")

    # Render a Rich Table summarizing each tool: number, type
    # (color-coded by category), name, script.
    table = Table(border_style="muted", show_lines=False, padding=(0, 1))
    table.add_column("#",      style="accent",  width=3)
    table.add_column("Type",   width=8)
    table.add_column("Tool",   style="primary")
    table.add_column("Script", style="muted")
    for i, t in enumerate(TOOLS, start=1):
        cat = TOOL_CATEGORIES.get(t.category, TOOL_CATEGORIES["active"])
        type_cell = f"[{cat['style']}]{cat['label']}[/{cat['style']}]"
        table.add_row(str(i), type_cell, t.name, t.script)
    console.print(table)
    # Category legend - shown once below the table so users learn the colors.
    legend_parts = []
    for cat_key, cat_info in TOOL_CATEGORIES.items():
        legend_parts.append(
            f"[{cat_info['style']}]{cat_info['label']}[/{cat_info['style']}] "
            f"[muted]= {cat_info['abbrev']}[/muted]"
        )
    console.print("[muted]Categories:[/muted]  " + "  |  ".join(legend_parts))

    # Use questionary for the actual selection. Prefix each tool name
    # with the category abbreviation so the user sees the type even in
    # the plain-text questionary list.
    choices = [f"[{TOOL_CATEGORIES[t.category]['abbrev']}] {t.name}"
                for t in TOOLS]
    choices += [_QUICK_SETUP_ACTION, _RESET_DEFAULTS_ACTION,
                 _VULN_MATRIX_ACTION, _MOTIVATION_ACTION, "Quit"]
    pick = questionary.select(
        "Pick a tool:",
        choices=choices,
        qmark="",
    ).ask()
    if pick is None or pick == "Quit":
        return None
    if pick in (_MOTIVATION_ACTION, _VULN_MATRIX_ACTION,
                 _QUICK_SETUP_ACTION, _RESET_DEFAULTS_ACTION):
        return pick
    # Strip the "[ACT] " / "[SOL] " / etc. prefix to match back to the
    # underlying Tool.
    tool_name = pick
    if pick.startswith("[") and "] " in pick:
        tool_name = pick.split("] ", 1)[1]
    return next(t for t in TOOLS if t.name == tool_name)


def show_tool_intro(console: Console, tool: Tool) -> None:
    """Print the tool's description + which vuln classes it targets + lab URL."""
    cat = TOOL_CATEGORIES.get(tool.category, TOOL_CATEGORIES["active"])
    # Category appears in the title so you see it again even after
    # selection - reinforces the color/abbrev association.
    title = f"[{cat['style']}][{cat['label'].upper()}][/{cat['style']}]  {tool.name}"
    content = Text.assemble(tool.description)
    if tool.vulnerabilities:
        content.append("\n\nVulnerability classes this addresses:\n", style="primary")
        for v in tool.vulnerabilities:
            content.append(f"  •  {v}\n", style="success")
        # trim trailing newline so the panel padding looks right
        content.rstrip()
    if tool.lab_url:
        content.append("\nTarget lab: ")
        content.append(tool.lab_url, style="url")
    # Border color matches the tool's category - at-a-glance category
    # cue even after you've drilled into the tool.
    console.print(Panel(content, title=title, border_style=cat["style"],
                        padding=(1, 2)))


def render_vuln_matrix(console: Console) -> None:
    """Show the tool ↔ vulnerability-class mapping as one big table."""
    console.print()
    table = Table(
        title="Tool → vulnerability-class mapping",
        title_style="primary",
        border_style="muted",
        show_lines=True,
    )
    table.add_column("Tool", style="primary", no_wrap=True)
    table.add_column("Vulnerability classes it targets", style="success")
    for t in TOOLS:
        vulns = "\n".join(f"• {v}" for v in t.vulnerabilities) if t.vulnerabilities \
                else "(no specific vuln class - utility tool)"
        table.add_row(t.name, vulns)
    console.print(table)
    console.print(
        "[muted]Tip: 'when in doubt' picks are usually [primary]intruder[/primary] "
        "(general fuzzer) for active probing and [primary]cheatsheet[/primary] "
        "(this menu) for syntax reference.[/muted]"
    )


def apply_session_defaults(prompts: list[Prompt], session: SessionState) -> list[Prompt]:
    """
    Return a copy of `prompts` where each Prompt whose `shared_var` is
    set in the session uses the session value as its default. Pure -
    doesn't mutate input.
    """
    out = []
    for p in prompts:
        if p.shared_var:
            session_val = getattr(session, p.shared_var, "")
            if session_val:
                out.append(replace(p, default=session_val))
                continue
        out.append(p)
    return out


def save_to_session(answers: dict, prompts: list[Prompt],
                     session: SessionState) -> None:
    """After the user supplies answers, save any shared_var-tagged
    values back into the SessionState for next time."""
    for p in prompts:
        if not p.shared_var:
            continue
        val = answers.get(p.arg)
        if val:
            setattr(session, p.shared_var, val)


def render_session_summary(console: Console, session: SessionState) -> None:
    """Show currently-set session defaults so the user sees what'll auto-fill."""
    snapshot = session.snapshot()
    if not snapshot:
        return
    console.print()
    table = Table(title="Session defaults  (auto-filled into matching prompts)",
                   title_style="primary", border_style="muted",
                   show_lines=False, padding=(0, 1))
    table.add_column("Variable", style="accent")
    table.add_column("Value",    style="success")
    for k, v in snapshot.items():
        # Truncate long values so the table stays readable.
        display = v if len(v) <= 70 else v[:67] + "..."
        table.add_row(k, display)
    console.print(table)


def run_quick_setup(session: SessionState, q_style) -> None:
    """
    Let the user pre-fill all the high-traffic shared vars in ONE
    interactive flow. Each prompt offers the current value as default
    (blank if not yet set). Blank input = leave unchanged.
    """
    defs = [
        ("lab_url",     "Lab URL  (example: https://0a1b00ab.web-security-academy.net)"),
        ("cookie_jar",  "Default cookie jar (JSON file, blank to skip)"),
        ("admin_jar",   "Admin cookie jar (for privesc, blank to skip)"),
        ("user_jar",    "Low-priv cookie jar (for privesc, blank to skip)"),
        ("proxy",       "Proxy URL  ('burp' = http://127.0.0.1:8080, blank to skip)"),
        ("oast_host",   "OAST host  (interactsh / canarytoken / webhook.site, blank to skip)"),
        ("request_file","Default raw HTTP request template (blank to skip)"),
    ]
    for field_name, question in defs:
        current = getattr(session, field_name, "")
        new = questionary.text(question, default=current,
                                qmark="", style=q_style).ask()
        if new is None:
            return  # Ctrl-C - leave whatever was there
        # Treat blank as "keep current"; user explicitly clears via
        # --reset-defaults at launch.
        if new.strip():
            setattr(session, field_name, new.strip())


def collect_args(tool: Tool, q_style: QStyle,
                  session: SessionState | None = None) -> dict[str, str] | None:
    """
    Walk through the tool's prompts and collect the user's answers.

    Returns a dict {arg_name: value} ready to convert into a CLI
    command. Returns None if the user cancelled (Ctrl-C).

    If `session` is provided, prompts whose `shared_var` is already
    set in the session use the session value as the default - so
    e.g. entering the lab URL once auto-fills every subsequent tool's
    URL prompt. This is the BSCP-exam speedup: you'd retype the same
    URL into 5+ tools otherwise.
    """
    prompts = (apply_session_defaults(tool.prompts, session)
                if session else tool.prompts)
    answers: dict[str, str] = {}
    for p in prompts:
        if p.kind == "select":
            val = questionary.select(
                p.question,
                choices=p.choices,
                default=p.default,
                qmark="›",
                style=q_style,
            ).ask()
        elif p.kind == "path":
            # questionary.path gives tab-completion of file paths.
            val = questionary.path(
                p.question,
                default=p.default or "",
                qmark="›",
                style=q_style,
            ).ask()
        else:
            val = questionary.text(
                p.question,
                default=p.default or "",
                qmark="›",
                style=q_style,
                # Loose validation: require non-empty for required prompts.
                validate=(lambda v: bool(v.strip()) or "required") if p.required else None,
            ).ask()
        if val is None:
            return None  # user pressed Ctrl-C
        # Skip optional prompts the user left blank.
        if not val and not p.required:
            continue
        answers[p.arg] = val.strip()

    # Final "extra args" prompt for power users. Accept any extra flags
    # they want to tack on - --proxy, --verbose, --workers, etc.
    extra = questionary.text(
        "Extra args (optional)  "
        "examples: --proxy burp     (route through Burp at 127.0.0.1:8080)\n"
        "          --workers 20     (more concurrent requests)\n"
        "          --jitter 0.5-2   (random delay between requests)\n"
        "          --max-rps 25     (proactive rate cap)\n"
        "          --verbose        (print every probe + first-hit dump)\n"
        "          --output out.json --output-html out.html",
        default="",
        qmark="›",
        style=q_style,
    ).ask()
    if extra:
        answers["__extra"] = extra.strip()
    return answers


def check_paths(tool: Tool, answers: dict[str, str]) -> list[tuple[Prompt, Path]]:
    """
    For every Prompt with kind=="path" that the user filled in, verify
    the file actually exists. Returns a list of (prompt, path) pairs
    for the missing ones - empty list means everything checked out.

    Done before subprocess so the user gets a clear "file not found:
    examples/login.txt" message instead of a tool-side traceback
    when the script tries to read the missing file.
    """
    missing: list[tuple[Prompt, Path]] = []
    for p in tool.prompts:
        if p.kind != "path":
            continue
        if p.arg not in answers:
            continue
        path = Path(answers[p.arg])
        if not path.exists():
            missing.append((p, path))
    return missing


def build_command(tool: Tool, answers: dict[str, str]) -> list[str]:
    """
    Turn the prompt answers into a subprocess-ready argv list.

    Order: python3 SCRIPT then positional args in tool.prompts order,
    then flags, then any extra raw args. shlex handles any tricky
    quoting in the extra string.
    """
    cmd = [sys.executable, tool.script]

    # Positional args first, in declaration order.
    for p in tool.prompts:
        if p.arg.startswith("-"):
            continue
        if p.arg in answers:
            cmd.append(answers[p.arg])

    # Then flag args.
    for p in tool.prompts:
        if not p.arg.startswith("-"):
            continue
        if p.arg in answers:
            cmd.extend([p.arg, answers[p.arg]])

    # Finally any free-form extras the user typed.
    extra = answers.get("__extra")
    if extra:
        cmd.extend(shlex.split(extra))

    return cmd


# =====================================================================
# BRAIN UNLOADER - personal motivation reminders
# =====================================================================
# Loads a markdown file the user writes (their "why I'm doing this")
# and surfaces it in three places:
#   - one random quote at startup, under the banner
#   - one random quote in the rule-tracker "you're stuck" warning
#   - the full file via the `motivation` menu entry
#
# Looked-for paths (first match wins):
#   1. $BSCP_MOTIVATION_FILE  (env override)
#   2. ./motivation.md        (project-local)
#   3. ~/.config/bscp-tools/motivation.md
#   4. ~/.brain-unloader.md   (legacy/fallback location)
#
# Missing file = feature silently off. No nagging to set it up.
# Template file shipped at motivation.md.template if the user wants
# a starting structure.

import random as _random_motivation


def _find_motivation_file() -> Path | None:
    """Walk the known locations; return the first existing file."""
    candidates = []
    env = os.environ.get("BSCP_MOTIVATION_FILE")
    if env:
        candidates.append(Path(env).expanduser())
    candidates.extend([
        Path("./motivation.md"),
        Path.home() / ".config" / "bscp-tools" / "motivation.md",
        Path.home() / ".brain-unloader.md",
    ])
    for p in candidates:
        if p.exists():
            return p
    return None


def parse_motivation(text: str) -> list[str]:
    """
    Extract "quotes" from a motivation markdown file.

    A quote is one of:
      - a single bullet line starting with '-' (the '- ' stripped)
      - a paragraph (consecutive non-empty, non-comment, non-header lines)

    Ignored:
      - lines starting with '#' (Markdown comments / our doc comments)
      - lines starting with '##' (section headers - rendered separately
        when the full file is shown)
      - blank lines (paragraph separators)
    """
    quotes: list[str] = []
    paragraph: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        # Comment / header / blank handling
        if not line or line.lstrip().startswith("#"):
            if paragraph:
                quotes.append(" ".join(paragraph).strip())
                paragraph = []
            continue
        # Bullet item: emit as its own quote.
        stripped = line.lstrip()
        if stripped.startswith("- "):
            if paragraph:
                quotes.append(" ".join(paragraph).strip())
                paragraph = []
            bullet = stripped[2:].strip()
            if bullet:
                quotes.append(bullet)
            continue
        paragraph.append(stripped)
    if paragraph:
        quotes.append(" ".join(paragraph).strip())
    # Drop quotes that are just placeholders like "[your current role]"
    # so an unedited template doesn't surface its squiggly-bracket TODOs.
    return [q for q in quotes if not (q.startswith("[") and q.endswith("]"))
            and len(q) > 5]


def load_motivation_quotes() -> list[str]:
    """Find the motivation file (if any), parse it, return quote list."""
    path = _find_motivation_file()
    if path is None:
        return []
    try:
        return parse_motivation(path.read_text(errors="replace"))
    except OSError:
        return []


def render_motivation_quote(console: Console, quotes: list[str]) -> None:
    """Pick one quote at random + render as a small unobtrusive panel."""
    if not quotes:
        return
    quote = _random_motivation.choice(quotes)
    console.print(Panel(
        Text(quote, style="accent"),
        title="why I'm doing this",
        title_align="left",
        border_style="muted",
        padding=(0, 2),
    ))


def render_motivation_full(console: Console) -> None:
    """Show the entire motivation file in a panel - the `motivation` menu cmd."""
    path = _find_motivation_file()
    if path is None:
        console.print(Panel(
            Text.assemble(
                ("No motivation file found.\n\n", "warning"),
                ("Create one at any of:\n", "muted"),
                "  - ./motivation.md\n",
                "  - ~/.config/bscp-tools/motivation.md\n",
                "  - ~/.brain-unloader.md\n\n",
                "Or set $BSCP_MOTIVATION_FILE to your own path.\n\n",
                ("See motivation.md.template in this repo for a starter.",
                 "muted"),
            ),
            title="Brain Unloader",
            border_style="warning",
            padding=(1, 2),
        ))
        return
    body = Text(path.read_text(errors="replace"))
    console.print(Panel(body,
                          title=f"Brain Unloader  ·  {path}",
                          border_style="primary",
                          padding=(1, 2)))


# =====================================================================
# RULE TRACKER - per-tool elapsed-time tracking with "don't get stuck" alerts
# =====================================================================
# The #1 BSCP rule is "don't get stuck on one approach for too long."
# We enforce it by tracking how long the user has spent in EACH tool
# this launcher session, and:
#   - Showing a running tally between selections (so they SEE where
#     the time is going).
#   - Flashing a warning if a single tool's accumulated time exceeds
#     `time_limit_minutes`. The suggestion: try a different angle
#     on the same vulnerability, not more of the same tool.
#
# All state is per-launcher-session (no disk persistence) - intentional;
# each exam attempt is independent.
@dataclass
class RuleTracker:
    time_limit_minutes: float = 15.0    # default: warn after 15 min on one tool
    spent: dict[str, float] = field(default_factory=dict)   # tool_key -> seconds
    runs:  dict[str, int]   = field(default_factory=dict)   # tool_key -> invocation count

    def record(self, tool_key: str, elapsed_seconds: float) -> None:
        self.spent[tool_key] = self.spent.get(tool_key, 0.0) + elapsed_seconds
        self.runs[tool_key] = self.runs.get(tool_key, 0) + 1

    def is_stuck(self, tool_key: str) -> bool:
        """True if this tool has now consumed > time_limit_minutes."""
        return self.spent.get(tool_key, 0.0) > (self.time_limit_minutes * 60)

    def total_seconds(self) -> float:
        return sum(self.spent.values())

    def render(self, console: Console) -> None:
        """Print a compact per-tool tally. Skipped if nothing's been run."""
        if not self.spent:
            return
        console.print()
        table = Table(title=f"Session time tracker  (warn after {self.time_limit_minutes:.0f} min/tool)",
                       title_style="primary", border_style="muted",
                       show_lines=False)
        table.add_column("Tool", style="primary")
        table.add_column("Runs",  style="accent",  justify="right")
        table.add_column("Time",  style="success", justify="right")
        table.add_column("Status")
        for key, secs in sorted(self.spent.items(), key=lambda kv: -kv[1]):
            mins = secs / 60.0
            status = ("[error]stuck — try another angle[/error]"
                       if self.is_stuck(key) else "[muted]ok[/muted]")
            table.add_row(key, str(self.runs[key]), f"{mins:5.1f} min", status)
        console.print(table)
        total_min = self.total_seconds() / 60.0
        console.print(f"  [muted]Total session time: {total_min:.1f} min[/muted]")


def confirm_and_run(console: Console, cmd: list[str], q_style: QStyle) -> tuple[int, float]:
    """
    Show the assembled command, exec it immediately, return
    (returncode, elapsed_seconds). No yes/no - you picked the tool and
    filled out the args, so obviously you want to run it.

    Showing the command is STILL intentional: it teaches the user
    exactly what shell command they would have typed to run this tool
    directly. Next time they don't need the launcher unless they want
    to. (Ctrl-C is the bail-out.)

    Elapsed time goes into the per-session RuleTracker so the launcher
    can warn when a tool eats too much time.
    """
    # shlex.join quotes each arg so the displayed line is paste-safe.
    rendered = shlex.join(cmd)

    console.print()
    console.print(Panel(
        Text(rendered, style="success"),
        title="Running now  (Ctrl-C to cancel)",
        subtitle="paste this into your shell to skip the launcher next time",
        border_style="accent",
        padding=(0, 2),
    ))
    console.print()

    # subprocess.run with no `capture_output` lets the tool's stdout/stderr
    # stream live to the user's terminal - including our color tags.
    start = time.monotonic()
    try:
        result = subprocess.run(cmd)
        rc = result.returncode
    except KeyboardInterrupt:
        # User wants out - count as "skipped" rather than success/error.
        console.print("[muted]cancelled with Ctrl-C[/muted]")
        rc = -1
    elapsed = time.monotonic() - start
    return rc, elapsed


# ---------------------------------------------------------------------
# MAIN LOOP
# ---------------------------------------------------------------------
def main():
    # ---- CLI: speed-up flags for setting session defaults at launch ----
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else "")
    ap.add_argument("--time-limit", type=float, default=15.0, metavar="MINUTES",
                    help="Warn when accumulated time on a single tool exceeds N "
                         "minutes (default 15). Enforces the BSCP-exam "
                         "'don't get stuck' rule.")
    ap.add_argument("--lab-url", default="", metavar="URL",
                    help="Pre-populate the session-wide lab URL. Every tool "
                         "prompt that asks for a lab/base/target URL will "
                         "default to this. Skips a LOT of typing in a 4-hour "
                         "exam.")
    ap.add_argument("--proxy", default="", metavar="URL",
                    help="Pre-populate the session-wide proxy (e.g. 'burp').")
    ap.add_argument("--oast-host", default="", metavar="HOST",
                    help="Pre-populate the session-wide OAST host.")
    args = ap.parse_args()
    tracker = RuleTracker(time_limit_minutes=args.time_limit)
    session = SessionState(
        lab_url=args.lab_url,
        proxy=args.proxy,
        oast_host=args.oast_host,
    )

    # Load motivation quotes ONCE at startup so we can sprinkle them
    # at strategic moments without re-reading the file every time.
    motivation_quotes = load_motivation_quotes()

    # We need SOME theme loaded from the start because the banner and
    # the theme-picker prompt themselves use style names like [primary]
    # and [warning] that only resolve once a theme is active. Default
    # to "neon" for the pre-pick UI; the user can switch in the picker.
    console = make_console("neon")
    show_banner(console)

    # One motivation quote right under the banner. Silent if no
    # motivation file exists - users who haven't set it up never see
    # the feature at all.
    render_motivation_quote(console, motivation_quotes)

    if not show_disclaimer_acceptance(console):
        console.print("[error]Declined. Exiting.[/error]")
        sys.exit(0)

    theme_name = pick_theme(console)

    # Rebuild the console under the chosen theme (no-op if they picked
    # neon, since it's already loaded) and re-render the banner so the
    # user sees the theme transition take effect.
    if theme_name != "neon":
        console = make_console(theme_name)
        console.clear()
        show_banner(console)
    q_style = make_questionary_style(theme_name)

    while True:
        # Show the running session-time tracker AND the auto-filled
        # session defaults between selections so the user always sees
        # WHERE their time is going AND WHAT will be pre-filled.
        tracker.render(console)
        render_session_summary(console, session)

        tool = show_tool_menu(console)
        if tool is None:
            console.print("[muted]bye[/muted]")
            break
        if tool == _MOTIVATION_ACTION:
            render_motivation_full(console)
            continue
        if tool == _VULN_MATRIX_ACTION:
            render_vuln_matrix(console)
            continue
        if tool == _QUICK_SETUP_ACTION:
            run_quick_setup(session, q_style)
            continue
        if tool == _RESET_DEFAULTS_ACTION:
            session = SessionState()
            console.print("[muted]session defaults cleared[/muted]")
            continue

        show_tool_intro(console, tool)

        # Pre-flight "you're stuck" warning - if this tool has ALREADY
        # consumed > time_limit_minutes in this session, warn BEFORE
        # the user commits to another invocation.
        if tracker.is_stuck(tool.key):
            mins = tracker.spent.get(tool.key, 0.0) / 60.0
            console.print(Panel(
                Text.assemble(
                    (f"You've spent {mins:.0f} min on this tool already.\n", "error"),
                    ("BSCP rule #1: don't get stuck. ", "warning"),
                    "Consider attacking the same vulnerability from a ",
                    ("different angle", "accent"),
                    " - maybe a different tool, different payload class, "
                    "or check whether you've misidentified the bug class entirely.",
                ),
                title="⚠  stuck-time warning",
                border_style="error",
                padding=(1, 2),
            ))
            # Pair the warning with a motivation quote - "WHY" is more
            # persuasive than "rule" when you're frustrated.
            render_motivation_quote(console, motivation_quotes)

        # Sanity check: does the script we're about to invoke even exist?
        script_path = Path(__file__).parent / tool.script
        if not script_path.exists():
            console.print(f"[error]script not found: {script_path}[/error]")
            continue

        answers = collect_args(tool, q_style, session=session)
        if answers is None:
            console.print("[muted]cancelled[/muted]")
            continue
        # Save shared-var answers back to the session so the next tool
        # invocation can default to them.
        save_to_session(answers, tool.prompts, session)

        # Validate that every path-kind prompt actually points at an
        # existing file. Catching this before exec gives a clear error
        # message instead of a tool-side FileNotFoundError traceback.
        missing = check_paths(tool, answers)
        if missing:
            for prompt, path in missing:
                console.print(f"[error]file not found:[/error] {path}  "
                              f"[muted](for '{prompt.question}')[/muted]")
            if any(p.arg == "request_file" for p, _ in missing):
                console.print("[muted]hint: see the examples/ directory for "
                              "starter templates you can edit.[/muted]")
            continue

        cmd = build_command(tool, answers)
        # build_command uses tool.script as-is; we need the absolute path
        # to be safe regardless of cwd.
        cmd[1] = str(script_path)

        rc, elapsed = confirm_and_run(console, cmd, q_style)
        if rc == -1:
            console.print("[muted]skipped[/muted]")
        else:
            tracker.record(tool.key, elapsed)
            elapsed_min = elapsed / 60.0
            if rc == 0:
                console.print(f"[success]tool exited successfully[/success]  "
                              f"[muted]({elapsed_min:.1f} min)[/muted]")
            else:
                console.print(f"[error]tool exited with code {rc}[/error]  "
                              f"[muted]({elapsed_min:.1f} min)[/muted]")

        # No "back to menu?" prompt - the menu always has a Quit option,
        # so asking after every single run is friction with no benefit.
        # Loop straight back to the tool menu (Quit from the menu OR
        # Ctrl-C from anywhere to bail).


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        # Ctrl-C at any prompt - exit cleanly without a traceback.
        print()
        print("interrupted")
        sys.exit(130)
