# portswigger-lab-tools

Small Python tools for solving PortSwigger [Web Security Academy](https://portswigger.net/web-security) labs without Burp Suite Pro. Burp Community's Intruder is artificially rate-limited, which makes brute-force / enumeration labs slow; these scripts hit the lab directly using `requests` + a small thread pool.

**See [docs/walkthrough.md](docs/walkthrough.md) for an end-to-end annotated example** of solving the canonical username-enumeration lab with these tools.

## Designed for AI / LLM orchestration

`intruder.py` has a `--json` mode that emits NDJSON (one JSON object per line) instead of human-readable output. Combined with `--include-body --truncate-body N`, you get a structured stream that's small enough to feed to an LLM:

```bash
python3 intruder.py req.txt --payload sqli.txt \
    --json --include-body --truncate-body 2000 \
    | your-llm-orchestrator.py
```

The response body is run through a noise stripper (scripts, styles, SVG, iframes, comments removed; whitespace collapsed) so a 200 KB React-hydrated page typically compacts to 2–5 KB while preserving forms, inputs, links, and visible text — exactly what an LLM needs to reason about attack surface.

All status / banner / summary lines route to **stderr** in `--json` mode so stdout stays a clean parseable stream.

## Time-based blind detection

```bash
python3 intruder.py req.txt --payload time-sqli-payloads.txt \
    --baseline-samples 5 --match-time-delta 4
```

- `--baseline-samples 5` sends 5 requests at startup with markers blanked out to measure the server's normal response time
- `--match-time-delta 4` flags any response ≥ 4 seconds slower than that baseline
- Designed for payloads like `' OR SLEEP(5)--` that produce identical response bodies but a measurable delay

## Session revivification

```bash
python3 intruder.py req.txt --payload usernames.txt \
    --login-url https://target/login --login-data 'user=admin&pw=secret' \
    --reauth-on-block
```

If the server returns `401`, `403`, or `302 -> /login` mid-fuzz, the script automatically re-runs the login flow and retries the request. Lock-serialized across workers so concurrent failures don't stampede the login endpoint.

## Which tool for which vulnerability?

The same mapping is available inside the launcher (pick "Show tool → vulnerability matrix" in the menu).

| Tool | Vulnerability classes it targets |
|---|---|
| [`intruder.py`](intruder.py) | SQLi (all flavors), XSS, path traversal, SSRF, command injection, SSTI, open redirect, auth brute force, web cache poisoning — any "swap X into position Y" attack |
| [`workflow.py`](workflow.py) | Multi-step CSRF, cross-app SSRF, stateful auth flows (OAuth / 2FA / password reset), session-pinning traps, vulns requiring per-iteration state refresh |
| [`privesc.py`](privesc.py) | IDOR / Broken Object-Level Authorization (BOLA), broken access control, privilege escalation (horizontal + vertical) |
| [`param_miner.py`](param_miner.py) | Mass assignment, parameter pollution, hidden admin/debug functionality, prototype pollution entry points, HTTP method override |
| [`dirbuster.py`](dirbuster.py) | Forced browsing, information disclosure (.git, .env, backup files), hidden API endpoints, source code exposure |
| [`jwt_tool.py`](jwt_tool.py) | JWT attacks: alg=none variants, HS256 weak-secret brute, kid injection, algorithm confusion |
| [`security_audit.py`](security_audit.py) | Missing security headers (CSP, HSTS, X-Frame-Options), insecure cookies (no HttpOnly/Secure/SameSite), tech-stack disclosure |
| [`exploit_server.py`](exploit_server.py) | Stored / reflected XSS (cookie exfil), CSRF (host attacker's form), file-upload delivery, open-redirect landing pages |
| [`oast_poll.py`](oast_poll.py) | Blind SSRF, blind SQLi, blind XXE, log4shell — anything that confirms via out-of-band callback |
| [`response_diff.py`](response_diff.py) | Subtle response analysis after stripping dynamic noise (CSRF tokens, timestamps) — username enum subtle variant, cache-poisoning verification |
| [`cyberchef.py`](cyberchef.py) | Token / cookie / payload analysis (encoding, hashing, JWT inspection, identify-what-is-this) |
| [`decode_tool.py`](decode_tool.py) | Encoding/decoding chains, auto-detect what something is |
| [`cheatsheet.py`](cheatsheet.py) | **Reference for ALL vuln classes** — SQLi, XSS, SSRF, JWT, SSTI, XXE, file upload, CSRF, NoSQLi, LDAP, race conditions, web cache poisoning, deserialization |
| [`username_enum_solver.py`](username_enum_solver.py) | Username enumeration (response-content leak) |
| [`subtle_response_solver.py`](subtle_response_solver.py) | Username enumeration (subtle 1-char delta) |
| [`timing_attack_solver.py`](timing_attack_solver.py) | Username enumeration (response-time / timing oracle) |

**When in doubt**, pick `intruder.py` (general fuzzer) for active probing and `cheatsheet.py` for syntax reference.

## Workflow directives at a glance

| Directive | What it does | Example file |
|---|---|---|
| `loop: {count: N}` | Run a step N times (index in `{{loop_index}}` or your `var`) | [`examples/workflow-loop-paginate.json`](examples/workflow-loop-paginate.json) |
| `loop: {until_status: 200, max: 5}` | Retry until status matches, capped at `max` | [`examples/workflow-loop-retry.json`](examples/workflow-loop-retry.json) |
| `loop: {until_extract: name, max: 10}` | Poll until an extractor finally hits | (in `workflow-loop-retry.json`) |
| `if: "{{role}} == admin"` | Skip step if condition is false. Operators: `==` `!=` `>` `<` `>=` `<=` `!` (prefix) and bare truthy | [`examples/workflow-conditional.json`](examples/workflow-conditional.json) |
| `include: "other.json"` | Pull another workflow in as a single step (shared session; final vars merge back) | [`examples/workflow-include-shared-auth.json`](examples/workflow-include-shared-auth.json) + [`auth-preamble.json`](examples/workflow-auth-preamble.json) |
| YAML format | Same semantics as JSON, more readable for hand-editing (needs `pip install pyyaml`) | [`examples/workflow-yaml-readable.yaml`](examples/workflow-yaml-readable.yaml) |
| `--watch` | Re-run automatically when the workflow file (or any include) is saved on disk. 1-second mtime polling | (any workflow file) |

## BSCP-style rate limit safety

The exam (and most real-world labs) will IP-ban you if you fuzz too aggressively. `intruder.py` has two layers of rate-limit defense:

- **Proactive cap** — `--max-rps N` (e.g. `--max-rps 20`) puts a hard ceiling on your request rate. Combined with `--workers`, this is what you control. BSCP-polite values are 20–30 rps.
- **Reactive backoff** — *always on*. If the server starts returning `429 Too Many Requests`, the rate limiter triggers exponential backoff (1s, 2s, 4s, 8s, ... capped at 60s) until you stop getting blocked. Resets on the first non-429 response.

You can see how many 429s were triggered in the end-of-run summary line.

## Quick start: launcher

```bash
pip install requests rich questionary
python3 lab_tools.py
```

`lab_tools.py` is an interactive launcher: a Rich-rendered banner, a menu of every tool in the repo, arrow-key navigation, theme picker (neon / matrix / monochrome), and guided prompts for the inputs each tool needs. It then prints the equivalent shell command (so you learn the CLI for next time) and runs the tool for you.

If you'd rather use the CLI directly, every tool is self-contained and runs on `pip install requests` alone — see the table below for entry points.

## Tools at a glance

| Script | Purpose | Lab(s) |
|---|---|---|
| [`lab_tools.py`](lab_tools.py) | Interactive launcher with themes and a menu of all tools | n/a (entry point) |
| [`username_enum_solver.py`](username_enum_solver.py) | Two-phase username + password attack against an obvious-response leak | [Username enum via different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses) |
| [`subtle_response_solver.py`](subtle_response_solver.py) | Same idea but for the ~1-char-difference variant; uses `difflib.SequenceMatcher` + body canonicalization | [Username enum via subtly different responses](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-subtly-different-responses) |
| [`timing_attack_solver.py`](timing_attack_solver.py) | Detects valid usernames by mean response time; long junk password + per-request X-Forwarded-For rotation | [Username enum via response timing](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-response-timing) |
| [`intruder.py`](intruder.py) | General-purpose Burp-Intruder-style fuzzer (Sniper / Battering Ram / Pitchfork / Cluster Bomb), matchers, payload encoders, JSON/CSV/HTML/MD output, auth via `--login-url` or cookie jar | Anything you can express as a request template + payload list |
| [`dirbuster.py`](dirbuster.py) | Content discovery / path enumeration. Extension fuzzing (`.php`, `.bak`, ...), recursive descent into discovered directories, same auth + proxy + output options as intruder | Any web target (use `common-paths.txt` to start; swap in [SecLists](https://github.com/danielmiessler/SecLists) for serious work) |
| [`param_miner.py`](param_miner.py) | Discover hidden admin/debug parameters that don't appear in browser traffic (admin, debug, role, isAdmin, ...). Handles URL-encoded and JSON bodies; compares each variant against a noise-aware baseline | BSCP-style hidden-parameter labs and real apps with undocumented backdoors |
| [`security_audit.py`](security_audit.py) | One-GET passive audit: missing CSP/HSTS/X-Frame-Options/etc., cookies lacking HttpOnly/Secure/SameSite, tech-stack disclosure headers | Any URL, including post-auth pages with `--cookie-jar` |
| [`jwt_tool.py`](jwt_tool.py) | JWT analyzer with attack helpers: `decode` (with security observations), `none` (alg=none forgery in three casings), `brute` (HS256 wordlist attack), `sign` (re-sign with known secret), `kid` (kid-header injection variants). CLI subcommands only — not in the launcher menu. | Any JWT-using lab |
| [`privesc.py`](privesc.py) | Dual-token access-control comparator. Replays a URL list under two cookie jars (admin + low-priv) and classifies each pair: `IDOR_LIKELY`, `CONTENT_DELTA`, `BYPASS`, `EXPECTED_BLOCK`, etc. Uses `difflib.SequenceMatcher.ratio()` for body similarity scoring. | BSCP-style IDOR / broken access control labs |
| [`decode_tool.py`](decode_tool.py) | Counterpart to `intruder.py --encode`. Subcommands: `url`, `double-url`, `base64`, `hex`, `html`, `chain` (apply nested decodings outermost-first), `auto` (try every decoder, surface readable results). Auto-detects JWTs and surfaces decoded header + payload. | Any encoded blob — cookies, tokens, query params |
| [`oast_poll.py`](oast_poll.py) | OAST hit correlator. Reads `intruder.py --oob-host`'s JSON output, fetches your OAST log (file or URL), correlates which fuzz payload triggered each back-channel hit. `--watch` mode for late-arriving hits. Tool-agnostic (works with interactsh-client, webhook.site, self-hosted DNS canaries). | After any `intruder --oob-host` run |
| [`workflow.py`](workflow.py) | Multi-step request runner with state extraction. JSON workflow file defines steps; each step can extract values (regex/cookie/header/JSON path) into vars that later steps reference via `{{name}}`. Final step optionally runs sniper-mode fuzz with all captured state. Supports `loop`, `if`, `include`, YAML, `--watch`. | Chained exploitation: login → fetch CSRF → submit form with fuzzed field |
| [`cyberchef.py`](cyberchef.py) | Offline mini-CyberChef in a TUI. 40+ operations across 7 categories (Encoding, Hashing, String, Data, Defang, Time, Misc) — chainable recipe stack with undo. Magic auto-decoder, JWT decode, defang for IOC sharing. **All-local computation** — no calls to the live CyberChef site, safe for tokens/cookies/credentials. | Quick conversions during a pentest without trusting third-party tools |
| [`exploit_server.py`](exploit_server.py) | Local HTTP server + auto-tunneling for client-side payloads. Hosts your XSS/CSRF/file payloads and exposes them via cloudflared / serveo / localhost.run (zero-signup alternatives to ngrok). Live request logging shows exfiltrated cookies as they arrive. | Stage 3 client-side exploitation |
| [`bscp-setup.sh`](bscp-setup.sh) + [`docs/bscp-checklist.md`](docs/bscp-checklist.md) | Installs `ysoserial` / `phpggc` / `sqlmap` to `/opt`, wraps them on PATH, and verifies your VM has the supporting toolchain. Checklist doc explains when to reach for which tool stage-by-stage. | One-time VM prep for the BSCP exam |
| [`proxy_spider.py`](proxy_spider.py) | Crawls a target and routes ALL traffic through Burp's proxy. Extracts every link + form action + form input name. Pre-populates Burp's HTTP History with the whole attack surface in minutes — Burp-Community equivalent of Pro's built-in crawler. | Attack-surface mapping at exam start |
| [`docs_downloader.py`](docs_downloader.py) | Crawls a docs site / wiki / blog and saves each page as **clean plain text** in a local directory mirror. Strips scripts/styles/nav chrome. Sanitizes URLs to safe Linux filenames (no `/` `?` `*` etc. that break mkdir). Bypasses Burp on purpose. | Pre-exam: build a greppable payload vault you can `grep -ri 'time-based' vault/` during the timed exam |

## Disclaimer — Educational use only

**This tool is for educational and authorized testing purposes only.** It is intended for:

- Solving [PortSwigger Web Security Academy](https://portswigger.net/web-security) labs (deliberately vulnerable training apps)
- CTF challenges
- Systems you own
- Systems you have **explicit written authorization** to test (e.g. a signed pentest engagement)

Running this — or any similar tool — against systems you do not own or have permission to test is **illegal** in most jurisdictions (e.g. the Computer Fraud and Abuse Act in the US, the Computer Misuse Act in the UK, and equivalents elsewhere). The author accepts no responsibility for misuse. **You are responsible for ensuring your use is lawful.**

Licensed under the [MIT License](LICENSE).

## Tools

### `username_enum_solver.py`

Solves [**Username enumeration via different responses**](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses).

Two-phase attack:

1. **Enumerate the username.** Probe each candidate with a fixed junk password; fingerprint each response as `(status, body length, error text)`. The valid username is the outlier.
2. **Brute-force the password.** Try each candidate password against the discovered username; success is a `302` redirect to `/my-account`.

Usage:

```bash
python3 username_enum_solver.py https://YOUR-LAB-ID.web-security-academy.net usernames.txt passwords.txt
```

Options:

**Tuning**
- `--workers N` — concurrent requests (default `10`). Higher is faster but more conspicuous.
- `--dummy-password STR` — password used during Phase 1. The default is a long random string so it can't accidentally collide with a real password.

**Stealth**
- `--jitter MIN-MAX` — random delay (seconds) before each request. Examples: `--jitter 0.5` (fixed 0.5s), `--jitter 0.5-2.0` (random in `[0.5, 2.0]`). Defeats simple rate-limiters. Pair with `--workers 1` for maximum stealth.

**Session management**
- `--fresh-session` — build a brand-new `Session` (cookie jar + connections) per request. Defeats per-session lockouts and tracking. Slower because each request does a fresh TCP+TLS handshake.
- `--csrf` — two-step flow: `GET /login` to fetch a CSRF token, then `POST /login` with the token. Required for labs that protect the login form against CSRF; not needed for this specific lab but useful for other auth labs.
- `--show-cookies` — print `Set-Cookie` headers returned by the server. Handy for understanding how the site tracks session state.

**Burp Suite integration**
- `--proxy URL` — route every request through an HTTP proxy. Use `--proxy burp` as shorthand for `http://127.0.0.1:8080` (Burp's default listener). Auto-enables `--insecure` because Burp re-signs TLS certs with its own CA.
- `--insecure` — skip TLS verification. Auto-enabled by `--proxy`. Only use in lab / authorized-test contexts where the upstream proxy is trusted.

With Burp open and proxying, every request + response shows up in Burp's HTTP History tab. From there you can replay them in Repeater, send interesting ones to Comparer/Scanner, or intercept and modify mid-flight. Useful for understanding exactly what the script is sending and for follow-up testing.

**Reliability + observability**
- `-H NAME:VALUE` (a.k.a. `--header`) — extra HTTP header sent on every request. Repeat for multiple. Example: `-H "Authorization: Bearer eyJ..." -H "X-Forwarded-For: 127.0.0.1"`.
- `--retries N` — retry on connection errors / transient `502`/`503`/`504` responses (default `2`).
- `--verbose` — print every probe (not just the final result) and dump the first probe's response body so you can sanity-check the lab is talking back as expected.
- `--output FILE.json` — write a JSON summary of the run (lab URL, valid username, password, credentials) for scripting.

Example with stealth + session management on:

```bash
python3 username_enum_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt \
    --workers 1 --jitter 0.5-2.0 --fresh-session
```

Example routing through Burp at the default listener:

```bash
python3 username_enum_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt \
    --proxy burp
```

### `intruder.py`

General-purpose HTTP request fuzzer modeled on Burp Suite's Intruder. Unlike `username_enum_solver.py` (which has hardcoded knowledge of the username-enumeration lab), `intruder.py` knows nothing about any specific endpoint — you give it a raw HTTP request template with `§MARKER§` payload positions, a wordlist, and an attack mode, and it does the rest.

Use it for: SQL injection probing, XSS payload testing, path-traversal, directory enumeration, header-injection fuzzing, header/cookie value brute-force, JWT manipulation, or anything else that boils down to "swap value X into position Y and look at the response."

**Attack modes** (same semantics as Burp Intruder):

| Mode | Payload sets | Requests | Use case |
|---|---|---|---|
| `sniper` | 1 | N×M | Test each marker independently. Default. |
| `battering-ram` | 1 | M | Same payload in every marker at once. |
| `pitchfork` | K | min(list lengths) | Parallel iteration — credential pairs that shouldn't cross. |
| `cluster-bomb` | K | product of lengths | Cartesian product — full brute-force. |

**Matchers** (AND'd together; result must satisfy all enabled):
- `--match-status SPEC` — e.g. `200`, `200-299`, `!403`, `5000-`
- `--match-length SPEC` — same syntax
- `--match-time SPEC` — response time in seconds
- `--match-regex PATTERN` — pass if regex found in body
- `--match-not-regex PATTERN` — pass if regex NOT found

**Other flags** are the same as `username_enum_solver.py`: `--workers`, `--jitter`, `--fresh-session`, `--proxy`, `--insecure`, `--retries`, `--verbose`, `--output`.

**Usage example — username enumeration as a generic fuzz**

Create `req.txt`:

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§USER§&password=junk
```

Then run:

```bash
python3 intruder.py req.txt \
    --payload usernames.txt \
    --mode sniper \
    --match-length '!3168'   # show the outlier (whatever length isn't 3168)
```

**Usage example — full credential brute-force (cluster-bomb)**

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§USER§&password=§PW§
```

```bash
python3 intruder.py req.txt \
    --payload usernames.txt \
    --payload passwords.txt \
    --mode cluster-bomb \
    --match-status 302       # success is a redirect to /my-account
```

**Usage example — header injection probe**

```
GET /admin HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
X-Forwarded-For: §IP§
```

```bash
python3 intruder.py req.txt \
    --payload ips.txt \
    --match-not-regex 'Forbidden' \
    --output hits.json
```

## Wordlists

`usernames.txt` and `passwords.txt` are the standard candidate lists [published by PortSwigger](https://portswigger.net/web-security/authentication/auth-lab-usernames) for these labs. Re-fetch with:

```bash
python3 -c "import re,urllib.request as u; \
  html=u.urlopen('https://portswigger.net/web-security/authentication/auth-lab-usernames').read().decode(); \
  print('\n'.join(l.strip() for l in re.search(r'<code class=\"code-scrollable\">(.*?)</code>',html,re.S).group(1).splitlines() if l.strip()))" > usernames.txt
```

(Same URL with `auth-lab-passwords` for passwords.)

## Example request templates

The [`examples/`](examples/) directory contains starter templates for `intruder.py`:

- [`examples/login.txt`](examples/login.txt) — single-marker sniper template for username enumeration
- [`examples/login-cluster-bomb.txt`](examples/login-cluster-bomb.txt) — two markers for cluster-bomb (full credential brute-force)
- [`examples/header-injection.txt`](examples/header-injection.txt) — header-value fuzzing template (e.g. `X-Forwarded-For` for IP-allowlist bypass)

Lines starting with `#` in the template file are treated as comments and stripped by the parser — use them to leave notes for yourself. Replace `YOUR-LAB-ID` in the `Host` header with your lab's actual subdomain before running.

## Requirements

- Python 3.10+
- `requests` (required for every tool)
- `rich` + `questionary` (required to use `lab_tools.py`; the individual scripts work without them)
- `tqdm` (optional — enables the progress bar; scripts work without it)
- `pytest` (only needed to run the test suite)

## Development

```bash
pip install requests pytest
pytest tests/ -v
```

71 unit tests cover the pure-logic helpers (request parsing, attack-mode generators, range-spec parsing, matchers, color helpers, canonicalization, IP generator). Network-touching code is left to manual lab testing. CI runs the suite on Python 3.10/3.11/3.12 — see [`.github/workflows/test.yml`](.github/workflows/test.yml).
