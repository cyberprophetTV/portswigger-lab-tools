# portswigger-lab-tools

Small Python tools for solving PortSwigger [Web Security Academy](https://portswigger.net/web-security) labs without Burp Suite Pro. Burp Community's Intruder is artificially rate-limited, which makes brute-force / enumeration labs slow; these scripts hit the lab directly using `requests` + a small thread pool.

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

## Requirements

- Python 3.10+
- `requests`
