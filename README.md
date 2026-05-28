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
