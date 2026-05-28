# portswigger-lab-tools

Small Python tools for solving PortSwigger [Web Security Academy](https://portswigger.net/web-security) labs without Burp Suite Pro. Burp Community's Intruder is artificially rate-limited, which makes brute-force / enumeration labs slow; these scripts hit the lab directly using `requests` + a small thread pool.

> For use against PortSwigger's deliberately vulnerable training labs only.

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

Example with stealth + session management on:

```bash
python3 username_enum_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt \
    --workers 1 --jitter 0.5-2.0 --fresh-session
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
