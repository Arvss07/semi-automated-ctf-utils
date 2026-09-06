# Web manual — Burp-centered manual testing

> Authorized CTF / educational use only. In-scope targets only. Stop on first proof — never dump beyond it, never scan shared infra at concurrency.
> No `web_recon.py` is shipped. Burp Community + browser + Kali CLI only. Toolkit pairing: `encoding_decoder.py` for offline layers.

## 1. Setup

- Burp per challenge (`Temporary project`, defaults). Use built-in Chromium (`Proxy → Intercept → Open browser`) — no proxy config. Firefox: `127.0.0.1:8080` + install PortSwigger CA from `http://burpsuite` (Burp browser profile only).
- Scope first: `Target → Scope → Include in scope` (authorized hosts only). Filter history to scope. Intercept ON to map, OFF to read.
- Rules: Repeater for single requests; Intruder throttled (1–2 threads, short wordlists, stop on first hit, in-scope CTF only); Sequencer/Comparer/Decoder for analysis, not scanning.

## 2. Recon (confirm every hint in Burp)

```bash
curl -i http://HOST:PORT/robots.txt; curl -i http://HOST:PORT/sitemap.xml; curl -i http://HOST:PORT/.git/HEAD
curl -sSI http://HOST:PORT/ | grep -Ei 'server|x-powered|set-cookie|strict|csp|cors|access-control'
openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null | openssl x509 -noout -issuer -subject -dates -ext subjectAltName
dig +short HOST A; dig +short HOST TXT
whatweb http://HOST:PORT/; wafw00f http://HOST:PORT/   # advisory only
```

Checklist: scope map (Site map + history, `Discover content` for gaps) → headers/cookies (`Inspector`; flag `Access-Control-Allow-Origin: *` + credentials, missing `HttpOnly`/`Secure`, `unsafe-inline *`) → TLS SANs (siblings are hints, not authorization) → JS/XHR (`Proxy → history → MIME XHR/JS`, grep bundles for `/api/`, `/graphql`, `fetch(`, keys; cross-check DevTools `F12 → Network`).

## 3. Burp loop

1. **Proxy:** browse one feature at a time; `Send to Repeater` (tamper) / `Send to Comparer` (before/after).
2. **Repeater:** one param at a time; read status/body/headers/timing. `Show response in browser` for XSS/DOM.
3. **Intruder:** `Sniper` single-field fuzz (`id=§123§`); `Cluster bomb` only for tiny pairs. Log mode/wordlist size/threads/stop.
4. **Sequencer:** live-capture ≥100 tokens; low entropy = finding.
5. **Comparer:** `Compare words/bytes` for boolean-SQLi (`' AND '1'='1` vs `' AND '1'='2`), role A vs B (IDOR).
6. **Decoder + history mining:** peel Base64/URL/hex inline (`Decoder → Decode as…`) or offline (`encoding_decoder.py --text '<BLOB>' --decode base64|--recursive`); search history for `api|graphql|token|Authorization:|flag` — hidden endpoints live in XHR, not nav.

## 4. Attacks (payload → confirm)

- **SQLi:** `' AND '1'='1` vs `' AND '1'='2`; confirm content/timing delta in Comparer. One row = proof.
- **XSS:** reflect canary (`XSSCTX123`), check context (HTML/attribute/JS/URL), craft per context. Confirm in `Show response in browser`.
- **SSTI:** `{{7*7}}` → `49` = eval. Confirm engine before chaining.
- **CMDi:** `;sleep 5|` timing delta; prefer timing over exfil.
- **IDOR:** `/user/123 → 124` in two tabs; confirm cross-account read in Comparer.
- **JWT:** `alg:none`, weak secret (offline, throttled), `kid` traversal. Confirm with one re-signed claim replay.
- **Session/reset:** pre-login token valid post-login = fixation. Reset-link leaks (`X-Forwarded-Host` in emailed URL, `Referer`) — own test account only.
- **Logic:** `price/qty/total` one at a time (recalculated?); `_method`/override (405→200 + state change); `{"role":"admin"}` (persisted on re-GET?); ≤5 spaced login/OTP tries (no lockout = finding, no stuffing).
- **Files/SSRF:** `../../etc/passwd` (`..%2f`, `....//`), confirm `/root:x:` content; upload double-extension only on CTF target, confirm by fetching it back; XXE `<!ENTITY>` confirm expansion (use `/etc/hostname`); SSRF `169.254.169.254`/internal ports, blind needs Collaborator (own payloads only, no pivoting).
- **Headers/cache:** missing cookie flags, `Allow-Origin: *` + credentials, `X-Forwarded-Host` reflected in links/cached `X-Cache: HIT` (canary hostname only).
