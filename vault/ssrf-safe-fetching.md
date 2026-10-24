---
tags: [security, ssrf, scraper]
---

# SSRF-Safe Fetching

The reference scraper fetches URLs taken from public CVE records. Anyone can submit
those URLs, so they are untrusted input.

## Threat

Without checks, a crafted reference URL (or a redirect) can point at
`169.254.169.254` (cloud metadata), `localhost`, or internal ranges. That's SSRF.

## Controls

- Schemes: `http`/`https` only. Ports: 80/443 only.
- Resolve every hostname and reject any address where `ipaddress.ip_address(x).is_global`
  is false (covers private, loopback, link-local, IPv6 ULA, IPv4-mapped IPv6).
- Connect to the **validated IP** (pin it), sending the original Host header and SNI,
  to defeat DNS rebinding.
- Follow redirects manually, re-validating every hop; cap at 3 hops.
- Strip auth headers on cross-origin redirects. Cap response size and time.
- Honest single User-Agent with contact info; respect robots.txt.

## Implementation (`src/cti/http/safe_fetch.py`)

- Custom, ~150 lines on httpx, chosen over `httpx-secure` so each control is visible
  and tested. Advocate was rejected (archived 2023).
- Requests go to the validated IP; `Host` header + `sni_hostname` extension carry
  the real hostname, so TLS certs are still checked against it.
- Rejects the host if **any** resolved address is non-public, and unwraps IPv4-mapped,
  6to4, and Teredo addresses before checking. Extra blocklist for ranges some Python
  versions misclassify (`fec0::/10`, `3fff::/20`, docs/benchmark nets). Needs Python ≥ 3.12.4.
- Hostnames go to the resolver and SNI in IDNA (ASCII) form, the same form as the Host header.

## Gotchas found in review

- **Connection reuse skips cert checks.** httpcore pools connections by IP:port, so a
  pooled TLS connection to host A could serve host B on the same IP without B's cert
  being verified. Fixed with `max_keepalive_connections=0`.
- **Proxy env vars** would route traffic via a proxy with the IP as SNI. `trust_env=False`.
- **Slow-drip responses**: an overall deadline (30 s) on top of per-read timeouts;
  `Accept-Encoding: identity` so the size cap counts real bytes (no gzip bombs).
- An unparseable `Location` raises `httpx.RemoteProtocolError` inside `send()`, even with
  redirects off; it's converted to `BlockedURLError`.

## Tests

Redirect to a private IP, DNS rebinding, IPv6 and IPv4-mapped addresses,
decimal/octal IP encodings (`http://2130706433/`), `file://` and other schemes.

## Scraper (`references/scraper.py`)

- SSRF validation runs **before** the robots.txt check, so a blocked host is recorded as
  `blocked`, not `robots`.
- robots.txt per RFC 9309 via `protego` (stdlib `urllib.robotparser` ignores `*`/`$`
  wildcards and uses first-match, so `Disallow: /*.php` read as *allowed*). 4xx means no
  rules; 5xx or any fetch error means disallow all. Agent token `cti-pipeline`. A redirect
  to another host is checked against that host's robots.txt.
- `scrape_one` never raises. Malformed hostnames (label > 63 chars, `a..b`, bad IDNA)
  raise `UnicodeError` from parsing or DNS; they're converted to `BlockedURLError`.
  Before this fix, one bad reference URL aborted the whole scrape on every resume.
- Bounded memory: targets go to the pool in batches of 4 x workers; shards flush at
  250 records or 64 MB.
- 8 workers, ≥ 2 s between requests to the same host, per-page failures recorded.
- Verified live: Red Hat, Openwall, and GitHub pages fetched over IP-pinned TLS (cert
  checked via SNI); `169.254.169.254` blocked.

Part of the [[ingest-once-snapshot]] run. See [[aws-cost-and-security]] for the cloud side.
