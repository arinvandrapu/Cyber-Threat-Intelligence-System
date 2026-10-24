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
  6to4, and Teredo addresses before checking.

## Tests

Redirect to a private IP, DNS rebinding, IPv6 and IPv4-mapped addresses,
decimal/octal IP encodings (`http://2130706433/`), `file://` and other schemes.

Part of the [[ingest-once-snapshot]] run. See [[aws-cost-and-security]] for the cloud side.
