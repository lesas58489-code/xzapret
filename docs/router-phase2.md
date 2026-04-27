# Router Phase 2 — DNS hijack for hostname-aware routing

**Status:** planned, not implemented.

## Motivation

Phase 1 (current, in `core/go/router.go`) decides per-connection by:
1. Hostname match against static lists (when SOCKS5 has hostname)
2. IP match against static-list pre-resolved IPs (when SOCKS5 has IP literal)
3. IP match against learned cache

In practice tun2socks forwards almost all SOCKS5 CONNECT requests with **IP literals** (because the app has already resolved the domain via system DNS, which currently goes through the tunnel and returns a real IP). So Phase 1's hostname-based decisions only kick in for the small subset of apps that pass hostnames directly to SOCKS5.

Phase 2 closes that gap by intercepting DNS so we always know the hostname of a connection.

## Mechanism: fake-IP

1. **DNS interception.** Tun2socks already routes UDP/53 to our SOCKS5 UDP-associate handler. Add a DNS-aware handler there: parse queries, generate replies.
2. **For known-bypass domains** (Phase 1 list match): real DNS resolve → return real IP. App connects to real IP via TUN → tun2socks → SOCKS5 with that IP → Router.Decide returns BYPASS (because IP is in `bypassIPs` set or static-IP-resolved list).
3. **For unknown / blocked domains:** return a fake IP from `198.18.0.0/15` (RFC2544 test range, almost never used in real networks). Maintain a map `fakeIP → realDomain` and `fakeIP → realIP-resolved-via-tunnel`.
4. **App connects to fake IP** via TUN → tun2socks → SOCKS5 CONNECT to fake IP. We look up the fake IP in our map, get the real domain, run `Router.Decide(domain, port)`, and:
   - **BYPASS:** look up real IP (refresh DNS via direct), `net.Dial("tcp", realIP:port)`.
   - **TUNNEL:** open mux stream to `(realDomain, port)` so the server resolves and connects (we never need real IP on client side).

## Why fake-IP and not "transparent DNS proxy that returns real IP for everything"

If we returned the real IP for blocked domains too, the app would TCP-connect to that real IP, which RU DPI would shape/reset. We need the app's TCP to land on us so we can decide whether to bypass or tunnel — fake IPs in 198.18/15 force exactly that.

## Cons / risks

- **198.18/15 collision:** RFC2544 test range. Some load testing tools and rare network configs use it. We need to detect and fall through to direct in that edge case (e.g., if a fake-IP CONNECT can't find a mapping → treat as real IP, route normal).
- **DoH / DoT clients** (e.g., Firefox built-in DoH to Cloudflare 1.1.1.1:443) bypass our DNS hijack entirely. Mitigation: route all 1.1.1.1:443 / 8.8.8.8:443 / known DoH IPs through tunnel always (or block them so apps fall back to system DNS).
- **DNS-cache mismatch:** if app caches its DNS reply for hours and we restart, the fakeIP map is gone. Solution: persist fakeIP map alongside router cache, or use deterministic fakeIP-from-hash so restart re-derives same mapping.
- **TTL handling:** DNS replies should carry sane TTLs (60s for fake IPs, real TTL for real IPs from upstream).
- **Concurrent map mutation:** with thousands of fake IPs over a session, GC is needed. Periodically prune entries unused for >1h.

## Implementation sketch

New files:
- `core/go/dns.go` — DNS server (parses queries, generates replies, fakeIP allocator)
- `core/go/dns_test.go` — round-trip tests
- Update `core/go/socks5.go` — UDP-associate handler routes :53 to DNS server; CONNECT handler resolves fakeIP → realDomain before Router.Decide
- Update `core/go/router.go` — accept hostname always; remove IP-literal special path

Estimated effort: 250-400 lines + tests. ~2-3 days of focused work.

## When to do this

- After Phase 1 has run in production for a while and we have data on actual bypass-cache hit rates.
- If hit rate is poor (<60% of traffic getting correct verdict) → Phase 2 is worth it.
- If hit rate is good → Phase 1 is sufficient, Phase 2 can wait.
