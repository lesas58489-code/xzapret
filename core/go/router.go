// Router decides per-connection whether traffic should bypass the mux tunnel
// (direct dial from this Go process — already excluded from VpnService) or
// go through the tunnel.
//
// Decision order:
//   1. Static whitelist (bypass.txt — Russian sites)        → BYPASS
//   2. Static blocklist (blocked.txt — known-blocked)       → TUNNEL
//   3. Pre-resolved IP set of whitelist                     → BYPASS
//   4. Learned cache (TTL'd)                                → cached verdict
//   5. Default                                              → TUNNEL (safe)
//
// Unknown destinations are async-probed via direct TCP-connect; result is
// cached. Cache survives restarts via JSON file in app cache dir.
//
// Phase 2 (not yet — see docs/router-phase2.md): DNS hijack so we have
// hostnames at the SOCKS5 layer instead of post-resolution IPs.

package xzapcore

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
)

// blockResponseMarkers are substrings that strongly indicate a server is
// returning a country-unavailable / VPN-detected / RKN-blocked response.
// If the probe HTTP response contains any of these (case-insensitive), the
// hostname is cached as TUNNEL even though TLS+TCP succeeded.
var blockResponseMarkers = []string{
	"country unavailable",
	"unavailable for legal reasons",
	"not available in your region",
	"not available in your country",
	"region is not supported",
	"country, region, or territory unsupported",
	"this service is not available",
	"страна недоступна",
	"доступ ограничен",
	"доступ заблокирован",
	"vpn detected",
	"vpn or proxy",
}

//go:embed lists/bypass.txt
var embeddedBypassList string

//go:embed lists/blocked.txt
var embeddedBlockedList string

//go:embed lists/bypass_cidr.txt
var embeddedBypassCIDR string

type Verdict uint8

const (
	VerdictTunnel Verdict = 0 // default: through mux
	VerdictBypass Verdict = 1 // direct from Go process
)

func (v Verdict) String() string {
	if v == VerdictBypass {
		return "bypass"
	}
	return "tunnel"
}

type cacheEntry struct {
	V       Verdict   `json:"v"`
	Expires time.Time `json:"e"`
}

type Router struct {
	cacheFile string

	bypassDomains  map[string]bool
	blockedDomains map[string]bool
	bypassNets     []*net.IPNet // CIDR ranges of major RU providers (static list)

	mu        sync.RWMutex
	bypassIPs map[string]bool       // refreshed periodically from bypassDomains
	cache     map[string]cacheEntry // host (or IP literal) → verdict, TTL'd

	probeCh chan probeRequest
	quit    chan struct{}
	once    sync.Once
}

type probeRequest struct {
	host string
	port int
}

const (
	probeQueueSize  = 256
	probeTimeout    = 2 * time.Second
	bypassCacheTTL  = 24 * time.Hour     // direct-OK can change as IPs migrate
	tunnelCacheTTL  = 7 * 24 * time.Hour // blocked rarely un-blocks fast
	refreshInterval = 1 * time.Hour
)

func NewRouter(cacheFile string) *Router {
	r := &Router{
		cacheFile:      cacheFile,
		bypassDomains:  parseDomainList(embeddedBypassList),
		blockedDomains: parseDomainList(embeddedBlockedList),
		bypassNets:     parseCIDRList(embeddedBypassCIDR),
		bypassIPs:      make(map[string]bool),
		cache:          make(map[string]cacheEntry),
		probeCh:        make(chan probeRequest, probeQueueSize),
		quit:           make(chan struct{}),
	}
	r.loadCache()
	log.Printf("router: %d bypass domains, %d blocked domains, %d bypass CIDRs, %d cached entries",
		len(r.bypassDomains), len(r.blockedDomains), len(r.bypassNets), len(r.cache))
	go r.proberLoop()
	go r.refreshLoop()
	return r
}

func (r *Router) Stop() {
	r.once.Do(func() { close(r.quit) })
	r.saveCache()
}

// Decide returns the routing verdict for a connection. For unknown
// destinations it returns VerdictTunnel (safe default) and schedules an
// async probe so subsequent connections may be cached as bypass.
func (r *Router) Decide(host string, port int) Verdict {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	// 1. static bypass list (matches host or any parent suffix)
	if r.matchDomain(h, r.bypassDomains) {
		return VerdictBypass
	}
	// 2. static blocked list
	if r.matchDomain(h, r.blockedDomains) {
		return VerdictTunnel
	}
	// 3a. pre-resolved bypass IPs (for when host is an IP literal)
	if ip := net.ParseIP(h); ip != nil {
		r.mu.RLock()
		hit := r.bypassIPs[h]
		r.mu.RUnlock()
		if hit {
			return VerdictBypass
		}
		// 3b. static CIDR ranges of RU providers — covers Yandex Market /
		// VK CDN / Sber subdomains that resolve to IPs outside the
		// bypassIPs set (which is built only from exact bypass.txt domains).
		for _, n := range r.bypassNets {
			if n.Contains(ip) {
				return VerdictBypass
			}
		}
	}
	// 4. learned cache
	r.mu.RLock()
	e, ok := r.cache[h]
	r.mu.RUnlock()
	if ok && time.Now().Before(e.Expires) {
		return e.V
	}
	// 5. default: tunnel + async probe
	select {
	case r.probeCh <- probeRequest{host: h, port: port}:
	default:
		// queue full — too many unknowns, skip this probe
	}
	return VerdictTunnel
}

func (r *Router) matchDomain(host string, set map[string]bool) bool {
	if set[host] {
		return true
	}
	parts := strings.Split(host, ".")
	for i := 1; i < len(parts); i++ {
		if set[strings.Join(parts[i:], ".")] {
			return true
		}
	}
	return false
}

func (r *Router) proberLoop() {
	for {
		select {
		case <-r.quit:
			return
		case req := <-r.probeCh:
			r.probeOne(req)
		}
	}
}

// probeOne attempts a direct TCP+TLS connect with short timeout. Outcomes:
//   - For HTTPS port (443) on hostname: do uTLS handshake with SNI=hostname.
//     TLS-OK → BYPASS (DPI lets the actual SNI through, safe to direct-route).
//     TLS RST/timeout → TUNNEL (DPI shapes at SNI layer — youtubei.googleapis.com
//     etc that pass TCP probe but fail TLS were the original false-positive).
//   - For non-HTTPS or IP literal: TCP-only check. IP-literal SUCCESS doesn't
//     cache (shared CDN IPs unsafe). FAILURE always caches TUNNEL.
func (r *Router) probeOne(req probeRequest) {
	r.mu.RLock()
	if e, ok := r.cache[req.host]; ok && time.Now().Before(e.Expires) {
		r.mu.RUnlock()
		return
	}
	r.mu.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	addr := net.JoinHostPort(req.host, fmt.Sprintf("%d", req.port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		// TCP failed — definitely tunnel
		r.mu.Lock()
		r.cache[req.host] = cacheEntry{V: VerdictTunnel, Expires: time.Now().Add(tunnelCacheTTL)}
		r.mu.Unlock()
		log.Printf("router: probe %s:%d → tunnel (tcp err=%v)", req.host, req.port, err)
		return
	}
	defer conn.Close()

	isIPLiteral := net.ParseIP(req.host) != nil

	// HTTPS hostname — three-stage probe: TCP (already done), TLS, HTTP.
	//   - TLS RST/timeout → DPI shapes at SNI layer (youtubei.googleapis.com).
	//   - HTTP 403/451 or known block phrase in response → geo-blocked
	//     (claude.ai, Netflix, hulu) — TLS works but content denied.
	if req.port == 443 && !isIPLiteral {
		cfg := &utls.Config{
			ServerName:         req.host,
			InsecureSkipVerify: true,
		}
		u := utls.UClient(conn, cfg, utls.HelloChrome_131)
		_ = u.SetDeadline(time.Now().Add(probeTimeout))
		if err := u.Handshake(); err != nil {
			r.cacheVerdict(req.host, VerdictTunnel, tunnelCacheTTL)
			log.Printf("router: probe %s:443 → tunnel (tls err=%v)", req.host, err)
			return
		}
		// HTTP probe — minimal GET / and check for geo-block markers.
		v, reason := r.httpProbe(u, req.host)
		ttl := bypassCacheTTL
		if v == VerdictTunnel {
			ttl = tunnelCacheTTL
		}
		r.cacheVerdict(req.host, v, ttl)
		log.Printf("router: probe %s:443 → %s (%s)", req.host, v, reason)
		return
	}

	// Non-HTTPS or IP literal — TCP-only signal.
	if isIPLiteral {
		log.Printf("router: probe %s:%d → tcp-ok but IP-literal (no bypass-learn) — tunnel default", req.host, req.port)
		return
	}
	r.cacheVerdict(req.host, VerdictBypass, bypassCacheTTL)
	log.Printf("router: probe %s:%d → bypass (tcp ok, non-https)", req.host, req.port)
}

func (r *Router) cacheVerdict(host string, v Verdict, ttl time.Duration) {
	r.mu.Lock()
	r.cache[host] = cacheEntry{V: v, Expires: time.Now().Add(ttl)}
	r.mu.Unlock()
}

// httpProbe sends a minimal GET / over an established TLS connection and
// inspects the response for geo-block / VPN-detected markers. Returns the
// verdict and a short reason string for logging.
func (r *Router) httpProbe(conn *utls.UConn, host string) (Verdict, string) {
	req := "GET / HTTP/1.1\r\n" +
		"Host: " + host + "\r\n" +
		"User-Agent: Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36\r\n" +
		"Accept: text/html,*/*;q=0.8\r\n" +
		"Accept-Language: en-US,en;q=0.9\r\n" +
		"Connection: close\r\n\r\n"
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		// Can't even write — TLS up but server unhappy. Default tunnel (safer).
		return VerdictTunnel, "http-write-fail: " + err.Error()
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8192)
	n, _ := io.ReadFull(conn, buf)
	if n == 0 {
		// Server accepted TLS but returned nothing — Cloudflare-style WAF
		// or anti-bot. We can't tell if the real fetch will succeed. Default
		// bypass (TLS handshake worked, give it a chance — user can complain).
		return VerdictBypass, "http-empty: assume ok"
	}
	resp := strings.ToLower(string(buf[:n]))

	// Status line: "HTTP/1.1 NNN ..."
	if i := strings.Index(resp, "\r\n"); i > 0 {
		statusLine := resp[:i]
		if strings.Contains(statusLine, " 403 ") || strings.Contains(statusLine, " 451 ") {
			return VerdictTunnel, "http-status: " + statusLine
		}
	}
	for _, m := range blockResponseMarkers {
		if strings.Contains(resp, m) {
			return VerdictTunnel, "http-marker: " + m
		}
	}
	return VerdictBypass, "http-ok"
}

func (r *Router) refreshLoop() {
	r.refreshBypassIPs()
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-r.quit:
			return
		case <-t.C:
			r.refreshBypassIPs()
			r.expireCache()
			r.saveCache()
		}
	}
}

func (r *Router) refreshBypassIPs() {
	newIPs := make(map[string]bool)
	for d := range r.bypassDomains {
		ips, err := net.LookupIP(d)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if v4 := ip.To4(); v4 != nil {
				newIPs[v4.String()] = true
			} else {
				newIPs[ip.String()] = true
			}
		}
	}
	r.mu.Lock()
	r.bypassIPs = newIPs
	r.mu.Unlock()
	log.Printf("router: refreshed bypass IP set, %d IPs from %d domains", len(newIPs), len(r.bypassDomains))
}

func (r *Router) expireCache() {
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	before := len(r.cache)
	for k, v := range r.cache {
		if now.After(v.Expires) {
			delete(r.cache, k)
		}
	}
	if removed := before - len(r.cache); removed > 0 {
		log.Printf("router: expired %d cache entries (%d remaining)", removed, len(r.cache))
	}
}

func (r *Router) loadCache() {
	if r.cacheFile == "" {
		return
	}
	data, err := os.ReadFile(r.cacheFile)
	if err != nil {
		return
	}
	var loaded map[string]cacheEntry
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Printf("router: cache load: %v (starting fresh)", err)
		return
	}
	now := time.Now()
	dropped := 0
	for k, v := range loaded {
		if now.After(v.Expires) {
			continue
		}
		// Phase 1-era unsafe entries: IP-literal cached as bypass via TCP probe.
		// Google CDN / Cloudflare share IPs across blocked and non-blocked
		// services (TCP-OK ≠ DPI-safe). Drop these on load — they cause
		// false-positive direct routes for blocked content.
		if v.V == VerdictBypass && net.ParseIP(k) != nil {
			dropped++
			continue
		}
		r.cache[k] = v
	}
	if dropped > 0 {
		log.Printf("router: dropped %d stale IP-literal bypass cache entries (Phase 1 leftovers)", dropped)
	}
}

func (r *Router) saveCache() {
	if r.cacheFile == "" {
		return
	}
	r.mu.RLock()
	data, err := json.Marshal(r.cache)
	r.mu.RUnlock()
	if err != nil {
		return
	}
	if err := os.WriteFile(r.cacheFile, data, 0600); err != nil {
		log.Printf("router: save cache: %v", err)
	}
}

// Stats returns current router state for debug logging.
func (r *Router) Stats() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	bypass, tunnel := 0, 0
	for _, e := range r.cache {
		if e.V == VerdictBypass {
			bypass++
		} else {
			tunnel++
		}
	}
	return fmt.Sprintf("bypass-domains=%d blocked-domains=%d bypass-ips=%d cache(bypass=%d tunnel=%d)",
		len(r.bypassDomains), len(r.blockedDomains), len(r.bypassIPs), bypass, tunnel)
}

func parseDomainList(text string) map[string]bool {
	out := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[strings.ToLower(line)] = true
	}
	return out
}

func parseCIDRList(text string) []*net.IPNet {
	var out []*net.IPNet
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, n, err := net.ParseCIDR(line)
		if err != nil {
			log.Printf("router: bad CIDR %q: %v", line, err)
			continue
		}
		out = append(out, n)
	}
	return out
}
