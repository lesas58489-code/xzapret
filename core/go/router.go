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
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed lists/bypass.txt
var embeddedBypassList string

//go:embed lists/blocked.txt
var embeddedBlockedList string

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
		bypassIPs:      make(map[string]bool),
		cache:          make(map[string]cacheEntry),
		probeCh:        make(chan probeRequest, probeQueueSize),
		quit:           make(chan struct{}),
	}
	r.loadCache()
	log.Printf("router: %d bypass domains, %d blocked domains, %d cached entries",
		len(r.bypassDomains), len(r.blockedDomains), len(r.cache))
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
	// 3. pre-resolved bypass IPs (for when host is an IP literal)
	if net.ParseIP(h) != nil {
		r.mu.RLock()
		hit := r.bypassIPs[h]
		r.mu.RUnlock()
		if hit {
			return VerdictBypass
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

// probeOne attempts a direct TCP connect with short timeout. Outcomes:
//   - probe SUCCESS only caches BYPASS if host is a hostname (not IP literal).
//     IPs are unsafe to bypass-by-probe because Google/CF/Akamai shared CDN
//     IPs serve both blocked and non-blocked services (TCP-OK ≠ "safe to use
//     direct" — DPI shapes at TLS-SNI layer, not TCP). Phase 2 DNS hijack
//     ensures we always see hostname here, so bypass-learning is safe.
//   - probe FAILURE always caches TUNNEL (TCP-unreachable from RU = certainly
//     not bypass-able; route via tunnel).
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

	isIPLiteral := net.ParseIP(req.host) != nil
	var v Verdict
	var ttl time.Duration
	if err == nil {
		conn.Close()
		if isIPLiteral {
			// TCP-OK to a raw IP doesn't prove the service behind it is safe
			// to bypass — skip caching, route via tunnel.
			log.Printf("router: probe %s:%d → tcp-ok but IP-literal (no bypass-learn) — tunnel default", req.host, req.port)
			return
		}
		v, ttl = VerdictBypass, bypassCacheTTL
	} else {
		v, ttl = VerdictTunnel, tunnelCacheTTL
	}
	r.mu.Lock()
	r.cache[req.host] = cacheEntry{V: v, Expires: time.Now().Add(ttl)}
	r.mu.Unlock()
	log.Printf("router: probe %s:%d → %s (ttl=%v err=%v)", req.host, req.port, v, ttl, err)
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
