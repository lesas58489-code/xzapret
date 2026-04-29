// High-level Client: pool + SOCKS5 listener + tun2socks orchestration.
// Exported from this package so the mobile/android.go wrapper can drive it.

package xzapcore

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lesas58489-code/xzapret/core/go/transport"
)

// ClientConfig is the fully parsed runtime configuration.
type ClientConfig struct {
	ServerHost string // "151.244.111.186" or "solar-cloud.xyz"
	ServerPort int    // TCP port for direct TLS transport (ignored for WS)
	KeyB64     string // AES-256 key, base64
	Transport  string // "tls" or "ws"
	WSUrl      string // required when Transport=="ws", e.g. "wss://solar-cloud.xyz/ws"
	TLSProfile string // "chrome131" (default), "chrome120", "firefox120", "safari16", "random"
	LocalSocks string // "127.0.0.1:10808"
	CacheDir   string // app private cache dir for router cache, RTT history, etc.
	// WSFallbackUrl is a Cloudflare-Worker-fronted WSS endpoint used when
	// direct TCP to all servers fails with "connection refused" / "network
	// is unreachable" — typical of RU regional whitelist mode (drone alert,
	// regional emergency). The Worker exits via CF backbone, bypassing TSPU.
	// Empty = fallback disabled.
	WSFallbackUrl string
	// PrivateDNSMode is read from Android Settings.Global.private_dns_mode by Kotlin
	// and passed in here. Values: "off" | "opportunistic" | "hostname" | "" (unknown).
	// When "opportunistic" we block DoT (TCP/853) so Android falls back to plain DNS
	// over UDP/53, which our DNS hijack handles. Other modes: no blocking.
	PrivateDNSMode string
}

// Client is the stateful XZAP client singleton.
type Client struct {
	cfg    ClientConfig
	cryp   *Crypto
	pool   *Pool
	socks  *socksServer
	decoy  *DecoyManager
	router    *Router
	startedAt time.Time
	mu        sync.Mutex
	up        bool

	// warmupDone flips to true once the pool's warmup goroutine has finished
	// kicking off all initial tunnels. The dialer uses this to switch from
	// the "warmup-only" server subset (non-deferred) to the full set.
	// Pointer-shared with PoolConfig.WarmupDone so Pool can flip it.
	warmupDone *atomic.Bool

	// rttMu protects rtts. rtts[host:port] = most-recent successful dial duration.
	// Used for smart-priority: prefer fastest server first on cold-start.
	rttMu sync.Mutex
	rtts  map[string]time.Duration
}

func (c *Client) recordRTT(s hostPort, dt time.Duration) {
	c.rttMu.Lock()
	defer c.rttMu.Unlock()
	if c.rtts == nil {
		c.rtts = make(map[string]time.Duration)
	}
	c.rtts[fmt.Sprintf("%s:%d", s.host, s.port)] = dt
}

// ServerRTTs returns a JSON object {host:port → milliseconds} of the most
// recent successful dial duration per server. Caller (Kotlin) persists this
// across app restarts via SharedPreferences and uses it to order the servers
// list passed to Start() so cold-start dials hit the fastest server first.
func (c *Client) ServerRTTs() string {
	c.rttMu.Lock()
	defer c.rttMu.Unlock()
	if len(c.rtts) == 0 {
		return "{}"
	}
	out := "{"
	first := true
	for k, v := range c.rtts {
		if !first {
			out += ","
		}
		first = false
		out += fmt.Sprintf("%q:%d", k, v.Milliseconds())
	}
	out += "}"
	return out
}

// NewClient validates config and sets up internal components (does not start them).
func NewClient(cfg ClientConfig) (*Client, error) {
	keyBytes, err := base64.StdEncoding.DecodeString(cfg.KeyB64)
	if err != nil {
		return nil, fmt.Errorf("config: key decode: %w", err)
	}
	cryp, err := NewCrypto(keyBytes)
	if err != nil {
		return nil, err
	}
	if cfg.LocalSocks == "" {
		cfg.LocalSocks = "127.0.0.1:10808"
	}
	return &Client{cfg: cfg, cryp: cryp, warmupDone: &atomic.Bool{}}, nil
}

// Start warms the tunnel pool and opens the local SOCKS5 listener.
// Returns error if SOCKS bind fails. Tunnel dial errors are logged but
// do not block start (retried continuously).
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.up {
		return fmt.Errorf("client already started")
	}

	dialer := c.makeDialer()
	poolCfg := DefaultPoolConfig(c.cryp, dialer)
	poolCfg.WarmupDone = c.warmupDone
	log.Printf("pool cfg: maxTunnels=%d maxAge=%v retireGrace=%v rotateEvery=%v warmupDelay=%v",
		poolCfg.MaxTunnels, poolCfg.MaxAge, poolCfg.RetireGrace, poolCfg.RotateEvery, poolCfg.WarmupDelay)
	c.pool = NewPool(poolCfg)
	c.pool.Start()

	ln, err := net.Listen("tcp", c.cfg.LocalSocks)
	if err != nil {
		c.pool.Stop()
		c.pool = nil
		return fmt.Errorf("SOCKS5 listen %s: %w", c.cfg.LocalSocks, err)
	}
	// Router decides per-connection: bypass tunnel (direct dial from our
	// process, mimo VpnService) or route through mux. Cache file lives in
	// app cache dir (passed by Kotlin via CacheDir).
	// v2 — TLS-level probe replaces TCP-only. Old "v1" cache file is left
	// behind (will be GC'd when user clears cache); we start fresh because
	// v1 hostnames cached as bypass via TCP-only probe (e.g. youtubei.googleapis.com)
	// are now known to fail at TLS layer.
	cachePath := ""
	if c.cfg.CacheDir != "" {
		cachePath = filepath.Join(c.cfg.CacheDir, "router_cache_v2.json")
	}
	c.router = NewRouter(cachePath)
	c.socks = newSocksServer(ln, c.pool)
	c.socks.router = c.router
	// DNS hijack: fake-IP responses → SOCKS5 CONNECT recovers hostname →
	// router decides per-domain (Phase 2). All-domain routing safety.
	c.socks.dns = NewDNSServer()
	// If Android Private DNS = "opportunistic" (Automatic, with fallback),
	// block DoT to force fallback to plain UDP/53 → our hijack catches it.
	c.socks.blockDoT = c.cfg.PrivateDNSMode == "opportunistic"
	if c.socks.blockDoT {
		log.Print("socks5: DoT blocking enabled (Private DNS = opportunistic)")
	}
	go c.socks.Run()

	// Start decoy traffic generator. Sites = whiteSNIs (bypass.txt).
	// Our process is excluded from VpnService (addDisallowedApplication),
	// so these requests bypass the tunnel and look like real browsing to DPI.
	c.decoy = NewDecoyManager(append([]string(nil), whiteSNIs...))
	c.decoy.Start()

	c.startedAt = time.Now()
	c.up = true
	log.Printf("xzap client started, SOCKS5 on %s, transport=%s", c.cfg.LocalSocks, c.cfg.Transport)
	return nil
}

// WaitReady blocks until at least one tunnel is ready or timeout.
func (c *Client) WaitReady(timeoutSec int) bool {
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()
	if pool == nil {
		return false
	}
	return pool.Ready(time.Duration(timeoutSec) * time.Second)
}

// Stats returns a JSON snapshot of pool state for the UI.
//   active:      tunnels currently alive AND not retiring
//   total:       all tunnel slots in pool (alive + retiring)
//   avg_rtt_ms:  average of last-successful-dial RTT across known servers
//   uptime_sec:  seconds since Client.Start succeeded
func (c *Client) Stats() string {
	c.mu.Lock()
	pool := c.pool
	startedAt := c.startedAt
	c.mu.Unlock()
	active, total := 0, 0
	if pool != nil {
		active, total = pool.Stats()
	}
	avgRtt := int64(0)
	c.rttMu.Lock()
	if n := len(c.rtts); n > 0 {
		var sum time.Duration
		for _, v := range c.rtts {
			sum += v
		}
		avgRtt = (sum / time.Duration(n)).Milliseconds()
	}
	c.rttMu.Unlock()
	uptime := int64(0)
	if !startedAt.IsZero() {
		uptime = int64(time.Since(startedAt).Seconds())
	}
	return fmt.Sprintf(`{"active":%d,"total":%d,"avg_rtt_ms":%d,"uptime_sec":%d}`,
		active, total, avgRtt, uptime)
}

// OnNetworkChanged signals that the underlying network has switched
// (cellular ↔ Wi-Fi, etc). Forces all current tunnels to close so pool
// rebuilds on the new interface — without waiting for PING timeouts.
func (c *Client) OnNetworkChanged() {
	c.mu.Lock()
	pool := c.pool
	c.mu.Unlock()
	if pool == nil {
		return
	}
	pool.KillAll()
}

// Stop tears everything down.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.up {
		return
	}
	if c.decoy != nil {
		c.decoy.Stop()
		c.decoy = nil
	}
	if c.router != nil {
		c.router.Stop()
		c.router = nil
	}
	if c.socks != nil {
		c.socks.Stop()
		c.socks = nil
	}
	if c.pool != nil {
		c.pool.Stop()
		c.pool = nil
	}
	c.up = false
	log.Print("xzap client stopped")
}

// hostPort represents a single relay endpoint.
//   deferred=true means "not part of warmup pool; only joins steady-state
//   rotation after warmup completes" — useful for slow/distant servers
//   (e.g. Tokyo from Russia) so cold-start hits the fast ones first.
type hostPort struct {
	host     string
	port     int
	deferred bool
}

// parseServers splits comma-separated "host" or "host:port" entries.
// Each entry without an explicit port falls back to defaultPort. Whitespace
// around commas is trimmed. A "!" prefix marks the server as deferred — it
// is excluded from warmup and only used in steady-state rotation.
// Returns at least one entry (default if empty).
func parseServers(spec string, defaultPort int) []hostPort {
	out := []hostPort{}
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		deferred := false
		if strings.HasPrefix(entry, "!") {
			deferred = true
			entry = strings.TrimSpace(strings.TrimPrefix(entry, "!"))
			if entry == "" {
				continue
			}
		}
		// IPv4 / domain "host" or "host:port"
		if i := strings.LastIndex(entry, ":"); i > 0 && !strings.Contains(entry, "::") {
			h := entry[:i]
			p, err := strconv.Atoi(entry[i+1:])
			if err == nil && p > 0 && p < 65536 {
				out = append(out, hostPort{host: h, port: p, deferred: deferred})
				continue
			}
		}
		out = append(out, hostPort{host: entry, port: defaultPort, deferred: deferred})
	}
	if len(out) == 0 {
		out = append(out, hostPort{host: spec, port: defaultPort})
	}
	return out
}

// makeDialer builds a TransportDialer according to config. Multi-server:
// ServerHost may be comma-separated. Each call round-robins through the
// list. Pool warmup creates 6 tunnels staggered, so each server gets
// roughly equal share without parallel cold-start burst.
func (c *Client) makeDialer() TransportDialer {
	switch c.cfg.Transport {
	case "ws":
		wsUrl := c.cfg.WSUrl
		return func(ctx context.Context) (ReaderWriterCloser, error) {
			return transport.DialWS(ctx, wsUrl)
		}
	default: // "tls"
		servers := parseServers(c.cfg.ServerHost, c.cfg.ServerPort)
		profile := parseProfile(c.cfg.TLSProfile)
		// Split into warmup-eligible (non-deferred) and full lists. During
		// warmup we only dial non-deferred servers. After warmup completes
		// (Pool sets warmupDone=true) we use the full list for replacements.
		// Caller can mark a server with "!" prefix in ServerHost to defer it.
		warmupServers := []hostPort{}
		for _, s := range servers {
			if !s.deferred {
				warmupServers = append(warmupServers, s)
			}
		}
		if len(warmupServers) == 0 {
			// All deferred? Fall back to using all — better than no servers.
			warmupServers = servers
			log.Printf("makeDialer: all servers marked deferred — fallback to full set for warmup too")
		}
		log.Printf("makeDialer: warmup-set=%v full-set=%v fallback=%q", warmupServers, servers, c.cfg.WSFallbackUrl)
		var counter atomic.Uint64
		warmupDone := c.warmupDone
		// Sliding window of last N dial outcomes for whitelist-mode detection.
		// If most recent dials all failed with refused/unreachable → switch
		// to WSS fallback URL (CF Worker fronting our backend over CF backbone).
		var refusedMu sync.Mutex
		var refusedRing []bool   // true = "refused/unreachable", false = "ok or other"
		const refusedWindow = 8  // observe last 8 outcomes
		const refusedThresh = 6  // 6+ refused → enter fallback mode
		return func(ctx context.Context) (ReaderWriterCloser, error) {
			// Decide if whitelist-mode is suspected.
			refusedMu.Lock()
			suspected := false
			if c.cfg.WSFallbackUrl != "" && len(refusedRing) >= refusedWindow {
				cnt := 0
				for _, r := range refusedRing {
					if r {
						cnt++
					}
				}
				if cnt >= refusedThresh {
					suspected = true
				}
			}
			refusedMu.Unlock()

			if suspected {
				log.Printf("makeDialer: whitelist-mode suspected (%d refused in last %d) → WSS fallback %s",
					refusedThresh, refusedWindow, c.cfg.WSFallbackUrl)
				conn, err := transport.DialWS(ctx, c.cfg.WSFallbackUrl)
				if err == nil {
					return conn, nil
				}
				log.Printf("makeDialer: WSS fallback also failed: %v — falling through to direct dial", err)
				// drop through to normal direct dial
			}

			pool := warmupServers
			if warmupDone.Load() {
				pool = servers
			}
			i := counter.Add(1) - 1
			s := pool[i%uint64(len(pool))]
			sni := randomWhiteSNI()
			persona, personaName := pickPersonality()
			phase := "warmup"
			if warmupDone.Load() {
				phase = "steady"
			}
			log.Printf("makeDialer: dial phase=%s server=%s sni=%s persona=%s", phase, s.host, sni, personaName)
			start := time.Now()
			conn, err := transport.DialTLSWithChaff(ctx, s.host, s.port, sni, profile, persona)
			refused := err != nil && (strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "network is unreachable"))
			refusedMu.Lock()
			refusedRing = append(refusedRing, refused)
			if len(refusedRing) > refusedWindow {
				refusedRing = refusedRing[len(refusedRing)-refusedWindow:]
			}
			refusedMu.Unlock()
			if err != nil {
				return nil, err
			}
			c.recordRTT(s, time.Since(start))
			return conn, nil
		}
	}
}

func parseProfile(s string) transport.TLSProfile {
	switch s {
	case "chrome120":
		return transport.ProfileChrome120
	case "firefox120":
		return transport.ProfileFirefox120
	case "safari16":
		return transport.ProfileSafari16
	case "random":
		return transport.ProfileRandomized
	default:
		return transport.ProfileChrome131
	}
}

// SNI rotation — Russian sites that pass DPI inspection regardless of
// destination IP. Server still serves LE cert for direct.solar-cloud.xyz
// (cert/SNI mismatch is OK because client uses InsecureSkipVerify).
// Tradeoff vs single direct.solar-cloud.xyz SNI:
//   - Pro: more variety, harder for DPI to fingerprint single SNI
//   - Con: cert mismatch visible to TLS-inspecting DPI
// Reverted from single-SNI 815f3e5 because user reports "тишина" with it.
var whiteSNIs = []string{
	"vk.com",
	"ok.ru",
	"yandex.ru",
	"yandex.net",
	"mail.ru",
	"rambler.ru",
	"avito.ru",
	"sberbank.ru",
	"gosuslugi.ru",
	"mos.ru",
	"rbc.ru",
	"lenta.ru",
	"ria.ru",
	"rt.com",
	"tinkoff.ru",
	"ozon.ru",
	"wildberries.ru",
	"kinopoisk.ru",
	"2gis.ru",
	"dzen.ru",
}

func randomWhiteSNI() string {
	return whiteSNIs[rand.Intn(len(whiteSNIs))]
}

// Personality presets for chaff-shaping per tunnel. Each tunnel gets a
// random one at dial time so DPI sees a mix of "browsing" / "video" /
// "download" traffic shapes across the pool, rather than 6 identical flows.
//   - browsing: 40% chaff chance, 3-10% size — bursty mixed pattern (default)
//   - video:    20% chaff chance, 5-15% size — steady streaming, larger chunks
//   - download: 10% chaff chance, 1-3% size — minimal overhead, mostly bulk
var personalityPresets = []struct {
	name   string
	params transport.ChaffParams
}{
	{"browsing", transport.ChaffParams{Chance: 0.40, PctMin: 0.03, PctMax: 0.10}},
	{"video", transport.ChaffParams{Chance: 0.20, PctMin: 0.05, PctMax: 0.15}},
	{"download", transport.ChaffParams{Chance: 0.10, PctMin: 0.01, PctMax: 0.03}},
}

// pickPersonality returns a random (params, name) pair. Equal-weight choice
// across the three presets — keep it simple, can tune the distribution later.
func pickPersonality() (transport.ChaffParams, string) {
	p := personalityPresets[rand.Intn(len(personalityPresets))]
	return p.params, p.name
}

