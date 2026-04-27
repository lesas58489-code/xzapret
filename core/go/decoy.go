// Decoy connections: periodic HTTPS GETs to bypass.txt domains, originated
// from this app's process (which is excluded from VpnService via
// addDisallowedApplication). DPI sees a mix of long-lived tunnel TLS sessions
// AND short-lived sessions to legitimate Russian sites — looks like a normal
// user browsing many sites, not a single tunnel.
//
// Bandwidth-budgeted to ~10MB/hour so it doesn't eat user's mobile data.

package xzapcore

import (
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
)

const (
	decoyMinInterval  = 30 * time.Second
	decoyMaxInterval  = 120 * time.Second
	decoyBurstChance  = 0.15
	decoyBurstSizeMin = 3
	decoyBurstSizeMax = 5
	decoyBurstWindow  = 8 * time.Second
	decoyReadLimit    = 256 * 1024       // up to 256 KB per fetch
	decoyHourlyBudget = 10 * 1024 * 1024 // 10 MB/hour soft cap
	decoyHandshakeTO  = 10 * time.Second
	decoyTotalTO      = 15 * time.Second
)

var decoyUserAgent = "Mozilla/5.0 (Linux; Android 13; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36"

type DecoyManager struct {
	sites         []string
	quit          chan struct{}
	once          sync.Once
	bytesThisHour atomic.Int64
	hourStartedAt atomic.Int64 // unix nanos
}

// NewDecoyManager returns a manager that fetches random pages on bypass.txt
// sites at random intervals while running. Sites: same list as whiteSNIs.
func NewDecoyManager(sites []string) *DecoyManager {
	d := &DecoyManager{
		sites: sites,
		quit:  make(chan struct{}),
	}
	d.hourStartedAt.Store(time.Now().UnixNano())
	return d
}

func (d *DecoyManager) Start() {
	if len(d.sites) == 0 {
		log.Printf("decoy: no sites configured, disabled")
		return
	}
	go d.run()
	log.Printf("decoy: started, %d candidate sites, budget=%dMB/hour", len(d.sites), decoyHourlyBudget>>20)
}

func (d *DecoyManager) Stop() {
	d.once.Do(func() { close(d.quit) })
}

func (d *DecoyManager) run() {
	// Initial delay 5-15s so we don't fire during VPN startup burst.
	select {
	case <-d.quit:
		return
	case <-time.After(time.Duration(5+rand.Intn(10)) * time.Second):
	}
	for {
		d.maybeResetHour()
		if d.bytesThisHour.Load() < decoyHourlyBudget {
			if rand.Float64() < decoyBurstChance {
				d.runBurst()
			} else {
				d.runOne()
			}
		}
		// Random next-fire interval.
		delta := decoyMaxInterval - decoyMinInterval
		wait := decoyMinInterval + time.Duration(rand.Int63n(int64(delta)))
		select {
		case <-d.quit:
			return
		case <-time.After(wait):
		}
	}
}

func (d *DecoyManager) maybeResetHour() {
	now := time.Now().UnixNano()
	started := d.hourStartedAt.Load()
	if time.Duration(now-started) >= time.Hour {
		d.hourStartedAt.Store(now)
		d.bytesThisHour.Store(0)
	}
}

func (d *DecoyManager) runBurst() {
	n := decoyBurstSizeMin + rand.Intn(decoyBurstSizeMax-decoyBurstSizeMin+1)
	log.Printf("decoy: burst of %d", n)
	for i := 0; i < n; i++ {
		d.runOne()
		// Spread the burst within decoyBurstWindow.
		gap := decoyBurstWindow / time.Duration(n+1)
		select {
		case <-d.quit:
			return
		case <-time.After(gap):
		}
	}
}

func (d *DecoyManager) runOne() {
	site := d.sites[rand.Intn(len(d.sites))]
	n, err := d.fetchOnce(site)
	if err != nil {
		log.Printf("decoy: %s err: %v", site, err)
		return
	}
	d.bytesThisHour.Add(int64(n))
	log.Printf("decoy: GET %s ok bytes=%d hourTotal=%dKB", site, n, d.bytesThisHour.Load()>>10)
}

// fetchOnce dials site:443 with uTLS Chrome131 + real cert validation,
// sends an HTTP/1.1 GET, drains body up to decoyReadLimit. Returns bytes read.
func (d *DecoyManager) fetchOnce(site string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), decoyTotalTO)
	defer cancel()

	// Force IPv4 (some RU carriers misroute IPv6).
	addrs, err := (&net.Resolver{}).LookupIP(ctx, "ip4", site)
	if err != nil || len(addrs) == 0 {
		return 0, fmt.Errorf("resolve: %w", err)
	}
	dialer := &net.Dialer{Timeout: decoyHandshakeTO}
	raw, err := dialer.DialContext(ctx, "tcp4", fmt.Sprintf("%s:443", addrs[0].String()))
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// uTLS Chrome131 — same fingerprint as our tunnel, so DPI sees a
	// consistent device. Real cert validation via ServerName matching.
	uconn := utls.UClient(raw, &utls.Config{
		ServerName: site,
		NextProtos: []string{"h2", "http/1.1"},
	}, utls.HelloChrome_131)
	_ = uconn.SetDeadline(time.Now().Add(decoyHandshakeTO))
	if err := uconn.Handshake(); err != nil {
		return 0, fmt.Errorf("handshake: %w", err)
	}
	_ = uconn.SetDeadline(time.Now().Add(decoyTotalTO))

	path := randomPath()
	req := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n"+
			"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"+
			"Accept-Language: ru-RU,ru;q=0.9,en;q=0.8\r\n"+
			"Accept-Encoding: gzip, deflate, br\r\n"+
			"Connection: close\r\n\r\n",
		path, site, decoyUserAgent)
	if _, err := uconn.Write([]byte(req)); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	n, _ := io.Copy(io.Discard, io.LimitReader(uconn, decoyReadLimit))
	return int(n), nil
}

// randomPath returns a generic path likely to exist on most sites.
// Most of the time "/" (homepage); occasionally simple subpaths.
func randomPath() string {
	switch rand.Intn(10) {
	case 0:
		return "/news"
	case 1:
		return "/sport"
	case 2:
		return "/weather"
	default:
		return "/"
	}
}
