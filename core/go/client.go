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
	"sync"
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
}

// Client is the stateful XZAP client singleton.
type Client struct {
	cfg   ClientConfig
	cryp  *Crypto
	pool  *Pool
	socks *socksServer
	mu    sync.Mutex
	up    bool
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
	return &Client{cfg: cfg, cryp: cryp}, nil
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
	c.socks = newSocksServer(ln, c.pool)
	go c.socks.Run()
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

// Stop tears everything down.
func (c *Client) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.up {
		return
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

// makeDialer builds a TransportDialer according to config.
func (c *Client) makeDialer() TransportDialer {
	switch c.cfg.Transport {
	case "ws":
		wsUrl := c.cfg.WSUrl
		return func(ctx context.Context) (ReaderWriterCloser, error) {
			return transport.DialWS(ctx, wsUrl)
		}
	default: // "tls"
		host := c.cfg.ServerHost
		port := c.cfg.ServerPort
		profile := parseProfile(c.cfg.TLSProfile)
		return func(ctx context.Context) (ReaderWriterCloser, error) {
			sni := randomWhiteSNI()
			conn, err := transport.DialTLS(ctx, host, port, sni, profile)
			if err != nil {
				return nil, err
			}
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

