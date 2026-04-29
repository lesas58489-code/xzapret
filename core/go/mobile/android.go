// Android-facing Go API. gomobile bind produces an AAR from this
// package; Kotlin code calls these exported functions.
//
// API surface is kept minimal and primitive-typed because gomobile
// does not support arbitrary Go types across the JNI boundary.

package mobile

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"

	xzapcore "github.com/lesas58489-code/xzapret/core/go"
	t2s "github.com/xjasonlyu/tun2socks/v2/engine"
)

var (
	mu      sync.Mutex
	client  *xzapcore.Client
	engineK *t2s.Key
	running bool
)

// startConfigJSON is the JSON contract between Kotlin and Go:
//
//	{
//	  "server_host": "151.244.111.186",
//	  "server_port": 8443,
//	  "key_b64":     "<base64>",
//	  "transport":   "tls" | "ws",
//	  "ws_url":      "wss://solar-cloud.xyz/ws",   // when transport=="ws"
//	  "tls_profile": "chrome131"|"chrome120"|"firefox120"|"safari16"|"random",
//	  "socks_port":  10808,
//	  "tun_fd":      42,        // from VpnService.establish()
//	  "mtu":         1500,
//	  "log_level":   "info"
//	}
type startConfig struct {
	ServerHost string `json:"server_host"`
	ServerPort int    `json:"server_port"`
	KeyB64     string `json:"key_b64"`
	Transport  string `json:"transport"`
	WSUrl      string `json:"ws_url"`
	TLSProfile string `json:"tls_profile"`
	SocksPort  int    `json:"socks_port"`
	TunFD      int    `json:"tun_fd"`
	MTU        int    `json:"mtu"`
	LogLevel       string `json:"log_level"`
	CacheDir       string `json:"cache_dir"`
	PrivateDNSMode string `json:"private_dns_mode"` // "off"|"opportunistic"|"hostname"|""
	WSFallbackUrl  string `json:"ws_fallback_url"`  // CF Worker URL for whitelist-mode fallback
}

// Start launches the XZAP client and, if TunFD>0, hooks up tun2socks
// to route TUN packets into our SOCKS5 listener.
// Returns "" on success, non-empty error string otherwise.
func Start(configJSON string) string {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return "already running"
	}
	var cfg startConfig
	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
		return fmt.Sprintf("config parse: %v", err)
	}
	if cfg.SocksPort == 0 {
		cfg.SocksPort = 10808
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1500
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "warn"
	}
	// Normalise tun2socks log level names (it expects warn/info/debug/error, not 'warning')
	switch cfg.LogLevel {
	case "warning":
		cfg.LogLevel = "warn"
	}

	c, err := xzapcore.NewClient(xzapcore.ClientConfig{
		ServerHost: cfg.ServerHost,
		ServerPort: cfg.ServerPort,
		KeyB64:     cfg.KeyB64,
		Transport:  cfg.Transport,
		WSUrl:      cfg.WSUrl,
		TLSProfile: cfg.TLSProfile,
		LocalSocks:     fmt.Sprintf("127.0.0.1:%d", cfg.SocksPort),
		CacheDir:       cfg.CacheDir,
		PrivateDNSMode: cfg.PrivateDNSMode,
		WSFallbackUrl:  cfg.WSFallbackUrl,
	})
	if err != nil {
		return fmt.Sprintf("client init: %v", err)
	}
	if err := c.Start(); err != nil {
		return fmt.Sprintf("client start: %v", err)
	}

	if cfg.TunFD > 0 {
		k := &t2s.Key{}
		k.Mark = 0
		k.MTU = cfg.MTU
		k.Device = fmt.Sprintf("fd://%d", cfg.TunFD)
		k.Proxy = fmt.Sprintf("socks5://127.0.0.1:%d", cfg.SocksPort)
		k.LogLevel = cfg.LogLevel
		t2s.Insert(k)
		t2s.Start()
		engineK = k
	}

	client = c
	running = true
	log.Print("[xzapcore] started")
	return ""
}

// WaitReady blocks up to timeoutSec for at least one tunnel to be ready.
// Returns true on success.
func WaitReady(timeoutSec int) bool {
	mu.Lock()
	c := client
	mu.Unlock()
	if c == nil {
		return false
	}
	return c.WaitReady(timeoutSec)
}

// Stop tears down tun2socks and the XZAP client.
func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	if engineK != nil {
		t2s.Stop()
		engineK = nil
	}
	if client != nil {
		client.Stop()
		client = nil
	}
	running = false
	log.Print("[xzapcore] stopped")
}

// NetworkChanged is called by Kotlin's ConnectivityManager.NetworkCallback
// when the device's underlying network switches (cellular ↔ Wi-Fi).
// Triggers pool.KillAll so tunnels reconstruct on the new interface
// instead of waiting for PING timeouts (~30s) on now-zombie sockets.
func NetworkChanged() {
	mu.Lock()
	c := client
	mu.Unlock()
	if c == nil {
		return
	}
	c.OnNetworkChanged()
}

// IsRunning reports current state.
func IsRunning() bool {
	mu.Lock()
	defer mu.Unlock()
	return running
}

// ServerRTTs returns a JSON map {host:port → milliseconds} of the most-recent
// successful dial duration per server. Caller (Kotlin) should call this on
// Stop(), persist to SharedPreferences, and on next Start() pre-sort the
// comma-separated server list (fastest first) before passing to Start().
// Returns "{}" if no data yet.
func ServerRTTs() string {
	mu.Lock()
	c := client
	mu.Unlock()
	if c == nil {
		return "{}"
	}
	return c.ServerRTTs()
}
