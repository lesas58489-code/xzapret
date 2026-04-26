// Pool manages a small set of persistent mux tunnels, rotating them
// proactively before DPI kills them and eagerly replacing dead ones.

package xzapcore

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

// TransportDialer opens a new transport connection and returns a
// reader/writer pair plus a Closer to tear it down.
type TransportDialer func(ctx context.Context) (ReaderWriterCloser, error)

// ReaderWriterCloser is the minimum a transport must implement.
type ReaderWriterCloser interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}

type PoolConfig struct {
	Crypto       *Crypto
	Dialer       TransportDialer
	MaxTunnels   int           // steady-state pool size
	MaxAge       time.Duration // proactively retire tunnels older than this
	RetireGrace  time.Duration // grace period before closing a retired tunnel
	RotateEvery  time.Duration // rotator check interval
	WarmupDelay  time.Duration // ignore rotation during this initial window
	StreamDialTO time.Duration // timeout for each stream open
}

func DefaultPoolConfig(c *Crypto, d TransportDialer) PoolConfig {
	return PoolConfig{
		Crypto:     c,
		Dialer:     d,
		MaxTunnels: 6,
		// Phase A — browser-like connection lifetime.
		// Measurement showed our tunnels live 175-560s; browser conns live 0.5-32s.
		// MaxAge=60s rotates aggressively. Streams in flight on retiring tunnels
		// keep going (RetireGrace) so YouTube/WebSocket streams don't stutter.
		MaxAge: 60 * time.Second,
		// RetireGrace was 30s, but force-closing long-lived streams (YouTube
		// chunks, WebSocket, EventSource) caused user-visible "hangs" — browser
		// retries cost minutes. 120s gives most streams time to drain.
		RetireGrace:  120 * time.Second,
		RotateEvery:  20 * time.Second,
		WarmupDelay:  30 * time.Second,
		StreamDialTO: 10 * time.Second,
	}
}

type pooledTunnel struct {
	t        *MuxTunnel
	retiring bool
}

type Pool struct {
	cfg     PoolConfig
	mu      sync.Mutex
	items   []*pooledTunnel
	crea    int // tunnels being created
	ready   chan struct{}
	once    sync.Once
	quit    chan struct{}
	startT  time.Time
	hasOne  atomic.Bool // any tunnel ever made it (controls fast-vs-slow dial path)
}

func NewPool(cfg PoolConfig) *Pool {
	return &Pool{
		cfg:    cfg,
		ready:  make(chan struct{}),
		quit:   make(chan struct{}),
		startT: time.Now(),
	}
}

// Start spawns warmup tunnels and the rotator. Returns immediately.
func (p *Pool) Start() {
	go p.warmup()
	go p.rotator()
}

// Stop tears down all tunnels.
func (p *Pool) Stop() {
	close(p.quit)
	p.mu.Lock()
	items := p.items
	p.items = nil
	p.mu.Unlock()
	for _, it := range items {
		it.t.Close()
	}
}

// Ready blocks until at least one tunnel is ready, or timeout elapses.
func (p *Pool) Ready(timeout time.Duration) bool {
	select {
	case <-p.ready:
		return true
	case <-time.After(timeout):
		return false
	}
}

// OpenStream picks the least-loaded fresh tunnel and opens a stream.
// Blocks on first-tunnel readiness so warmup races don't nuke early requests.
func (p *Pool) OpenStream(ctx context.Context, host string, port int) (*muxStream, error) {
	// Cold pool: wait for first tunnel before trying to pick. tun2socks
	// fires requests within ~400ms of VPN up, but first WSS+mux handshake
	// needs ~600-900ms; without this wait every early request fails and
	// Chrome marks the network offline.
	select {
	case <-p.ready:
	case <-ctx.Done():
		return nil, fmt.Errorf("pool: cold (timed out waiting for first tunnel): %w", ctx.Err())
	}
	for attempt := 0; attempt < 3; attempt++ {
		t := p.pick()
		if t == nil {
			// pool had a tunnel but it died since ready was signalled; brief wait
			select {
			case <-time.After(200 * time.Millisecond):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			continue
		}
		stream, err := t.OpenStream(ctx, host, port)
		if err == nil {
			return stream, nil
		}
		// retry with fresh tunnel — current one likely died
	}
	return nil, fmt.Errorf("pool: could not open stream to %s:%d", host, port)
}

func (p *Pool) pick() *MuxTunnel {
	p.mu.Lock()
	// Drop dead
	alive := p.items[:0]
	for _, it := range p.items {
		if it.t.IsAlive() {
			alive = append(alive, it)
		}
	}
	p.items = alive
	// Missing? Kick AT MOST ONE background dial. Multiple parallel dials
	// trigger DPI burst-detection on Russian carriers; the rotator's slow-
	// fill cadence handles steady-state replenishment without burst.
	needed := p.cfg.MaxTunnels - len(p.items) - p.crea
	if needed > 0 {
		go p.createOne()
	}
	// Least-loaded fresh (non-retiring)
	var best *MuxTunnel
	bestLoad := 1 << 30
	for _, it := range p.items {
		if it.retiring {
			continue
		}
		load := it.t.StreamCount()
		if load < bestLoad {
			bestLoad = load
			best = it.t
		}
	}
	if best == nil {
		// all retiring; fall back to any alive
		for _, it := range p.items {
			best = it.t
			break
		}
	}
	p.mu.Unlock()
	return best
}

func (p *Pool) warmup() {
	// Cold start: ONE dial at a time. Parallel dial bursts trigger DPI/ISP
	// stateful filters that blackhole the destination IP for ~30s — net
	// wall-clock ends up the same as single-dial. The short cold-path
	// timeouts in createOne (5s × 3 attempts) handle flaky handshakes
	// without flooding the network.
	p.createOne()
	// Slow-fill the rest at the original cadence
	for i := 1; i < p.cfg.MaxTunnels; i++ {
		select {
		case <-p.quit:
			return
		case <-time.After(time.Duration(i)*3*time.Second + jitter(2*time.Second)):
			go p.createOne()
		}
	}
}

func (p *Pool) createOne() {
	p.mu.Lock()
	p.crea++
	p.mu.Unlock()
	defer func() {
		p.mu.Lock()
		p.crea--
		p.mu.Unlock()
	}()
	// Cold path: short timeouts, more attempts, fast retry. Once any tunnel
	// is alive, switch to longer per-attempt budget so we don't churn.
	var dialTO time.Duration
	var attempts int
	var backoff time.Duration
	if p.hasOne.Load() {
		dialTO = 15 * time.Second
		attempts = 2
		backoff = 2 * time.Second
	} else {
		dialTO = 5 * time.Second
		attempts = 3
		backoff = 500 * time.Millisecond
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			select {
			case <-p.quit:
				return
			case <-time.After(backoff + jitter(backoff)):
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), dialTO)
		conn, err2 := p.cfg.Dialer(ctx)
		cancel()
		if err2 != nil {
			err = err2
			log.Printf("pool: dial failed (attempt %d): %v", attempt+1, err2)
			continue
		}
		t, err2 := NewMuxTunnel(conn, conn, p.cfg.Crypto)
		if err2 != nil {
			conn.Close()
			err = err2
			log.Printf("pool: mux handshake failed (attempt %d): %v", attempt+1, err2)
			continue
		}
		p.mu.Lock()
		p.items = append(p.items, &pooledTunnel{t: t})
		p.mu.Unlock()
		p.hasOne.Store(true)
		p.once.Do(func() { close(p.ready) })
		return
	}
	log.Printf("pool: create failed after retries: %v", err)
}

func (p *Pool) rotator() {
	t := time.NewTicker(p.cfg.RotateEvery)
	defer t.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-t.C:
		}
		if time.Since(p.startT) < p.cfg.WarmupDelay {
			log.Printf("rotator: in warmup window (%.0fs/%.0fs), skip", time.Since(p.startT).Seconds(), p.cfg.WarmupDelay.Seconds())
			continue
		}
		p.mu.Lock()
		// Count fresh
		var freshCount, retiringCount, deadCount int
		for _, it := range p.items {
			if !it.t.IsAlive() {
				deadCount++
			} else if it.retiring {
				retiringCount++
			} else {
				freshCount++
			}
		}
		if freshCount < 3 {
			log.Printf("rotator: fresh=%d retiring=%d dead=%d items=%d, freshCount<3 skip", freshCount, retiringCount, deadCount, len(p.items))
			p.mu.Unlock()
			continue
		}
		// Find oldest fresh
		var oldest *pooledTunnel
		var oldestAge time.Duration
		for _, it := range p.items {
			if !it.t.IsAlive() || it.retiring {
				continue
			}
			age := time.Since(it.t.createdAt)
			if age > oldestAge {
				oldestAge = age
				oldest = it
			}
		}
		if oldest == nil || oldestAge < p.cfg.MaxAge {
			log.Printf("rotator: fresh=%d oldest=%v MaxAge=%v not-yet skip", freshCount, oldestAge, p.cfg.MaxAge)
			p.mu.Unlock()
			continue
		}
		oldest.retiring = true
		target := oldest.t
		p.mu.Unlock()
		log.Printf("pool: retiring tunnel age=%s streams=%d", oldestAge, target.StreamCount())
		go p.createOne()
		go func() {
			// Graceful rotation: don't close while streams are alive. Poll
			// every 2s, bounded by RetireGrace absolute timeout so a
			// stuck stream can't leak the tunnel forever.
			deadline := time.Now().Add(p.cfg.RetireGrace)
			for {
				if target.StreamCount() == 0 {
					break
				}
				if time.Now().After(deadline) {
					log.Printf("pool: RetireGrace expired with streams=%d, force-closing", target.StreamCount())
					break
				}
				select {
				case <-p.quit:
					target.Close()
					return
				case <-time.After(2 * time.Second):
				}
			}
			target.Close()
		}()
	}
}

func jitter(max time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(max)))
}
