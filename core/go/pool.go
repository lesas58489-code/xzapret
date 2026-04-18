// Pool manages a small set of persistent mux tunnels, rotating them
// proactively before DPI kills them and eagerly replacing dead ones.

package xzapcore

import (
	"context"
	"fmt"
	"log"
	"math/rand"
	"sync"
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
		Crypto:       c,
		Dialer:       d,
		MaxTunnels:   3,
		MaxAge:       30 * time.Second,
		RetireGrace:  8 * time.Second,
		RotateEvery:  5 * time.Second,
		WarmupDelay:  40 * time.Second,
		StreamDialTO: 10 * time.Second,
	}
}

type pooledTunnel struct {
	t        *MuxTunnel
	retiring bool
}

type Pool struct {
	cfg    PoolConfig
	mu     sync.Mutex
	items  []*pooledTunnel
	crea   int // tunnels being created
	ready  chan struct{}
	once   sync.Once
	quit   chan struct{}
	startT time.Time
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
func (p *Pool) OpenStream(ctx context.Context, host string, port int) (*muxStream, error) {
	for attempt := 0; attempt < 2; attempt++ {
		t := p.pick()
		if t == nil {
			time.Sleep(200 * time.Millisecond)
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
	// Missing? Kick background creation
	needed := p.cfg.MaxTunnels - len(p.items) - p.crea
	for i := 0; i < needed; i++ {
		delay := time.Duration(i) * 3 * time.Second
		go func(d time.Duration) {
			if d > 0 {
				time.Sleep(d)
			}
			p.createOne()
		}(delay)
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
	// First tunnel synchronous (signals readiness fast)
	p.createOne()
	// Rest staggered 3-5s
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
	// retry up to 2 times with short backoff (carrier sometimes RSTs bursts)
	var err error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			select {
			case <-p.quit:
				return
			case <-time.After(2*time.Second + jitter(3*time.Second)):
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
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
			continue
		}
		p.mu.Lock()
		// Count fresh
		var freshCount int
		for _, it := range p.items {
			if it.t.IsAlive() && !it.retiring {
				freshCount++
			}
		}
		if freshCount < 3 {
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
			p.mu.Unlock()
			continue
		}
		oldest.retiring = true
		target := oldest.t
		p.mu.Unlock()
		log.Printf("pool: retiring tunnel age=%s", oldestAge)
		go p.createOne()
		go func() {
			select {
			case <-p.quit:
			case <-time.After(p.cfg.RetireGrace):
			}
			target.Close()
		}()
	}
}

func jitter(max time.Duration) time.Duration {
	return time.Duration(rand.Int63n(int64(max)))
}
