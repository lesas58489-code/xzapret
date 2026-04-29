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
	Crypto           *Crypto
	Dialer           TransportDialer
	MaxTunnels       int           // steady-state pool size
	MaxAge           time.Duration // proactively retire tunnels older than this
	MaxBytes         int64         // retire after this many payload bytes (jittered ±50%)
	MaxStreams       uint32        // retire after this many streams opened (jittered ±50%)
	RetireMaxActive  int           // smart-retire: skip tunnel if active streams > this (avoid force-close mid-video)
	RetireGrace      time.Duration // grace period before closing a retired tunnel
	RotateEvery      time.Duration // rotator check interval
	WarmupDelay      time.Duration // ignore rotation during this initial window
	StreamDialTO     time.Duration // timeout for each stream open
	// WarmupDone is flipped to true once warmup() finishes scheduling all
	// initial dials. Shared with Client so makeDialer() can switch from
	// warmup-set (non-deferred servers) to full set. Optional — if nil,
	// no phase distinction is made.
	WarmupDone       *atomic.Bool
}

func DefaultPoolConfig(c *Crypto, d TransportDialer) PoolConfig {
	return PoolConfig{
		Crypto:     c,
		Dialer:     d,
		MaxTunnels: 6,
		// Reverted Phase A (60s/30s rotation). Aggressive rotation didn't
		// reduce user-visible hangs and high ctx.Done counts indicated pool
		// churn (12 dial fails, 12 tunnel EXITs) was actually hurting stability
		// rather than helping. Connection-lifetime improvement also evaporated
		// once RetireGrace was raised to 120s to avoid force-closing streams
		// — TCP flow lifetime ended up the same as pre-rotation.
		MaxAge:          10 * time.Minute,
		MaxBytes:        50 * 1024 * 1024, // 50 MB base, jittered → 25-75 MB per tunnel
		MaxStreams:      120,              // 120 base, jittered → 60-180 per tunnel
		RetireMaxActive: 5,                 // skip retire if more than 5 active streams (avoid mid-video kills)
		RetireGrace:     180 * time.Second, // graceful drain — long-lived TCP (Telegram MTProto, WebSocket, video) needs minutes to migrate cleanly
		RotateEvery:     30 * time.Second,
		WarmupDelay:     2 * time.Minute,
		StreamDialTO:    10 * time.Second,
	}
}

type pooledTunnel struct {
	t          *MuxTunnel
	maxAge     time.Duration // per-tunnel jittered lifetime
	maxBytes   int64         // per-tunnel jittered byte budget
	maxStreams uint32        // per-tunnel jittered stream budget
	retiring   bool
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

// Stats returns current pool counts and lifetime byte totals.
// Used by Mobile.Stats() → UI for SwarmChip + throughput display.
func (p *Pool) Stats() (active, total int, bytesIn, bytesOut int64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	total = len(p.items)
	for _, it := range p.items {
		if it.t.IsAlive() && !it.retiring {
			active++
		}
		bytesIn += it.t.BytesIn()
		bytesOut += it.t.BytesOut()
	}
	return
}

// KillAll closes every existing tunnel and clears the pool. Used when the
// underlying network changes (cellular ↔ Wi-Fi switch) — the prior tunnels'
// TCP sockets were bound to the old source IP and are now zombie connections
// that pick() would still treat as alive until PING/PONG eventually fails
// (~30s). KillAll forces immediate reconstruction on the new network.
// Pool keeps running; pick() will trigger createOne for replacements.
func (p *Pool) KillAll() {
	p.mu.Lock()
	items := p.items
	p.items = nil
	p.mu.Unlock()
	for _, it := range items {
		it.t.Close()
	}
	log.Printf("pool: KillAll — closed %d tunnels (network change)", len(items))
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
	const maxAttempts = 3
	for attempt := 0; attempt < maxAttempts; attempt++ {
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
		// Per-attempt timeout. First attempt gets half the remaining budget
		// (so a healthy-slow handshake of 2-4s isn't killed prematurely),
		// retries split the rest. Bounded [500ms, 6s].
		// Earlier "remaining/attemptsLeft" was too aggressive on first try
		// — 10s caller / 3 attempts = 3.33s killed legitimate slow handshakes
		// instead of just sick ones.
		remaining := time.Until(deadlineOrFar(ctx))
		var perAttempt time.Duration
		if attempt == 0 {
			perAttempt = remaining / 2
		} else {
			perAttempt = remaining / time.Duration(maxAttempts-attempt)
		}
		if perAttempt > 6*time.Second {
			perAttempt = 6 * time.Second
		}
		if perAttempt < 500*time.Millisecond {
			perAttempt = 500 * time.Millisecond
		}
		subCtx, cancel := context.WithTimeout(ctx, perAttempt)
		stream, err := t.OpenStream(subCtx, host, port)
		cancel()
		if err == nil {
			return stream, nil
		}
		// retry with fresh tunnel — current one likely sick or dead.
		// pick() will already deprioritize the one that just timed out
		// (its health window now has a fresh outcomeTimeout entry).
	}
	return nil, fmt.Errorf("pool: could not open stream to %s:%d", host, port)
}

// deadlineOrFar returns ctx's deadline, or a far-future time if no deadline.
func deadlineOrFar(ctx context.Context) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(30 * time.Second)
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
	// Pick: prefer healthy non-retiring tunnels first. Within that set, pick
	// least-loaded. If all healthy are retiring or no healthy exist, fall
	// back to any non-retiring alive (even if sick — better than nothing).
	// "Sick" = mostly timeouts/failures recently → DPI is shaping this tunnel,
	// keep streams off it so user gets quick failover to healthier siblings.
	var best *MuxTunnel
	bestLoad := 1 << 30
	for _, it := range p.items {
		if it.retiring || it.t.IsSick() {
			continue
		}
		load := it.t.StreamCount()
		if load < bestLoad {
			bestLoad = load
			best = it.t
		}
	}
	if best == nil {
		// No healthy non-retiring; try any non-retiring (sick included).
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
	// Cold start: under Megafon DPI shaping, single sequential dial can
	// take 10-15s before getting first tunnel (every TLS handshake hits
	// 3s timeout). User waits with empty pool, app says "connecting".
	//
	// Compromise: launch TWO parallel dials for the first tunnel only.
	// Two is the limit per CLAUDE.md observation that 3+ parallel triggers
	// DPI burst-detection. After one succeeds, the second's success (if
	// any) just adds to the pool early — net positive.
	go p.createOne()
	go p.createOne()
	// Slow-fill the rest at the original cadence
	for i := 2; i < p.cfg.MaxTunnels; i++ {
		select {
		case <-p.quit:
			return
		case <-time.After(time.Duration(i-1)*3*time.Second + jitter(2*time.Second)):
			go p.createOne()
		}
	}
	// Warmup is done — flip the flag so dialer starts using deferred servers.
	if p.cfg.WarmupDone != nil {
		p.cfg.WarmupDone.Store(true)
		log.Printf("pool: warmup complete, deferred servers now eligible for dial")
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
		// Cold start under Megafon DPI shaping: TLS handshake reads can
		// legitimately take 3-4s before middlebox lets bytes through.
		// 3s timeout was killing valid handshakes; 5s gives DPI time to
		// "decide". Retry rotates to next server (Dialer counter increments).
		dialTO = 5 * time.Second
		attempts = 3
		backoff = 300 * time.Millisecond
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
		// Jitter all three rotation budgets per tunnel: ~[0.5×, 1.5×] of base.
		// Spreads rotations across time/bytes/streams so DPI can't fingerprint
		// any one regular cycle. Each tunnel hits whichever threshold first.
		jAge := 0.5 + rand.Float64()
		jBytes := 0.5 + rand.Float64()
		jStreams := 0.5 + rand.Float64()
		jMaxAge := time.Duration(float64(p.cfg.MaxAge) * jAge)
		jMaxBytes := int64(float64(p.cfg.MaxBytes) * jBytes)
		jMaxStreams := uint32(float64(p.cfg.MaxStreams) * jStreams)
		p.mu.Lock()
		p.items = append(p.items, &pooledTunnel{
			t:          t,
			maxAge:     jMaxAge,
			maxBytes:   jMaxBytes,
			maxStreams: jMaxStreams,
		})
		p.mu.Unlock()
		log.Printf("pool: tunnel created, budgets: age=%v bytes=%dMB streams=%d",
			jMaxAge, jMaxBytes>>20, jMaxStreams)
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
		// Smart-retire algorithm:
		//   1. Find tunnels that have exceeded ANY budget (age/bytes/streams).
		//   2. Among those, prefer the one with the FEWEST active streams
		//      so we don't force-close 10 active streams mid-video.
		//   3. If even the best candidate has too many active streams (>RetireMaxActive),
		//      skip this tick entirely UNLESS some tunnel is "far overdue"
		//      (age > 2× its budget) — then force-retire the most-overdue one
		//      to bound how long a busy tunnel can resist retirement.
		var victim, fallback *pooledTunnel
		var reason string
		var victimAge time.Duration
		var victimBytes int64
		var victimStreams uint32
		var victimActive int
		var fallbackAge time.Duration
		for _, it := range p.items {
			if !it.t.IsAlive() || it.retiring {
				continue
			}
			age := time.Since(it.t.createdAt)
			bytes := it.t.BytesOut()
			streams := it.t.StreamsCreated()
			active := it.t.StreamCount()
			var r string
			switch {
			case it.t.IsSick():
				r = "sick" // DPI throttle / SYN_ACKs not arriving
			case age >= it.maxAge:
				r = "age"
			case bytes >= it.maxBytes:
				r = "bytes"
			case streams >= it.maxStreams:
				r = "streams"
			default:
				continue // not over any budget and not sick
			}
			// Hard-ceiling: tunnel is way past its budget — keep as fallback
			// in case we can't find a low-active-streams candidate this tick.
			if age > 2*it.maxAge && (fallback == nil || age > fallbackAge) {
				fallback = it
				fallbackAge = age
			}
			// Smart pick: only consider candidates with low active stream count.
			if active <= p.cfg.RetireMaxActive {
				if victim == nil || active < victimActive {
					victim, reason = it, r
					victimAge, victimBytes, victimStreams, victimActive = age, bytes, streams, active
				}
			}
		}
		if victim == nil && fallback != nil {
			// All over-budget tunnels are heavily used. Force-retire the most
			// overdue one (age > 2× budget) to keep rotation moving.
			victim = fallback
			reason = "force-overdue"
			victimAge = time.Since(fallback.t.createdAt)
			victimBytes = fallback.t.BytesOut()
			victimStreams = fallback.t.StreamsCreated()
			victimActive = fallback.t.StreamCount()
		}
		if victim == nil {
			log.Printf("rotator: fresh=%d no eligible victim (over-budget tunnels too busy, none far-overdue) — skip", freshCount)
			p.mu.Unlock()
			continue
		}
		victim.retiring = true
		target := victim.t
		budgets := fmt.Sprintf("maxAge=%v maxBytes=%dMB maxStreams=%d", victim.maxAge, victim.maxBytes>>20, victim.maxStreams)
		p.mu.Unlock()
		log.Printf("pool: retiring tunnel reason=%s age=%v bytes=%dMB streams-created=%d active=%d (%s)",
			reason, victimAge.Round(time.Second), victimBytes>>20, victimStreams, victimActive, budgets)
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
