// XZAP mux — multiple logical streams over one XZAP tunnel.
// Wire-compatible with Kotlin client and Python server.
//
// Mux frame (as plaintext inside an XZAP frame):
//
//   [4B stream_id][1B cmd][4B payload_len][payload]
//
// Commands:
//   0x01 SYN      — open stream, payload = JSON {"host":"...","port":N}
//   0x02 SYN_ACK
//   0x03 DATA
//   0x04 FIN
//   0x05 RST
//   0x06 PING
//   0x07 PONG
//   0x08 WINDOW    — flow control credit (payload = 4B big-endian delta)
//
// Version handshake: client sends XZAP frame with plaintext {"v":"mux1"};
// server replies with same. Streams then multiplex over the tunnel.

package xzapcore

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"
)

const (
	cmdSYN     = 0x01
	cmdSYNACK  = 0x02
	cmdDATA    = 0x03
	cmdFIN     = 0x04
	cmdRST     = 0x05
	cmdPING    = 0x06
	cmdPONG    = 0x07
	cmdWINDOW  = 0x08
	muxHdrSize = 9
	controlSID = 0
	muxVersion = "mux1"

	initialWindow = 256 * 1024
	maxPayload    = 256 * 1024
)

// packMuxFrame assembles [sid|cmd|len|payload].
func packMuxFrame(sid uint32, cmd byte, payload []byte) []byte {
	out := make([]byte, muxHdrSize+len(payload))
	binary.BigEndian.PutUint32(out[0:4], sid)
	out[4] = cmd
	binary.BigEndian.PutUint32(out[5:9], uint32(len(payload)))
	copy(out[9:], payload)
	return out
}

// MuxConn is a duplex byte stream multiplexed over one XZAP tunnel.
type MuxConn interface {
	io.ReadWriteCloser
}

// MuxTunnel manages one underlying XZAP frame transport and dispatches
// mux frames to MuxStream instances.
type MuxTunnel struct {
	r io.Reader
	w io.Writer
	c *Crypto

	writeMu sync.Mutex

	streamsMu    sync.Mutex
	streams      map[uint32]*muxStream
	nextStreamID uint32

	alive int32 // atomic bool

	// PING/PONG liveness
	lastFrameAt atomic.Int64 // unix nanos of any frame from peer
	lastPingAt  atomic.Int64
	pingIntvl   time.Duration
	pingTimeout time.Duration

	createdAt time.Time
	closeOnce sync.Once
	closedCh  chan struct{}
}

// NewMuxTunnel wraps an established XZAP transport and performs the
// version handshake. Returns a running MuxTunnel ready to open streams.
func NewMuxTunnel(r io.Reader, w io.Writer, c *Crypto) (*MuxTunnel, error) {
	// Client-side version handshake
	if err := WriteFrame(w, c, []byte(`{"v":"`+muxVersion+`"}`)); err != nil {
		return nil, fmt.Errorf("mux: send version: %w", err)
	}
	resp, err := ReadFrame(r, c)
	if err != nil {
		return nil, fmt.Errorf("mux: recv version: %w", err)
	}
	var versionAck struct{ V string `json:"v"` }
	if err := json.Unmarshal(resp, &versionAck); err != nil || versionAck.V != muxVersion {
		return nil, fmt.Errorf("mux: unexpected version handshake: %q", resp)
	}
	t := &MuxTunnel{
		r:            r,
		w:            w,
		c:            c,
		streams:      make(map[uint32]*muxStream),
		nextStreamID: 1, // 0 reserved for control
		pingIntvl:    10 * time.Second,
		pingTimeout:  30 * time.Second,
		createdAt:    time.Now(),
		closedCh:     make(chan struct{}),
	}
	atomic.StoreInt32(&t.alive, 1)
	t.lastFrameAt.Store(time.Now().UnixNano())
	go t.readerLoop()
	go t.pingLoop()
	return t, nil
}

// IsAlive reports whether the tunnel has not been torn down.
func (t *MuxTunnel) IsAlive() bool { return atomic.LoadInt32(&t.alive) == 1 }

// StreamCount returns active streams on this tunnel.
func (t *MuxTunnel) StreamCount() int {
	t.streamsMu.Lock()
	defer t.streamsMu.Unlock()
	return len(t.streams)
}

// Close tears down the tunnel and all its streams.
func (t *MuxTunnel) Close() error {
	t.closeOnce.Do(func() {
		atomic.StoreInt32(&t.alive, 0)
		close(t.closedCh)
		if c, ok := t.r.(io.Closer); ok {
			c.Close()
		}
		t.streamsMu.Lock()
		for _, s := range t.streams {
			s.forceClose()
		}
		t.streams = nil
		t.streamsMu.Unlock()
	})
	return nil
}

func (t *MuxTunnel) sendFrame(sid uint32, cmd byte, payload []byte) error {
	if !t.IsAlive() {
		return io.ErrClosedPipe
	}
	frame := packMuxFrame(sid, cmd, payload)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	return WriteFrame(t.w, t.c, frame)
}

// OpenStream dials host:port through the tunnel and returns a duplex
// stream. ctx is used for awaiting SYN_ACK only.
func (t *MuxTunnel) OpenStream(ctx context.Context, host string, port int) (*muxStream, error) {
	t.streamsMu.Lock()
	sid := t.nextStreamID
	t.nextStreamID++
	s := newMuxStream(sid, t)
	t.streams[sid] = s
	t.streamsMu.Unlock()

	req, _ := json.Marshal(map[string]interface{}{"host": host, "port": port})
	synSentAt := time.Now()
	if err := t.sendFrame(sid, cmdSYN, req); err != nil {
		log.Printf("mux: stream=%d SYN send failed to %s:%d: %v", sid, host, port, err)
		t.removeStream(sid)
		return nil, err
	}
	// Phase C — timing diagnosis: log destination + RTT for every stream open,
	// to find which hosts are slow (server target-connect bottleneck) vs fast.
	tunAge := time.Since(t.createdAt).Round(time.Second)
	streamsBefore := t.StreamCount()
	// Await SYN_ACK
	select {
	case ok := <-s.ack:
		rtt := time.Since(synSentAt)
		log.Printf("mux: stream=%d ACK ok=%v dest=%s:%d rtt=%v tunAge=%v streamsBefore=%d", sid, ok, host, port, rtt, tunAge, streamsBefore)
		if !ok {
			t.removeStream(sid)
			return nil, fmt.Errorf("mux: server rejected stream to %s:%d", host, port)
		}
	case <-ctx.Done():
		waited := time.Since(synSentAt)
		log.Printf("mux: stream=%d TIMEOUT dest=%s:%d waited=%v ctx=%v tunAge=%v streamsBefore=%d", sid, host, port, waited, ctx.Err(), tunAge, streamsBefore)
		t.removeStream(sid)
		return nil, ctx.Err()
	}
	// Bootstrap WINDOW frame engages server-side flow control
	zero := make([]byte, 4)
	_ = t.sendFrame(sid, cmdWINDOW, zero)
	return s, nil
}

func (t *MuxTunnel) removeStream(sid uint32) {
	t.streamsMu.Lock()
	if s, ok := t.streams[sid]; ok {
		delete(t.streams, sid)
		s.forceClose()
	}
	t.streamsMu.Unlock()
}

func (t *MuxTunnel) readerLoop() {
	defer func() {
		log.Printf("mux: readerLoop EXIT (tunnel closing)")
		t.Close()
	}()
	for atomic.LoadInt32(&t.alive) == 1 {
		frame, err := ReadFrame(t.r, t.c)
		if err != nil {
			log.Printf("mux: readerLoop ReadFrame error: %v", err)
			return
		}
		t.lastFrameAt.Store(time.Now().UnixNano())
		if len(frame) < muxHdrSize {
			log.Printf("mux: readerLoop got undersized frame %d bytes", len(frame))
			continue
		}
		sid := binary.BigEndian.Uint32(frame[0:4])
		cmd := frame[4]
		plen := binary.BigEndian.Uint32(frame[5:9])
		if plen > maxPayload || int(plen)+muxHdrSize > len(frame) {
			log.Printf("mux: readerLoop bad frame sid=%d cmd=0x%02x plen=%d framelen=%d", sid, cmd, plen, len(frame))
			continue
		}
		payload := frame[muxHdrSize : muxHdrSize+int(plen)]

		// Skip noisy per-frame log for control PING/PONG; log everything else
		if !(sid == controlSID && (cmd == cmdPING || cmd == cmdPONG)) {
			log.Printf("mux: readerLoop RX sid=%d cmd=0x%02x plen=%d", sid, cmd, plen)
		}

		if sid == controlSID {
			switch cmd {
			case cmdPING:
				_ = t.sendFrame(controlSID, cmdPONG, nil)
			}
			continue
		}
		t.streamsMu.Lock()
		s := t.streams[sid]
		t.streamsMu.Unlock()
		if s == nil {
			log.Printf("mux: readerLoop no stream for sid=%d cmd=0x%02x — dropping", sid, cmd)
			continue
		}
		switch cmd {
		case cmdSYNACK:
			s.onAck(true)
		case cmdRST, cmdFIN:
			s.onAck(false)
			s.forceClose()
			t.removeStream(sid)
		case cmdDATA:
			s.onData(payload)
		case cmdWINDOW:
			if len(payload) >= 4 {
				delta := int32(binary.BigEndian.Uint32(payload[:4]))
				s.onWindowUpdate(delta)
			}
		}
	}
}

func (t *MuxTunnel) pingLoop() {
	tk := time.NewTicker(t.pingIntvl)
	defer tk.Stop()
	for {
		select {
		case <-t.closedCh:
			return
		case <-tk.C:
			now := time.Now().UnixNano()
			lastFrame := t.lastFrameAt.Load()
			lastPing := t.lastPingAt.Load()
			if lastPing > lastFrame && time.Duration(now-lastFrame) > t.pingTimeout {
				// server went silent for too long — tunnel is dead
				t.Close()
				return
			}
			t.lastPingAt.Store(now)
			if err := t.sendFrame(controlSID, cmdPING, nil); err != nil {
				t.Close()
				return
			}
		}
	}
}

// === muxStream ===

type muxStream struct {
	id       uint32
	tunnel   *MuxTunnel
	rx       chan []byte
	ack      chan bool
	closed   atomic.Bool
	rxBuf    []byte
	rxMu     sync.Mutex

	// Send-side flow control
	sendWin  atomic.Int32
	winCh    chan struct{} // notified on WINDOW update

	// Receive-side accounting (credit peer periodically)
	consumed atomic.Int32
}

func newMuxStream(id uint32, t *MuxTunnel) *muxStream {
	s := &muxStream{
		id:     id,
		tunnel: t,
		rx:     make(chan []byte, 32),
		ack:    make(chan bool, 1),
		winCh:  make(chan struct{}, 1),
	}
	s.sendWin.Store(initialWindow)
	return s
}

func (s *muxStream) onAck(ok bool) {
	select {
	case s.ack <- ok:
	default:
	}
}

func (s *muxStream) onData(data []byte) {
	if s.closed.Load() {
		return
	}
	b := make([]byte, len(data))
	copy(b, data)
	select {
	case s.rx <- b:
	case <-time.After(30 * time.Second):
		// Drop — reader is stuck
	}
}

func (s *muxStream) onWindowUpdate(delta int32) {
	if delta > 0 {
		s.sendWin.Add(delta)
	}
	select {
	case s.winCh <- struct{}{}:
	default:
	}
}

func (s *muxStream) forceClose() {
	if s.closed.CompareAndSwap(false, true) {
		close(s.rx)
		// unblock ack waiters
		select {
		case s.ack <- false:
		default:
		}
	}
}

// Read drains chunks arriving from the peer.
func (s *muxStream) Read(p []byte) (int, error) {
	s.rxMu.Lock()
	defer s.rxMu.Unlock()
	if len(s.rxBuf) == 0 {
		chunk, ok := <-s.rx
		if !ok {
			return 0, io.EOF
		}
		s.rxBuf = chunk
	}
	n := copy(p, s.rxBuf)
	s.rxBuf = s.rxBuf[n:]
	// Credit back to peer every 64KB consumed
	if total := s.consumed.Add(int32(n)); total >= 64*1024 {
		if s.consumed.CompareAndSwap(total, 0) {
			var buf [4]byte
			binary.BigEndian.PutUint32(buf[:], uint32(total))
			_ = s.tunnel.sendFrame(s.id, cmdWINDOW, buf[:])
		}
	}
	return n, nil
}

// Write chunks of up to 32KB respecting the send window.
func (s *muxStream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.ErrClosedPipe
	}
	pos := 0
	for pos < len(p) {
		if s.sendWin.Load() <= 0 {
			select {
			case <-s.winCh:
			case <-time.After(30 * time.Second):
				return pos, fmt.Errorf("mux: send window starvation")
			}
		}
		remaining := len(p) - pos
		allowed := int(s.sendWin.Load())
		if allowed > remaining {
			allowed = remaining
		}
		if allowed > 32*1024 {
			allowed = 32 * 1024
		}
		if allowed <= 0 {
			continue
		}
		if err := s.tunnel.sendFrame(s.id, cmdDATA, p[pos:pos+allowed]); err != nil {
			return pos, err
		}
		s.sendWin.Add(int32(-allowed))
		pos += allowed
	}
	return pos, nil
}

// Close signals FIN and drops the stream from the tunnel.
func (s *muxStream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		_ = s.tunnel.sendFrame(s.id, cmdFIN, nil)
		s.tunnel.removeStream(s.id)
	}
	return nil
}
