// Minimal SOCKS5 server that routes all CONNECT requests through the
// XZAP mux tunnel pool. UDP ASSOCIATE is accepted for DNS only; non-DNS
// UDP (QUIC) is rejected so apps fall back to TCP quickly.

package xzapcore

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const socksBufSize = 64 * 1024

// socksServer listens on a local TCP port and accepts SOCKS5 clients.
type socksServer struct {
	ln       net.Listener
	pool     *Pool
	running  atomic.Bool
	bypassIP func(net.IP) bool // optional: return true for IPs that should go direct
}

func newSocksServer(ln net.Listener, pool *Pool) *socksServer {
	return &socksServer{ln: ln, pool: pool}
}

func (s *socksServer) Run() {
	s.running.Store(true)
	for s.running.Load() {
		c, err := s.ln.Accept()
		if err != nil {
			if !s.running.Load() {
				return
			}
			continue
		}
		go s.handleClient(c)
	}
}

func (s *socksServer) Stop() {
	s.running.Store(false)
	_ = s.ln.Close()
}

func (s *socksServer) handleClient(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	// Greeting: VER=5, NMETHODS, METHODS...
	buf := make([]byte, 262)
	if _, err := io.ReadFull(c, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	n := int(buf[1])
	if _, err := io.ReadFull(c, buf[:n]); err != nil {
		return
	}
	// Reply: no-auth
	if _, err := c.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	if _, err := io.ReadFull(c, buf[:4]); err != nil {
		return
	}
	cmd := buf[1]
	atyp := buf[3]

	if cmd == 0x03 {
		// UDP ASSOCIATE: reject, forcing apps to TCP fallback
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if cmd != 0x01 {
		_, _ = c.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		if _, err := io.ReadFull(c, buf[:4]); err != nil {
			return
		}
		host = net.IP(buf[:4]).String()
	case 0x03: // domain
		if _, err := io.ReadFull(c, buf[:1]); err != nil {
			return
		}
		dlen := int(buf[0])
		if _, err := io.ReadFull(c, buf[:dlen]); err != nil {
			return
		}
		host = string(buf[:dlen])
	case 0x04: // IPv6
		if _, err := io.ReadFull(c, buf[:16]); err != nil {
			return
		}
		host = net.IP(buf[:16]).String()
	default:
		_, _ = c.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	if _, err := io.ReadFull(c, buf[:2]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(buf[:2]))

	// Remove deadline for the data phase
	_ = c.SetDeadline(time.Time{})

	// Bypass direct? (e.g. private LAN, or carrier-specific whitelist)
	if s.bypassIP != nil {
		if ip := net.ParseIP(host); ip != nil && s.bypassIP(ip) {
			s.handleDirect(c, host, port)
			return
		}
	}

	// Open mux stream
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := s.pool.OpenStream(ctx, host, port)
	if err != nil {
		log.Printf("socks5: stream open failed %s:%d: %v", host, port, err)
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer stream.Close()

	// Reply success
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}

	// Relay both directions
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, c)
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(c, stream)
		errCh <- err
	}()
	<-errCh
}

func (s *socksServer) handleDirect(c net.Conn, host string, port int) {
	remote, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()
	if _, err := c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(remote, c); errCh <- err }()
	go func() { _, err := io.Copy(c, remote); errCh <- err }()
	<-errCh
}
