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
		// UDP ASSOCIATE — accept so DNS queries can relay via TCP tunnel.
		// Non-DNS UDP (QUIC etc) gets silently dropped, forcing TCP fallback.
		s.handleUDPAssociate(c, buf)
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

// handleUDPAssociate: accept associate, relay DNS over TCP via mux tunnel.
// Non-DNS UDP silently dropped → apps fall back to TCP.
func (s *socksServer) handleUDPAssociate(c net.Conn, buf []byte) {
	// Skip DST.ADDR + DST.PORT (4 bytes atyp already read, buf[3] = atyp)
	atyp := buf[3]
	switch atyp {
	case 0x01:
		_, _ = io.ReadFull(c, buf[:6])
	case 0x03:
		_, _ = io.ReadFull(c, buf[:1])
		dlen := int(buf[0])
		_, _ = io.ReadFull(c, buf[:dlen+2])
	case 0x04:
		_, _ = io.ReadFull(c, buf[:18])
	}

	// Bind a UDP socket on 127.0.0.1 and reply with its port.
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		_, _ = c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	udpPort := udp.LocalAddr().(*net.UDPAddr).Port
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, byte(udpPort >> 8), byte(udpPort & 0xFF)}
	if _, err := c.Write(reply); err != nil {
		udp.Close()
		return
	}

	// UDP receive loop in a goroutine; session ends when control TCP closes
	done := make(chan struct{})
	go s.udpLoop(udp, done)

	// Keep control TCP alive; close when client disconnects
	_, _ = io.Copy(io.Discard, c)
	close(done)
	_ = udp.Close()
}

func (s *socksServer) udpLoop(udp *net.UDPConn, done chan struct{}) {
	buf := make([]byte, 65536)
	_ = udp.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		select {
		case <-done:
			return
		default:
		}
		_ = udp.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, src, err := udp.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if n < 4 {
			continue
		}
		// SOCKS5 UDP header: [2B RSV][1B FRAG][1B ATYP][addr][port][data]
		atyp := buf[3]
		var dstHost string
		var dstPort int
		var payloadOff int
		switch atyp {
		case 0x01:
			if n < 10 { continue }
			dstHost = net.IP(buf[4:8]).String()
			dstPort = int(buf[8])<<8 | int(buf[9])
			payloadOff = 10
		case 0x03:
			if n < 5 { continue }
			dlen := int(buf[4])
			if n < 7+dlen { continue }
			dstHost = string(buf[5 : 5+dlen])
			dstPort = int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
			payloadOff = 7 + dlen
		case 0x04:
			if n < 22 { continue }
			dstHost = net.IP(buf[4:20]).String()
			dstPort = int(buf[20])<<8 | int(buf[21])
			payloadOff = 22
		default:
			continue
		}
		if dstPort != 53 {
			// Non-DNS UDP — drop silently (app will fall back to TCP)
			continue
		}
		query := make([]byte, n-payloadOff)
		copy(query, buf[payloadOff:n])
		udpHdr := make([]byte, payloadOff)
		copy(udpHdr, buf[:payloadOff])
		go s.relayDNS(udp, src, dstHost, query, udpHdr)
	}
}

// relayDNS opens a mux stream to dstHost:53 and sends the DNS query as
// DNS-over-TCP ([2B len][query]), then forwards the reply back as SOCKS5 UDP.
func (s *socksServer) relayDNS(udp *net.UDPConn, src *net.UDPAddr,
	dstHost string, query, udpHdr []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := s.pool.OpenStream(ctx, dstHost, 53)
	if err != nil {
		return
	}
	defer stream.Close()

	// DNS-over-TCP: [2B length][query]
	tcpQ := make([]byte, 2+len(query))
	tcpQ[0] = byte(len(query) >> 8)
	tcpQ[1] = byte(len(query))
	copy(tcpQ[2:], query)
	if _, err := stream.Write(tcpQ); err != nil {
		return
	}
	// Read response: [2B len][data]
	resp := make([]byte, 4096)
	n, err := io.ReadAtLeast(stream, resp, 2)
	if err != nil {
		return
	}
	respLen := int(resp[0])<<8 | int(resp[1])
	if respLen > 4000 || n-2 < respLen {
		// Read remaining if needed
		need := 2 + respLen - n
		if need > 0 {
			more := make([]byte, need)
			if _, err := io.ReadFull(stream, more); err != nil {
				return
			}
			resp = append(resp[:n], more...)
			n += need
		}
	}
	if n < 2+respLen {
		return
	}
	dns := resp[2 : 2+respLen]

	// Build SOCKS5 UDP reply = original UDP header + DNS response
	reply := make([]byte, 0, len(udpHdr)+len(dns))
	reply = append(reply, udpHdr...)
	reply = append(reply, dns...)
	_, _ = udp.WriteToUDP(reply, src)
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
