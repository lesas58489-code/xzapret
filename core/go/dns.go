// DNS hijack — intercept DNS queries from apps and return fake IPs from
// 198.18.0.0/15 (RFC2544 test range). Each fake IP is bound to the queried
// domain via the fakeIPPool. When the app then opens a TCP connection to
// that fake IP, the SOCKS5 CONNECT handler recovers the domain via
// LookupFakeIP() and feeds it to Router.Decide() — so every routing decision
// is hostname-based, not IP-based.
//
// Why fake IPs and not real ones:
//   - For tunnel-bound traffic (blocked services), we never need a real IP
//     on the client side; the mux server resolves and connects on our behalf.
//   - For bypass-bound traffic (russian sites + learned-direct), the SOCKS5
//     handleDirect re-resolves the hostname when dialing — so the actual
//     real-IP lookup happens inside Go's resolver (local network DNS, not
//     through tunnel), no extra round-trip vs returning real IP from here.
//
// AAAA queries return NODATA (no IPv6 fake range), forcing apps to use A.

package xzapcore

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

const (
	// 198.18.0.0/15 — RFC2544 benchmark range. 131072 IPs.
	fakeIPBase     = 0xC6120000 // 198.18.0.0
	fakeIPCapacity = 131072
)

type fakeIPPool struct {
	mu        sync.Mutex
	next      uint32
	domain2ip map[string]uint32 // lowercase fqdn → offset
	ip2domain map[uint32]string // offset → fqdn
	lastUsed  map[uint32]time.Time
}

func newFakeIPPool() *fakeIPPool {
	return &fakeIPPool{
		domain2ip: make(map[string]uint32),
		ip2domain: make(map[uint32]string),
		lastUsed:  make(map[uint32]time.Time),
	}
}

// Allocate returns a fake IP for the given domain, reusing existing mapping
// if any. LRU-evicts the next slot when the pool wraps around.
func (p *fakeIPPool) Allocate(domain string) net.IP {
	p.mu.Lock()
	defer p.mu.Unlock()

	if off, ok := p.domain2ip[domain]; ok {
		p.lastUsed[off] = time.Now()
		return offsetToIP(off)
	}
	off := p.next
	if old, exists := p.ip2domain[off]; exists {
		delete(p.domain2ip, old)
	}
	p.domain2ip[domain] = off
	p.ip2domain[off] = domain
	p.lastUsed[off] = time.Now()
	p.next = (p.next + 1) % fakeIPCapacity
	return offsetToIP(off)
}

// Lookup returns the original domain for a fake IP, or "" if not allocated.
func (p *fakeIPPool) Lookup(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	u := binary.BigEndian.Uint32(v4)
	if u < fakeIPBase || u >= fakeIPBase+fakeIPCapacity {
		return ""
	}
	off := u - fakeIPBase
	p.mu.Lock()
	defer p.mu.Unlock()
	if d, ok := p.ip2domain[off]; ok {
		p.lastUsed[off] = time.Now()
		return d
	}
	return ""
}

func (p *fakeIPPool) Size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.domain2ip)
}

func offsetToIP(off uint32) net.IP {
	u := fakeIPBase + off
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, u)
	return ip
}

// DNSServer parses incoming DNS queries and synthesizes responses pointing
// at fake IPs. The SOCKS5 CONNECT handler later resolves fake IP → domain
// via LookupFakeIP and routes per Router decision.
type DNSServer struct {
	pool *fakeIPPool
}

func NewDNSServer() *DNSServer {
	return &DNSServer{pool: newFakeIPPool()}
}

// HandleQuery returns a synthesized response for a DNS query packet.
// On parse error, returns a SERVFAIL response so the caller can still
// reply to the client (rather than dropping silently).
func (d *DNSServer) HandleQuery(query []byte) ([]byte, error) {
	var p dnsmessage.Parser
	hdr, err := p.Start(query)
	if err != nil {
		return d.servfailResponse(query, 0)
	}
	q, err := p.Question()
	if err != nil {
		return d.servfailResponse(query, hdr.ID)
	}

	domain := strings.TrimSuffix(strings.ToLower(q.Name.String()), ".")

	bld := dnsmessage.NewBuilder(make([]byte, 0, 512), dnsmessage.Header{
		ID:                 hdr.ID,
		Response:           true,
		OpCode:             hdr.OpCode,
		RecursionDesired:   hdr.RecursionDesired,
		RecursionAvailable: true,
		RCode:              dnsmessage.RCodeSuccess,
	})
	bld.EnableCompression()
	if err := bld.StartQuestions(); err != nil {
		return d.servfailResponse(query, hdr.ID)
	}
	if err := bld.Question(q); err != nil {
		return d.servfailResponse(query, hdr.ID)
	}
	if err := bld.StartAnswers(); err != nil {
		return d.servfailResponse(query, hdr.ID)
	}

	switch q.Type {
	case dnsmessage.TypeA:
		fakeIP := d.pool.Allocate(domain)
		var arr [4]byte
		copy(arr[:], fakeIP.To4())
		if err := bld.AResource(
			dnsmessage.ResourceHeader{
				Name:  q.Name,
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			},
			dnsmessage.AResource{A: arr},
		); err != nil {
			log.Printf("dns: build A response failed for %s: %v", domain, err)
		}
	case dnsmessage.TypeAAAA:
		// NODATA: empty answer. Apps fall back to A.
	default:
		// NODATA for NS/MX/TXT/CNAME etc.
	}

	return bld.Finish()
}

func (d *DNSServer) servfailResponse(query []byte, id uint16) ([]byte, error) {
	if id == 0 && len(query) >= 2 {
		id = binary.BigEndian.Uint16(query[:2])
	}
	bld := dnsmessage.NewBuilder(make([]byte, 0, 12), dnsmessage.Header{
		ID:       id,
		Response: true,
		RCode:    dnsmessage.RCodeServerFailure,
	})
	return bld.Finish()
}

// LookupFakeIP returns the original domain for a fake IP literal, or ""
// if host is not a fake IP we allocated.
func (d *DNSServer) LookupFakeIP(host string) string {
	ip := net.ParseIP(host)
	if ip == nil {
		return ""
	}
	return d.pool.Lookup(ip)
}

// Stats reports current fake-IP pool size.
func (d *DNSServer) Stats() string {
	return fmt.Sprintf("fake-ips=%d/%d", d.pool.Size(), fakeIPCapacity)
}
