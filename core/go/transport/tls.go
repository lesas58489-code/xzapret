// uTLS-based transport: establishes a TLS connection whose ClientHello
// is byte-identical to a real Chrome / Firefox / Safari. DPI that relies
// on JA3/JA4 fingerprinting cannot distinguish it from browser traffic.

package transport

import (
	"context"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// TLSProfile selects which browser ClientHello to mimic.
type TLSProfile int

const (
	ProfileChrome120 TLSProfile = iota
	ProfileChrome131
	ProfileFirefox120
	ProfileSafari16
	ProfileRandomized
)

var clientHelloByProfile = map[TLSProfile]utls.ClientHelloID{
	ProfileChrome120:  utls.HelloChrome_120,
	ProfileChrome131:  utls.HelloChrome_131,
	ProfileFirefox120: utls.HelloFirefox_120,
	ProfileSafari16:   utls.HelloSafari_16_0,
	ProfileRandomized: utls.HelloRandomizedALPN,
}

// DialTLS opens a TCP connection to (host, port) and wraps it in a uTLS
// handshake mimicking the given browser. sni controls the SNI sent to
// the server — typically a legitimate-looking host like microsoft.com.
// The server certificate is NOT validated (we rely on XZAP key auth).
func DialTLS(ctx context.Context, host string, port int, sni string, profile TLSProfile) (net.Conn, error) {
	// Force IPv4 resolution. Some carriers (Megafon RU) give only IPv6
	// to the client but have no IPv6 route to IPv4 origins → ENETUNREACH.
	addrs, err := (&net.Resolver{}).LookupIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp4", fmt.Sprintf("%s:%d", addrs[0].String(), port))
	if err != nil {
		return nil, err
	}
	if tc, ok := raw.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
		_ = tc.SetNoDelay(true)
	}
	helloID, ok := clientHelloByProfile[profile]
	if !ok {
		helloID = utls.HelloChrome_131
	}
	uconn := utls.UClient(raw, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // self-signed cert on origin — XZAP key auth instead
		NextProtos:         []string{"h2", "http/1.1"},
	}, helloID)
	deadline := time.Now().Add(10 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = uconn.SetDeadline(deadline)
	if err := uconn.Handshake(); err != nil {
		raw.Close()
		return nil, fmt.Errorf("uTLS handshake: %w", err)
	}
	_ = uconn.SetDeadline(time.Time{})
	return uconn, nil
}
