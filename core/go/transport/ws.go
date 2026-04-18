// WebSocket transport using uTLS for the outer TLS handshake. Each WS
// binary message carries exactly one XZAP frame, matching the server's
// frame-boundary handler (xzap/transport/ws.py with _WSStreamReader).

package transport

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"nhooyr.io/websocket"
)

// DialWS opens a wss:// URL through Cloudflare (or any WS server) with
// a uTLS Chrome fingerprint, then returns a net.Conn-compatible wrapper
// where each Write() is sent as one WS binary message and Read() blocks
// until the next message arrives.
func DialWS(ctx context.Context, rawURL string) (net.Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("ws url parse: %w", err)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	// Dial the underlying TCP+uTLS connection ourselves so we control the
	// ClientHello fingerprint (plain websocket.Dial would use Go's stdlib
	// TLS and emit Go's JA3, which DPI can fingerprint).
	addrs, err := (&net.Resolver{}).LookupIP(ctx, "ip4", host)
	if err != nil || len(addrs) == 0 {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp4", net.JoinHostPort(addrs[0].String(), port))
	if err != nil {
		return nil, err
	}

	var tlsConn io.ReadWriteCloser = raw
	if u.Scheme == "wss" {
		uconn := utls.UClient(raw, &utls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloChrome_131)
		_ = uconn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := uconn.Handshake(); err != nil {
			raw.Close()
			return nil, fmt.Errorf("ws: uTLS handshake: %w", err)
		}
		_ = uconn.SetDeadline(time.Time{})
		tlsConn = uconn
	}

	// Now run WebSocket handshake over tlsConn.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				// Already connected — wrap tlsConn as net.Conn
				if c, ok := tlsConn.(net.Conn); ok {
					return c, nil
				}
				return nil, fmt.Errorf("ws: tls conn not net.Conn")
			},
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if c, ok := tlsConn.(net.Conn); ok {
					return c, nil
				}
				return nil, fmt.Errorf("ws: tls conn not net.Conn")
			},
			TLSHandshakeTimeout: time.Second, // already handshaked
		},
	}
	wsConn, _, err := websocket.Dial(ctx, rawURL, &websocket.DialOptions{
		HTTPClient:           httpClient,
		CompressionMode:      websocket.CompressionDisabled,
		HTTPHeader:           browserLikeHeaders(host, strings.HasPrefix(rawURL, "wss")),
	})
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("ws: dial: %w", err)
	}
	wsConn.SetReadLimit(-1) // unlimited
	return &wsNetConn{ws: wsConn, ctx: context.Background()}, nil
}

func browserLikeHeaders(host string, wss bool) http.Header {
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Cache-Control", "no-cache")
	if wss {
		h.Set("Origin", "https://"+host)
	} else {
		h.Set("Origin", "http://"+host)
	}
	return h
}

// wsNetConn adapts websocket.Conn to net.Conn with message-per-Write/Read semantics.
type wsNetConn struct {
	ws  *websocket.Conn
	ctx context.Context
	// current inbound message buffer
	buf []byte
}

func (c *wsNetConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	_, data, err := c.ws.Read(c.ctx)
	if err != nil {
		return 0, io.EOF
	}
	c.buf = data
	n := copy(p, c.buf)
	c.buf = c.buf[n:]
	return n, nil
}

func (c *wsNetConn) Write(p []byte) (int, error) {
	if err := c.ws.Write(c.ctx, websocket.MessageBinary, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *wsNetConn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

// Unused net.Conn methods — stub them (the mux code never calls them).
func (c *wsNetConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *wsNetConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *wsNetConn) SetDeadline(t time.Time) error      { return nil }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return nil }
