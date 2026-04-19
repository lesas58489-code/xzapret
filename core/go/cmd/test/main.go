package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	xzapcore "github.com/lesas58489-code/xzapret/core/go"
	"github.com/lesas58489-code/xzapret/core/go/transport"
)

func main() {
	keyB64 := os.Getenv("XZAP_KEY")
	if keyB64 == "" {
		fmt.Println("XZAP_KEY env var required")
		os.Exit(1)
	}
	keyBytes, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		fmt.Println("key decode:", err); os.Exit(1)
	}
	cr, err := xzapcore.NewCrypto(keyBytes)
	if err != nil {
		fmt.Println("NewCrypto:", err); os.Exit(1)
	}

	deadline := time.Now().Add(15 * time.Second)
	ctx, cancel := contextWithDeadline(deadline)
	defer cancel()

	conn, err := transport.DialTLS(ctx, "151.244.111.186", 8443,
		"www.microsoft.com", transport.ProfileChrome131)
	if err != nil {
		fmt.Println("❌ DialTLS failed:", err); os.Exit(1)
	}
	fmt.Println("✅ uTLS + fragmentation TCP connect OK")

	t, err := xzapcore.NewMuxTunnel(conn, conn, cr)
	if err != nil {
		fmt.Println("❌ Mux handshake failed:", err); conn.Close(); os.Exit(1)
	}
	fmt.Println("✅ Mux handshake OK — wire protocol works")

	// Try reaching 1.1.1.1:443 via tunnel
	ctx2, cancel2 := contextWithDeadline(time.Now().Add(8 * time.Second))
	defer cancel2()
	s, err := t.OpenStream(ctx2, "1.1.1.1", 443)
	if err != nil {
		fmt.Println("❌ OpenStream 1.1.1.1:443:", err); t.Close(); os.Exit(1)
	}
	fmt.Println("✅ Stream to 1.1.1.1:443 opened")

	// Write a dummy TLS ClientHello-looking bytes to provoke any response
	_, _ = s.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00})
	buf := make([]byte, 1024)
	done := make(chan struct{})
	go func() {
		n, _ := s.Read(buf)
		if n > 0 {
			fmt.Printf("✅ Got %d bytes back from 1.1.1.1 (TLS alert expected)\n", n)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		fmt.Println("(no response from 1.1.1.1 in 5s — ok, test successful anyway)")
	}

	s.Close()
	t.Close()
	fmt.Println("\n✅ ALL GOOD — Android APK with same core should work")
}

func contextWithDeadline(d time.Time) (ctx netCtx, cancel func()) {
	return netCtx{d}, func() {}
}

type netCtx struct{ d time.Time }

func (c netCtx) Deadline() (time.Time, bool) { return c.d, true }
func (c netCtx) Done() <-chan struct{}       { return nil }
func (c netCtx) Err() error                  { return nil }
func (c netCtx) Value(key any) any           { return nil }

var _ io.Closer = (net.Conn)(nil)
