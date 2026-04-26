// FragmentedConn wraps a net.Conn and adds the XZAP fragmentation layer
// on top of it. This is required by the Python server's TCP/TLS path
// which reads data through FragmentedReader before handing it to the
// XZAP frame decoder.
//
// Wire format per fragment: [4B total_len][1B flags][data]
//
// flags:
//   0x00 real data  — receiver appends `data` to its accumulator
//   0x01 chaff       — receiver drops the fragment
//   0x02 overlap     — first N bytes of `data` overlap with previous fragment
//                      (not used by this client)
//
// Small frames (<= 150B) are split into 24-68 byte micro-fragments. Large
// frames are sent as one real fragment.

package transport

import (
	"encoding/binary"
	"io"
	"math/rand"
	"net"
	"sync"
	"time"
)

const (
	flagReal  = 0x00
	flagChaff = 0x01
	fragHdr   = 5
	fragMin   = 24
	fragMax   = 68
	fragThres = 150

	// Phase D3 mirror — chaff in client→server direction.
	// Mirrors xzap/transport/fragmented.py D3 settings.
	chaffChance  = 0.35
	chaffSizeMin = 800
	chaffSizeMax = 4000
	chaffNumMax  = 3
)

type fragConn struct {
	net.Conn
	rxBuf []byte // reassembled payload bytes not yet consumed by Read
	wMu   sync.Mutex
}

// WrapFragmented wraps c so that Write() segments outgoing data into
// fragments and Read() reassembles incoming fragments.
func WrapFragmented(c net.Conn) net.Conn {
	return &fragConn{Conn: c}
}

func (f *fragConn) Write(p []byte) (int, error) {
	f.wMu.Lock()
	defer f.wMu.Unlock()
	// Small data → micro-fragment; large → single real fragment + optional chaff.
	if len(p) <= fragThres {
		return len(p), f.writeFragmented(p)
	}

	// Phase D3 mirror — pack real + optional chaff fragments into ONE Conn.Write
	// (single TLS record). No drain/flush amplification → no UX latency penalty.
	buf := make([]byte, 0, fragHdr+len(p)+chaffNumMax*(fragHdr+chaffSizeMax))
	buf = appendFragment(buf, p, flagReal)
	if rand.Float64() < chaffChance {
		n := 1 + rand.Intn(chaffNumMax)
		for i := 0; i < n; i++ {
			size := chaffSizeMin + rand.Intn(chaffSizeMax-chaffSizeMin+1)
			chaff := make([]byte, size)
			_, _ = rand.Read(chaff)
			buf = appendFragment(buf, chaff, flagChaff)
		}
	}
	if _, err := f.Conn.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

// appendFragment encodes a fragment and appends to buf. Format: [4B total_len][1B flags][data].
func appendFragment(buf []byte, data []byte, flags byte) []byte {
	total := uint32(len(data) + 1)
	hdr := [5]byte{}
	binary.BigEndian.PutUint32(hdr[:4], total)
	hdr[4] = flags
	buf = append(buf, hdr[:]...)
	buf = append(buf, data...)
	return buf
}

func (f *fragConn) writeFragmented(data []byte) error {
	offset := 0
	for offset < len(data) {
		remaining := len(data) - offset
		size := fragMin + rand.Intn(fragMax-fragMin+1)
		if size > remaining {
			size = remaining
		}
		// Avoid leaving a stub smaller than fragMin on the next iteration
		if rem := remaining - size; rem > 0 && rem < fragMin {
			size = remaining
		}
		if err := f.writeOne(data[offset:offset+size], flagReal); err != nil {
			return err
		}
		offset += size
	}
	return nil
}

func (f *fragConn) writeOne(data []byte, flags byte) error {
	total := len(data) + 1 // +1 for flags byte
	buf := make([]byte, 4+total)
	binary.BigEndian.PutUint32(buf[:4], uint32(total))
	buf[4] = flags
	copy(buf[5:], data)
	_, err := f.Conn.Write(buf)
	return err
}

// Read returns up to len(p) bytes of reassembled payload. Fragments are
// pulled from the wire as needed.
func (f *fragConn) Read(p []byte) (int, error) {
	for len(f.rxBuf) == 0 {
		if err := f.readFragment(); err != nil {
			return 0, err
		}
	}
	n := copy(p, f.rxBuf)
	f.rxBuf = f.rxBuf[n:]
	return n, nil
}

func (f *fragConn) readFragment() error {
	for {
		var hdr [4]byte
		if _, err := io.ReadFull(f.Conn, hdr[:]); err != nil {
			return err
		}
		total := binary.BigEndian.Uint32(hdr[:])
		if total == 0 || total > 256*1024 {
			return io.ErrUnexpectedEOF
		}
		payload := make([]byte, total)
		if _, err := io.ReadFull(f.Conn, payload); err != nil {
			return err
		}
		flags := payload[0]
		data := payload[1:]
		if flags == flagChaff {
			continue // receiver drops chaff
		}
		f.rxBuf = append(f.rxBuf, data...)
		return nil
	}
}

// Suppress unused import warning in some build configs
var _ = time.Second
