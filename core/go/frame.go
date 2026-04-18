// XZAP wire frame format (compatible with Python server and original clients).
//
//   [4B big-endian payload_len]
//   [16B random prefix]
//   [encrypted_body]                     <- variable length, ends at payload_len
//
// payload_len counts bytes after the 4-byte length header, i.e.
// payload_len = 16 + len(encrypted_body).

package xzapcore

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	PrefixSize   = 16
	MaxFrameSize = 256 * 1024 // anti-DoS cap
)

// WriteFrame encrypts plaintext and writes one complete XZAP frame.
func WriteFrame(w io.Writer, c *Crypto, plaintext []byte) error {
	encrypted := c.Encrypt(plaintext)
	prefix := make([]byte, PrefixSize)
	if _, err := rand.Read(prefix); err != nil {
		return err
	}
	total := PrefixSize + len(encrypted)
	hdr := make([]byte, 4+total)
	binary.BigEndian.PutUint32(hdr[:4], uint32(total))
	copy(hdr[4:4+PrefixSize], prefix)
	copy(hdr[4+PrefixSize:], encrypted)
	_, err := w.Write(hdr)
	return err
}

// ReadFrame reads one XZAP frame and returns the decrypted plaintext.
func ReadFrame(r io.Reader, c *Crypto) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	total := binary.BigEndian.Uint32(hdr[:])
	if total == 0 || total > MaxFrameSize {
		return nil, fmt.Errorf("bad frame size %d", total)
	}
	payload := make([]byte, total)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	if len(payload) < PrefixSize {
		return nil, errors.New("payload shorter than prefix")
	}
	return c.Decrypt(payload[PrefixSize:])
}
