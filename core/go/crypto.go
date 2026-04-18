// XZAP crypto: AES-256-GCM. Wire-compatible with the Python server and
// the original Kotlin/Python clients.
//
// Frame body on the wire = [12B nonce][ciphertext+16B tag]
// where ciphertext is AES-GCM(key, nonce, plaintext, no AAD).

package xzapcore

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

type Crypto struct {
	aead cipher.AEAD
}

func NewCrypto(key []byte) (*Crypto, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Crypto{aead: aead}, nil
}

// Encrypt returns [nonce | ciphertext+tag].
func (c *Crypto) Encrypt(plaintext []byte) []byte {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err) // rand never fails in practice
	}
	out := make([]byte, 0, len(nonce)+len(plaintext)+c.aead.Overhead())
	out = append(out, nonce...)
	return c.aead.Seal(out, nonce, plaintext, nil)
}

// Decrypt expects [nonce | ciphertext+tag].
func (c *Crypto) Decrypt(data []byte) ([]byte, error) {
	n := c.aead.NonceSize()
	if len(data) < n+c.aead.Overhead() {
		return nil, fmt.Errorf("ciphertext too short (%d bytes)", len(data))
	}
	return c.aead.Open(nil, data[:n], data[n:], nil)
}
