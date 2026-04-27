//go:build windows

// Package crypto provides RSA-OAEP + AES-256-GCM encryption
// for the forensic suite collector.
//
// File format:
//
//	[8B]  Magic "VXMN0001"
//	[4B]  RSA-encrypted AES key length (big-endian uint32)
//	[NB]  AES-256 key encrypted with RSA-OAEP(SHA-256)
//	Repeated until EOF:
//	  [4B]  Chunk ciphertext length (0 = end marker)
//	  [NB]  nonce(12B) + AES-256-GCM ciphertext + GCM tag(16B)
//
// Named entries inside the plaintext stream:
//
//	[4B name length][name bytes][8B data length][data bytes] repeated
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	Magic       = "VXMN0001"
	ChunkSize   = 64 * 1024 * 1024 // 64 MB per encrypted chunk
	AESKeyLen   = 32
	GCMNonceLen = 12
)

// EncWriter is an open encrypted output stream.
// Call WriteEntry to add named entries, then Close to finalise.
type EncWriter struct {
	dst *os.File
	gcm cipher.AEAD
	buf []byte
}

// NewEncWriter creates an encrypted output file at dstPath using pub as the
// RSA public key. The caller must call Close() to flush and finalize.
func NewEncWriter(dstPath string, pub *rsa.PublicKey) (*EncWriter, error) {
	aesKey := make([]byte, AESKeyLen)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("AES key generation failed: %w", err)
	}
	encKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("RSA-OAEP encryption failed: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("AES init failed: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("GCM init failed: %w", err)
	}
	dst, err := os.Create(dstPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file (%s): %w", dstPath, err)
	}
	// Write header
	if _, err := dst.Write([]byte(Magic)); err != nil {
		dst.Close()
		return nil, err
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(encKey)))
	if _, err := dst.Write(lenBuf[:]); err != nil {
		dst.Close()
		return nil, err
	}
	if _, err := dst.Write(encKey); err != nil {
		dst.Close()
		return nil, err
	}
	return &EncWriter{dst: dst, gcm: gcm, buf: make([]byte, 0, ChunkSize)}, nil
}

// WriteEntry writes a named entry into the encrypted stream.
func (w *EncWriter) WriteEntry(name string, data []byte) error {
	nameBytes := []byte(name)
	var hdr [12]byte
	binary.BigEndian.PutUint32(hdr[0:4], uint32(len(nameBytes)))
	binary.BigEndian.PutUint64(hdr[4:12], uint64(len(data)))
	if err := w.writeRaw(hdr[:]); err != nil {
		return err
	}
	if err := w.writeRaw(nameBytes); err != nil {
		return err
	}
	return w.writeRaw(data)
}

// Close flushes any buffered data and writes the end marker.
func (w *EncWriter) Close() error {
	if len(w.buf) > 0 {
		if err := w.flush(); err != nil {
			return err
		}
	}
	var zero [4]byte
	if _, err := w.dst.Write(zero[:]); err != nil {
		return err
	}
	return w.dst.Close()
}

func (w *EncWriter) writeRaw(p []byte) error {
	for len(p) > 0 {
		space := ChunkSize - len(w.buf)
		n := len(p)
		if n > space {
			n = space
		}
		w.buf = append(w.buf, p[:n]...)
		p = p[n:]
		if len(w.buf) == ChunkSize {
			if err := w.flush(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (w *EncWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	nonce := make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}
	ct := w.gcm.Seal(nonce, nonce, w.buf, nil)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ct)))
	if _, err := w.dst.Write(lenBuf[:]); err != nil {
		return err
	}
	if _, err := w.dst.Write(ct); err != nil {
		return err
	}
	w.buf = w.buf[:0]
	return nil
}

// ReadAllRaw reads all raw bytes from an io.Reader and returns them.
// Used internally for memory dump → ZIP → entry flow.
func ReadAllRaw(r io.Reader) ([]byte, error) {
	return io.ReadAll(r)
}
