//go:build windows

// Package vault provides RSA-OAEP and AES-256-GCM encryption capabilities
// for the forensic artifact collector.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
)

const (
	// Magic is the file signature for identifying the collector's encrypted files.
	Magic = "VXMN0001"
	// ChunkSize defines the maximum size of buffered plaintext before encryption (64 MB).
	ChunkSize = 64 * 1024 * 1024
	// AESKeyLen is the length of the AES-256 key in bytes.
	AESKeyLen = 32
	// GCMNonceLen is the standard nonce size for AES-GCM.
	GCMNonceLen = 12
)

// EncWriter represents an active encrypted output stream.
type EncWriter struct {
	dst *os.File
	gcm cipher.AEAD
	buf []byte
}

// NewEncWriter creates an encrypted file at dstPath using the RSA public key.
// rsa.PublicKey: 2048-bit or higher is recommended
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

// WriteEntry writes a named data entry into the encrypted stream.
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

// Close flushes buffered data, writes the termination marker, and closes the file.
func (w *EncWriter) Close() error {
	if len(w.buf) > 0 {
		if err := w.flush(); err != nil {
			return err
		}
	}
	// Finalize stream with a termination marker.
	var zero [4]byte
	if _, err := w.dst.Write(zero[:]); err != nil {
		return err
	}
	return w.dst.Close()
}

// writeRaw partitions input bytes into ChunkSize-sized buffers for encryption.
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

// flush encrypts the current buffer using AES-GCM and writes it to disk.
func (w *EncWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	nonce := make([]byte, GCMNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	// Output format: [Nonce(12B)][Ciphertext]
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
