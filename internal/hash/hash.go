// Package hash provides SHA-256 hashing utilities for the collector.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Bytes returns the lowercase hexadecimal SHA-256 digest of the data.
func SHA256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
