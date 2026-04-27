// Package hasher provides SHA-256 hashing helpers.
package hasher

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Bytes returns the lowercase hex SHA-256 digest of data.
func SHA256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
