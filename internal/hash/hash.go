// Copyright 2026 CrabCanneryShip
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package hash provides SHA-256 hashing utilities for the collector.
package hash

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// SHA256Bytes returns the lowercase hexadecimal SHA-256 digest of the data.
func SHA256Bytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// StreamHasher accumulates a SHA-256 digest incrementally and implements
// io.Writer for streaming data.
type StreamHasher struct {
	h hash.Hash
}

// NewStreamHasher returns a ready-to-use StreamHasher.
func NewStreamHasher() *StreamHasher {
	return &StreamHasher{h: sha256.New()}
}

// Write implements io.Writer.
func (s *StreamHasher) Write(p []byte) (int, error) {
	return s.h.Write(p)
}

// SumHex returns the lowercase hexadecimal SHA-256 digest of everything written so far.
func (s *StreamHasher) SumHex() string {
	return hex.EncodeToString(s.h.Sum(nil))
}
