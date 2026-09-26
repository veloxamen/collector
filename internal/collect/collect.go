//go:build windows

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

// Package collect gathers Windows artifacts and writes them to an encrypted stream.
package collect

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"collector/internal/hash"
	"collector/internal/ntfs"
)

// EntryWriter is the interface that wraps the basic WriteEntry and Close methods.
type EntryWriter interface {
	WriteEntry(name string, data []byte) error
	WriteEntryStream(name string, size uint64, r io.Reader) error
	Close() error
}

// ResultSet represents the metadata and hash for an individual collected artifact.
type ResultSet struct {
	OutputPath  string
	BytesCopied uint64
	SHA256      string
	SourcePath  string
	Method      string
	Modified    time.Time
}

// Collect maintains the state of an artifact collection session, including NTFS access.
type Collect struct {
	doHash  bool
	enc     EntryWriter
	session *ntfs.Session
}

// New creates a new Collector with the specified hashing preference and EntryWriter.
func New(doHash bool, ew EntryWriter) *Collect {
	return &Collect{doHash: doHash, enc: ew}
}

// WriteEntry saves a custom data block directly to the encrypted output stream.
func (c *Collect) WriteEntry(name string, data []byte) error {
	return c.enc.WriteEntry(name, data)
}

// Close releases the underlying NTFS session resources.
func (c *Collect) Close() {
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
}

// ReadAndEncrypt collects a file using NTFS, computes its hash, and secures it in the output stream.
func (c *Collect) ReadAndEncrypt(path string) (ResultSet, error) {
	sess, err := c.getSession(path)
	if err != nil {
		return ResultSet{}, err
	}
	relPath := volumeRelPath(sess.Label, path)
	inode, exists := sess.FindFileInode(relPath)
	if !exists {
		if strings.EqualFold(relPath, "$MFT") {
			data, err := sess.ReadFileByRelPath(relPath)
			if err != nil {
				return ResultSet{}, fmt.Errorf("$MFT read failed: %w", err)
			}
			return c.encryptData(path, data, time.Time{})
		}
		return ResultSet{}, fmt.Errorf("cannot resolve inode for %s", relPath)
	}

	ts, hasTS := sess.GetFileTimestampsByInode(inode)
	var modTime time.Time
	if hasTS {
		modTime = ts.Modified
	}

	// Files exceeding the threshold are streamed instead of buffered.
	if threshold := ntfs.StreamThresholdBytes(); threshold > 0 {
		if size, sizeErr := sess.GetFileSizeByInode(inode); sizeErr == nil && size > threshold {
			return c.streamAndEncrypt(sess, path, inode, size, modTime)
		}
	}

	data, err := sess.ReadFileByInode(inode)
	if err != nil {
		return ResultSet{}, fmt.Errorf("inode read failed (%s): %w", relPath, err)
	}
	return c.encryptData(path, data, modTime)
}

// streamAndEncrypt streams and encrypts large files without buffering them in memory.
func (c *Collect) streamAndEncrypt(sess *ntfs.Session, sourcePath string, inode uint64, size uint64, modTime time.Time) (ResultSet, error) {
	entryName := pathToCryptEntry(sourcePath)
	pr, pw := io.Pipe()

	readErr := make(chan error, 1)
	go func() {
		n, err := sess.StreamFileByInode(inode, pw)
		if err == nil && n != size {
			err = fmt.Errorf("read %d bytes from volume but expected %d", n, size)
		}
		// CloseWithError closes the reader with an optional error, preserving the cause.
		pw.CloseWithError(err)
		readErr <- err
	}()

	var r io.Reader = pr
	var hasher *hash.StreamHasher
	if c.doHash {
		hasher = hash.NewStreamHasher()
		r = io.TeeReader(pr, hasher)
	}

	writeErr := c.enc.WriteEntryStream(entryName, size, r)
	if writeErr != nil {
		// Unblock the producer to prevent goroutine leaks.
		pr.CloseWithError(writeErr)
	}

	// Drain the reader to prevent leaks and prioritize its error.
	if re := <-readErr; re != nil && writeErr == nil {
		writeErr = fmt.Errorf("read from volume: %w", re)
	}
	if writeErr != nil {
		return ResultSet{}, fmt.Errorf("stream write failed (%s): %w", sourcePath, writeErr)
	}

	result := ResultSet{
		OutputPath:  entryName,
		BytesCopied: size,
		SourcePath:  sourcePath,
		Modified:    modTime,
		Method:      "stream",
	}
	if hasher != nil {
		result.SHA256 = hasher.SumHex()
	}
	return result, nil
}

// encryptData handles the encryption of raw data and optional SHA-256 hashing.
func (c *Collect) encryptData(sourcePath string, data []byte, modTime time.Time) (ResultSet, error) {
	entryName := pathToCryptEntry(sourcePath)
	if err := c.enc.WriteEntry(entryName, data); err != nil {
		return ResultSet{}, fmt.Errorf("write failed (%s): %w", entryName, err)
	}
	r := ResultSet{
		OutputPath:  entryName,
		BytesCopied: uint64(len(data)),
		SourcePath:  sourcePath,
		Modified:    modTime,
	}
	if c.doHash {
		r.SHA256 = hash.SHA256Bytes(data)
	}
	return r, nil
}

// getSession provides a cached NTFS session for the specified volume, creating one if necessary.
func (c *Collect) getSession(path string) (*ntfs.Session, error) {
	volume := strings.TrimRight(filepath.VolumeName(path), ":")
	if c.session != nil && c.session.Label == volume {
		return c.session, nil
	}
	fmt.Printf("[*] Loading MFT for volume %s...\n", volume)
	sess, err := ntfs.NewSession(volume)
	if err != nil {
		return nil, fmt.Errorf("NTFS session failed: %w", err)
	}
	c.session = sess
	fmt.Printf("[*] MFT loaded\n")
	return c.session, nil
}

// volumeRelPath strips the volume letter to create a relative path for the archive.
func volumeRelPath(volume, fullPath string) string {
	prefix := strings.TrimRight(volume, `\`) + `:\`
	rel := strings.TrimPrefix(fullPath, prefix)
	return strings.TrimLeft(rel, `\`)
}

// pathToCryptEntry transforms an OS path into a normalized entry name for the bundle.
func pathToCryptEntry(sourcePath string) string {
	parts := strings.FieldsFunc(sourcePath, func(r rune) bool {
		return r == '\\' || r == '/'
	})
	out := make([]string, 0, len(parts))
	for i, p := range parts {
		if i == 0 {
			p = strings.TrimSuffix(p, ":")
		}
		out = append(out, p)
	}
	return strings.Join(out, "/")
}
