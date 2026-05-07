//go:build windows

// Package collect gathers Windows artifacts and writes them to an encrypted stream.
package collect

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"collector/internal/hash"
	"collector/internal/ntfs"
)

// EntryWriter is the interface that wraps the basic WriteEntry and Close methods.
type EntryWriter interface {
	WriteEntry(name string, data []byte) error
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
	data, err := sess.ReadFileByInode(inode)
	if err != nil {
		return ResultSet{}, fmt.Errorf("inode read failed (%s): %w", relPath, err)
	}
	ts, hasTS := sess.GetFileTimestampsByInode(inode)
	var modTime time.Time
	if hasTS {
		modTime = ts.Modified
	}
	return c.encryptData(path, data, modTime)
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
