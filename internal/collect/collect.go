//go:build windows

// Package collector gathers Windows artifacts and writes them to an encrypted stream.
//
// Acquisition methods:
//   - Raw (NTFS direct):  IsLocked=true entries — reads OS-locked files via MFT
//   - OS (stdlib):        IsLocked=false entries — reads via os.Open / WalkDir
//
// Note on timestamps: os.Open is a read-only operation and does not update
// atime on Windows (atime tracking is disabled by default since Vista).
// No special handling is required for non-locked files.
package collect

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"collector/internal/config"
	"collector/internal/hasher"
	"collector/internal/ntfs"
)

// EntryWriter is satisfied by *crypto.EncWriter.
type EntryWriter interface {
	WriteEntry(name string, data []byte) error
	Close() error
}

const UserHolder = "{user}"

// CollectionResult holds metadata for a single collected file.
type CollectionResult struct {
	OutputPath  string
	BytesCopied uint64
	SHA256      string
	SourcePath  string
	Method      string
	Modified    time.Time
}

// Collector holds the NTFS session and the encrypted stream writer.
type Collector struct {
	doHash  bool
	enc     EntryWriter
	session *ntfs.Session
}

// New creates a Collector.
func New(doHash bool, ew EntryWriter) *Collector {
	return &Collector{doHash: doHash, enc: ew}
}

// WriteEntry writes an arbitrary entry directly (used for report files).
func (c *Collector) WriteEntry(name string, data []byte) error {
	return c.enc.WriteEntry(name, data)
}

// Close releases the NTFS session.
func (c *Collector) Close() {
	if c.session != nil {
		c.session.Close()
		c.session = nil
	}
}

// CollectEntry interprets one config.Entry and returns all results.
func (c *Collector) CollectEntry(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	switch entry.Type {
	case config.TypeProfileGlob:
		return c.collectProfileGlob(cfg, entry)
	case config.TypeDir:
		if config.HasUserPlaceholder(entry.Path) {
			return c.collectUserLoop(cfg, entry)
		}
		return c.collectDir(entry.Path, entry.Recursive, entry.AcquisitionMethod())
	case config.TypeFile:
		if config.HasUserPlaceholder(entry.Path) {
			return c.collectUserLoop(cfg, entry)
		}
		return c.collectFile(entry.Path, entry.AcquisitionMethod())
	default:
		return nil, fmt.Errorf("unknown entry type: %s", entry.Type)
	}
}

// ── PROFILE_GLOB ──────────────────────────────────────────────────────────────

// collectProfileGlob enumerates browser profiles matching ProfileRegex and
// collects files matching FileGlob inside each profile directory.
//
// This handles both {user} expansion and profile enumeration in one pass.
func (c *Collector) collectProfileGlob(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	re, err := regexp.Compile(entry.ProfileRegex)
	if err != nil {
		return nil, fmt.Errorf("PROFILE_GLOB: invalid regex %q: %w", entry.ProfileRegex, err)
	}
	// Split pipe-separated file names into a set for fast lookup
	wantedFiles := makeFileSet(entry.FileGlob)

	// Determine the set of base paths to scan (expand {user} if present)
	basePaths, err := c.expandBasePaths(cfg, entry.Path)
	if err != nil {
		return nil, err
	}

	var results []CollectionResult
	for _, basePath := range basePaths {
		children, err := os.ReadDir(basePath)
		if err != nil {
			log.Printf("[W] PROFILE_GLOB: cannot read %s: %v", basePath, err)
			continue
		}
		for _, child := range children {
			if !child.IsDir() {
				continue
			}
			if !re.MatchString(child.Name()) {
				continue
			}
			profileDir := filepath.Join(basePath, child.Name())
			res, err := c.collectFilesFromDir(profileDir, wantedFiles, entry.AcquisitionMethod())
			if err != nil {
				log.Printf("[W] PROFILE_GLOB profile %s: %v", profileDir, err)
				continue
			}
			results = append(results, res...)
		}
	}
	return results, nil
}

// expandBasePaths returns the set of concrete base paths after {user} expansion.
func (c *Collector) expandBasePaths(cfg *config.Config, basePath string) ([]string, error) {
	if !config.HasUserPlaceholder(basePath) {
		return []string{basePath}, nil
	}
	users, err := listUsers(cfg, basePath)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(users))
	for _, u := range users {
		paths = append(paths, cfg.ExpandUserPath(basePath, u))
	}
	return paths, nil
}

// collectFilesFromDir collects specific files (by name set) from a single directory.
func (c *Collector) collectFilesFromDir(dir string, wanted map[string]bool, method config.AcquisitionMethod) ([]CollectionResult, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", dir, err)
	}
	var results []CollectionResult
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !wanted[strings.ToLower(e.Name())] {
			continue
		}
		fullPath := filepath.Join(dir, e.Name())
		res, err := c.collectFile(fullPath, method)
		if err != nil {
			log.Printf("[W] collectFilesFromDir: %v", err)
			continue
		}
		results = append(results, res...)
	}
	return results, nil
}

func makeFileSet(glob string) map[string]bool {
	m := make(map[string]bool)
	for _, f := range strings.Split(glob, "|") {
		if t := strings.TrimSpace(f); t != "" {
			m[strings.ToLower(t)] = true
		}
	}
	return m
}

// ── User Loop ─────────────────────────────────────────────────────────────────

func (c *Collector) collectUserLoop(cfg *config.Config, entry config.Entry) ([]CollectionResult, error) {
	users, err := listUsers(cfg, entry.Path)
	if err != nil {
		return nil, err
	}
	var results []CollectionResult
	for _, user := range users {
		expanded := cfg.ExpandUserPath(entry.Path, user)
		var res []CollectionResult
		var err error
		switch entry.Type {
		case config.TypeDir:
			res, err = c.collectDir(expanded, entry.Recursive, entry.AcquisitionMethod())
		default:
			res, err = c.collectFile(expanded, entry.AcquisitionMethod())
		}
		if err != nil {
			log.Printf("[W] user %s: %v", user, err)
			continue
		}
		results = append(results, res...)
	}
	return results, nil
}

// listUsers returns usernames under the Users directory derived from path,
// excluding those in cfg.ExcludeUsers.
func listUsers(cfg *config.Config, path string) ([]string, error) {
	idx := strings.Index(path, UserHolder)
	if idx < 1 {
		return nil, fmt.Errorf("no {user} placeholder in path: %s", path)
	}
	usersDir := path[:idx-1] // strip trailing backslash before {user}
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate %s: %w", usersDir, err)
	}
	var users []string
	for _, d := range entries {
		if d.IsDir() && !cfg.IsExcludedUser(d.Name()) {
			users = append(users, d.Name())
		}
	}
	return users, nil
}

// ── DIR ───────────────────────────────────────────────────────────────────────

func (c *Collector) collectDir(dirPath string, recursive bool, method config.AcquisitionMethod) ([]CollectionResult, error) {
	if method == config.MethodRaw {
		return c.collectDirRaw(dirPath, recursive)
	}
	return c.collectDirOS(dirPath, recursive)
}

func (c *Collector) collectDirRaw(dirPath string, recursive bool) ([]CollectionResult, error) {
	sess, err := c.getSession(dirPath)
	if err != nil {
		return nil, err
	}
	relDir := volumeRelPath(sess.Label, dirPath)
	entries, err := sess.ListDirEntries(relDir, recursive)
	if err != nil {
		return nil, fmt.Errorf("directory enumeration failed (%s): %w", dirPath, err)
	}
	var results []CollectionResult
	for _, entry := range entries {
		data, err := sess.ReadFileByInode(entry.Inode)
		if err != nil {
			log.Printf("[W] inode read failed '%s': %v", entry.RelPath, err)
			continue
		}
		fullSrc := sess.Label + `:\` + entry.RelPath
		entryName := pathToCryptEntry(fullSrc)
		ts, hasTS := sess.GetFileTimestampsByInode(entry.Inode)
		var modTime time.Time
		if hasTS {
			modTime = ts.Modified
		}
		if err := c.enc.WriteEntry(entryName, data); err != nil {
			log.Printf("[W] write failed '%s': %v", entryName, err)
			continue
		}
		r := CollectionResult{
			OutputPath: entryName, BytesCopied: uint64(len(data)),
			SourcePath: fullSrc, Method: "Raw", Modified: modTime,
		}
		if c.doHash {
			r.SHA256 = hasher.SHA256Bytes(data)
		}
		results = append(results, r)
	}
	return results, nil
}

func (c *Collector) collectDirOS(dirPath string, recursive bool) ([]CollectionResult, error) {
	var results []CollectionResult
	if recursive {
		err := filepath.WalkDir(dirPath, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			r, rerr := c.readAndEncryptOS(path)
			if rerr != nil {
				log.Printf("[W] OS read failed '%s': %v", path, rerr)
				return nil
			}
			results = append(results, *r)
			return nil
		})
		return results, err
	}
	dirEntries, err := os.ReadDir(dirPath)
	if err != nil {
		return nil, fmt.Errorf("directory read failed (%s): %w", dirPath, err)
	}
	for _, d := range dirEntries {
		if d.IsDir() {
			continue
		}
		fullPath := filepath.Join(dirPath, d.Name())
		r, rerr := c.readAndEncryptOS(fullPath)
		if rerr != nil {
			log.Printf("[W] OS read failed '%s': %v", fullPath, rerr)
			continue
		}
		results = append(results, *r)
	}
	return results, nil
}

// ── FILE ──────────────────────────────────────────────────────────────────────

func (c *Collector) collectFile(path string, method config.AcquisitionMethod) ([]CollectionResult, error) {
	var r *CollectionResult
	var err error
	if method == config.MethodRaw {
		r, err = c.readAndEncryptRaw(path)
	} else {
		r, err = c.readAndEncryptOS(path)
	}
	if err != nil {
		return nil, err
	}
	return []CollectionResult{*r}, nil
}

// ── Raw acquisition ───────────────────────────────────────────────────────────

func (c *Collector) readAndEncryptRaw(path string) (*CollectionResult, error) {
	sess, err := c.getSession(path)
	if err != nil {
		return nil, err
	}
	relPath := volumeRelPath(sess.Label, path)
	inode, exists := sess.FindFileInode(relPath)
	if !exists {
		if strings.EqualFold(relPath, "$MFT") {
			data, err := sess.ReadFileByRelPath(relPath)
			if err != nil {
				return nil, fmt.Errorf("$MFT read failed: %w", err)
			}
			return c.encryptData(path, "Raw", data, time.Time{})
		}
		return nil, fmt.Errorf("cannot resolve inode for %s", relPath)
	}
	data, err := sess.ReadFileByInode(inode)
	if err != nil {
		return nil, fmt.Errorf("inode read failed (%s): %w", relPath, err)
	}
	ts, hasTS := sess.GetFileTimestampsByInode(inode)
	var modTime time.Time
	if hasTS {
		modTime = ts.Modified
	}
	return c.encryptData(path, "Raw", data, modTime)
}

// ── OS acquisition ────────────────────────────────────────────────────────────

func (c *Collector) readAndEncryptOS(sourcePath string) (*CollectionResult, error) {
	f, err := os.Open(sourcePath)
	if err != nil {
		return nil, fmt.Errorf("open failed (%s): %w", sourcePath, err)
	}
	defer f.Close()
	info, _ := f.Stat()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read failed (%s): %w", sourcePath, err)
	}
	var modTime time.Time
	if info != nil {
		modTime = info.ModTime()
	}
	return c.encryptData(sourcePath, "OS", data, modTime)
}

func (c *Collector) encryptData(sourcePath, method string, data []byte, modTime time.Time) (*CollectionResult, error) {
	entryName := pathToCryptEntry(sourcePath)
	if err := c.enc.WriteEntry(entryName, data); err != nil {
		return nil, fmt.Errorf("write failed (%s): %w", entryName, err)
	}
	r := &CollectionResult{
		OutputPath: entryName, BytesCopied: uint64(len(data)),
		SourcePath: sourcePath, Method: method, Modified: modTime,
	}
	if c.doHash {
		r.SHA256 = hasher.SHA256Bytes(data)
	}
	return r, nil
}

// ── NTFS session ──────────────────────────────────────────────────────────────

func (c *Collector) getSession(path string) (*ntfs.Session, error) {
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

// ── Utilities ─────────────────────────────────────────────────────────────────

func volumeRelPath(volume, fullPath string) string {
	prefix := strings.TrimRight(volume, `\`) + `:\`
	rel := strings.TrimPrefix(fullPath, prefix)
	return strings.TrimLeft(rel, `\`)
}

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
