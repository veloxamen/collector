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

// Package memory provides physical memory acquisition using winpmem.
// It captures RAM, compresses it to ZIP, and manages temporary raw files.
package memory

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"collector/internal/humanize"
)

// entryStreamWriter defines the minimal capability AcquireAndCompress needs from
// the output container.
type entryStreamWriter interface {
	WriteEntryStream(name string, size uint64, r io.Reader) error
}

// DumpResult contains the outcome and metadata of a memory acquisition process.
type DumpResult struct {
	ZipEntry   string  // name of the entry written into the output container
	ZipBytes   uint64  // size of the compressed ZIP archive
	RawBytes   int64   // size of the raw dump before compression
	ElapsedSec float64 // total wall-clock seconds
}

// AcquireAndCompress dumps physical memory via winpmem, compresses it to a ZIP
// archive, and streams it into ew as a single entry using temporary files on disk.
func AcquireAndCompress(hostname string, ew entryStreamWriter) (*DumpResult, error) {
	winpmem, err := resolveWinpmem()
	if err != nil {
		return nil, err
	}
	log.Printf("[D] winpmem: %s", winpmem)

	// Temp file for raw dump
	tmp, err := os.CreateTemp("", "memdump_*.raw")
	if err != nil {
		return nil, fmt.Errorf("cannot create temp file: %w", err)
	}
	rawFile := tmp.Name()
	tmp.Close()

	defer func() {
		if _, err := os.Stat(rawFile); err == nil {
			log.Printf("[D] Removing temporary raw file: %s", rawFile)
			os.Remove(rawFile)
		}
	}()

	start := time.Now()

	// Phase 1: acquire with winpmem
	fmt.Printf("  [1/3] Acquiring memory dump via winpmem...\n")
	var outBuf bytes.Buffer
	cmd := exec.Command(winpmem, "acquire", rawFile)
	cmd.Stdout = &outBuf
	cmd.Stderr = io.MultiWriter(os.Stderr, &outBuf)
	if err := cmd.Run(); err != nil {
		info, serr := os.Stat(rawFile)
		if serr != nil || info.Size() == 0 {
			return nil, fmt.Errorf("winpmem failed: %w\n%s", err, outBuf.String())
		}
		fmt.Fprintf(os.Stderr, "  [!] winpmem exited non-zero but dump file exists — continuing\n")
	}

	info, err := os.Stat(rawFile)
	if err != nil || info.Size() == 0 {
		return nil, fmt.Errorf("dump file was not created or is empty")
	}
	rawBytes := info.Size()
	fmt.Printf("  [1/3] Done — raw dump: %s\n", humanize.FormatBytes(uint64(rawBytes)))

	// Phase 2: ZIP compress, raw temp file → zip temp file (streamed, not buffered)
	fmt.Printf("  [2/3] Compressing memory dump...\n")
	zipFile, zipBytes, err := compressToZipFile(rawFile, hostname+"_memory.raw")
	if err != nil {
		return nil, fmt.Errorf("ZIP compression failed: %w", err)
	}
	defer func() {
		log.Printf("[D] Removing temporary zip file: %s", zipFile)
		os.Remove(zipFile)
	}()
	fmt.Printf("  [2/3] Done — compressed: %s\n", humanize.FormatBytes(zipBytes))

	// Phase 3: stream the zip temp file straight into the encrypted output
	fmt.Printf("  [3/3] Writing to output...\n")
	zr, err := os.Open(zipFile)
	if err != nil {
		return nil, fmt.Errorf("reopen zip file: %w", err)
	}
	defer zr.Close()

	const zipEntry = "memdump.zip"
	if err := ew.WriteEntryStream(zipEntry, zipBytes, zr); err != nil {
		return nil, fmt.Errorf("write to output: %w", err)
	}
	fmt.Printf("  [3/3] Done\n")

	return &DumpResult{
		ZipEntry:   zipEntry,
		ZipBytes:   zipBytes,
		RawBytes:   rawBytes,
		ElapsedSec: time.Since(start).Seconds(),
	}, nil
}

// compressToZipFile streams rawFile into a new single-entry ZIP archive
// written to its own temp file without holding contents in memory.
func compressToZipFile(rawFile, entryName string) (zipPath string, size uint64, err error) {
	src, err := os.Open(rawFile)
	if err != nil {
		return "", 0, fmt.Errorf("open raw file: %w", err)
	}
	defer src.Close()

	dst, err := os.CreateTemp("", "memdump_*.zip")
	if err != nil {
		return "", 0, fmt.Errorf("create zip temp file: %w", err)
	}
	zipPath = dst.Name()
	ok := false
	defer func() {
		dst.Close() //nolint:errcheck
		if !ok {
			os.Remove(zipPath)
		}
	}()

	zw := zip.NewWriter(dst)
	w, err := zw.Create(entryName)
	if err != nil {
		return "", 0, fmt.Errorf("zip create entry: %w", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return "", 0, fmt.Errorf("zip copy: %w", err)
	}
	if err := zw.Close(); err != nil {
		return "", 0, fmt.Errorf("zip close: %w", err)
	}

	info, err := dst.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("stat zip file: %w", err)
	}

	ok = true
	return zipPath, uint64(info.Size()), nil
}

// resolveWinpmem searches for a winpmem executable in the collector's directory.
func resolveWinpmem() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to determine executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)

	candidates := []string{
		"go-winpmem_amd64_1.0-rc2_signed.exe", // current recommendation
		"go-winpmem.exe",                      // for future renaming
	}
	for _, name := range candidates {
		p := filepath.Join(exeDir, name)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf(
		"winpmem not found in %s\nExpected one of:\n  %s",
		exeDir, strings.Join(candidates, "\n  "),
	)
}
