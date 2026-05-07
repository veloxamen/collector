//go:build windows

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
)

// DumpResult contains the outcome and metadata of a memory acquisition process.
type DumpResult struct {
	ZipData    []byte  // compressed ZIP archive bytes
	RawBytes   int64   // size of the raw dump before compression
	ElapsedSec float64 // total wall-clock seconds
}

// AcquireAndCompress dumps physical memory via winpmem and returns a compressed ZIP.
// It creates a temporary raw file which is removed after compression to reduce
// the footprint on the evidence drive and avoid RAM contamination.
func AcquireAndCompress(hostname string) (*DumpResult, error) {
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
	fmt.Printf("  [1/2] Acquiring memory dump via winpmem...\n")
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
	fmt.Printf("  [1/2] Done — raw dump: %s\n", formatBytes(uint64(rawBytes)))

	// Phase 2: ZIP compress
	fmt.Printf("  [2/2] Compressing memory dump...\n")
	zipData, err := compressToZip(rawFile, hostname+"_memory.raw")
	if err != nil {
		return nil, fmt.Errorf("ZIP compression failed: %w", err)
	}
	fmt.Printf("  [2/2] Done — compressed: %s\n", formatBytes(uint64(len(zipData))))

	return &DumpResult{
		ZipData:    zipData,
		RawBytes:   rawBytes,
		ElapsedSec: time.Since(start).Seconds(),
	}, nil
}

// compressFileToMemory reads a file from disk and returns its ZIP-compressed bytes.
func compressToZip(rawFile, entryName string) ([]byte, error) {
	src, err := os.Open(rawFile)
	if err != nil {
		return nil, fmt.Errorf("open raw file: %w", err)
	}
	defer src.Close()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(entryName)
	if err != nil {
		return nil, fmt.Errorf("zip create entry: %w", err)
	}
	if _, err := io.Copy(w, src); err != nil {
		return nil, fmt.Errorf("zip copy: %w", err)
	}
	if err := zw.Close(); err != nil {
		return nil, fmt.Errorf("zip close: %w", err)
	}
	return buf.Bytes(), nil
}

// resolveWinpmem searches for a winpmem executable in the collector's directory.
func resolveWinpmem() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to determine executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)

	// Make list of conseivable winpmem file names.
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

// formatBytes returns a human-readable string representation of a file size.
func formatBytes(b uint64) string {
	const (
		KB = uint64(1024)
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
