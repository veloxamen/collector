// Package report generates collection result reports.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"collector/internal/collect"
	"collector/internal/config"
)

// ── Entry Result Types ────────────────────────────────────────────────────────

type entryStatus int

const (
	statusSuccess entryStatus = iota
	statusPartial             // some files failed
	statusSkipped             // zero files found
	statusFailure
)

// EntryResult aggregates the collection result for one config.Entry row.
type EntryResult struct {
	Entry   config.Entry
	Status  entryStatus
	Results []collect.CollectionResult
	ErrMsg  string
}

// ── Report ────────────────────────────────────────────────────────────────────

// Report holds the results of a complete collection session.
type Report struct {
	timestamp string
	hostname  string
	entries   []EntryResult
	memDump   *memoryDumpInfo // nil = not attempted
}

// New creates a new Report for a collection session.
func New(hostname string) *Report {
	return &Report{hostname: hostname}
}

// ── Add Methods ───────────────────────────────────────────────────────────────

func (r *Report) AddSuccess(entry config.Entry, results []collect.CollectionResult) {
	r.entries = append(r.entries, EntryResult{
		Entry:   entry,
		Status:  statusSuccess,
		Results: results,
	})
}

func (r *Report) AddPartial(entry config.Entry, results []collect.CollectionResult, errMsg string) {
	r.entries = append(r.entries, EntryResult{
		Entry:   entry,
		Status:  statusPartial,
		Results: results,
		ErrMsg:  errMsg,
	})
}

func (r *Report) AddSkipped(entry config.Entry) {
	r.entries = append(r.entries, EntryResult{
		Entry:  entry,
		Status: statusSkipped,
	})
}

func (r *Report) AddFailure(entry config.Entry, errMsg string) {
	r.entries = append(r.entries, EntryResult{
		Entry:  entry,
		Status: statusFailure,
		ErrMsg: errMsg,
	})
}

// ── Aggregation ───────────────────────────────────────────────────────────────

func (r *Report) totalFiles() int {
	n := 0
	for _, e := range r.entries {
		n += len(e.Results)
	}
	return n
}

func (r *Report) countByStatus(s entryStatus) int {
	n := 0
	for _, e := range r.entries {
		if e.Status == s {
			n++
		}
	}
	return n
}

func totalBytes(results []collect.CollectionResult) uint64 {
	var t uint64
	for _, r := range results {
		t += r.BytesCopied
	}
	return t
}

// ── Console Output ────────────────────────────────────────────────────────────

func (r *Report) PrintSummary() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║               Collection Summary                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  Hostname       : %s\n", r.hostname)
	if r.memDump != nil {
		if r.memDump.success {
			fmt.Printf("  Memory Dump    : ✓ %s (%.1f sec)\n",
				r.memDump.zipEntry, r.memDump.elapsedSec)
		} else {
			fmt.Printf("  Memory Dump    : ✗ failed (%s)\n", r.memDump.errMsg)
		}
	} else {
		fmt.Printf("  Memory Dump    : - skipped\n")
	}
		fmt.Printf("  Entries        : %d\n", len(r.entries))
	fmt.Printf("  Success        : %d entries (%d files)\n",
		r.countByStatus(statusSuccess)+r.countByStatus(statusPartial), r.totalFiles())
	if r.countByStatus(statusSkipped) > 0 {
		fmt.Printf("  Skipped        : %d entries (no files found)\n", r.countByStatus(statusSkipped))
	}
	if r.countByStatus(statusFailure) > 0 {
		fmt.Printf("  Failed         : %d entries\n", r.countByStatus(statusFailure))
	}
	fmt.Println()

	for _, e := range r.entries {
		switch e.Status {
		case statusSuccess:
			fmt.Printf("  ✓ [%s] %s\n", e.Entry.Type, e.Entry.Path)
			fmt.Printf("      %d file(s) / %s\n", len(e.Results), formatBytes(totalBytes(e.Results)))
		case statusPartial:
			fmt.Printf("  △ [%s] %s\n", e.Entry.Type, e.Entry.Path)
			fmt.Printf("      %d file(s) collected (partial failure: %s)\n", len(e.Results), e.ErrMsg)
		case statusSkipped:
			fmt.Printf("  ~ [%s] %s — no files found\n", e.Entry.Type, e.Entry.Path)
		case statusFailure:
			fmt.Printf("  ✗ [%s] %s\n", e.Entry.Type, e.Entry.Path)
			fmt.Printf("      Error: %s\n", e.ErrMsg)
		}
	}
	fmt.Println()
}

// ── Text Report ───────────────────────────────────────────────────────────────

func (r *Report) writeText(w io.Writer) {
	fmt.Fprintln(w, "Artifact Collection Report")
	fmt.Fprintln(w, "==========================")
	fmt.Fprintf(w, "Hostname   : %s\n", r.hostname)
		fmt.Fprintf(w, "Generated  : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Entries    : %d total / %d success / %d skip / %d fail\n\n",
		len(r.entries),
		r.countByStatus(statusSuccess)+r.countByStatus(statusPartial),
		r.countByStatus(statusSkipped),
		r.countByStatus(statusFailure),
	)
	fmt.Fprintln(w, "--------------------------")

	for _, e := range r.entries {
		recursive := "NO"
		if e.Entry.Recursive {
			recursive = "YES"
		}
		switch e.Status {
		case statusSuccess, statusPartial:
			statusStr := "SUCCESS"
			if e.Status == statusPartial {
				statusStr = "PARTIAL"
			}
			fmt.Fprintf(w, "[%s] %s  %s\n", statusStr, string(e.Entry.Type), e.Entry.Path)
			fmt.Fprintf(w, "  Path      : %s\n", e.Entry.Path)
			fmt.Fprintf(w, "  Recursive : %s\n", recursive)
			fmt.Fprintf(w, "  Files     : %d (%s total)\n", len(e.Results), formatBytes(totalBytes(e.Results)))
			if e.ErrMsg != "" {
				fmt.Fprintf(w, "  Warning   : %s\n", e.ErrMsg)
			}
			for _, res := range e.Results {
				if res.SHA256 != "" {
					fmt.Fprintf(w, "    - %s (%s)  %s\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied), res.SHA256)
				} else {
					fmt.Fprintf(w, "    - %s (%s)\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied))
				}
			}
		case statusSkipped:
			fmt.Fprintf(w, "[SKIPPED] %s\n", e.Entry.Type)
			fmt.Fprintf(w, "  Path : %s\n", e.Entry.Path)
		case statusFailure:
			fmt.Fprintf(w, "[FAILED] %s\n", e.Entry.Type)
			fmt.Fprintf(w, "  Path  : %s\n", e.Entry.Path)
			fmt.Fprintf(w, "  Error : %s\n", e.ErrMsg)
		}
		fmt.Fprintln(w)
	}
}

func (r *Report) SaveText(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r.writeText(f)
	return nil
}

func (r *Report) ToTextBytes() []byte {
	var buf bytes.Buffer
	r.writeText(&buf)
	return buf.Bytes()
}

// ── JSON Report ───────────────────────────────────────────────────────────────

func (r *Report) writeJSON(w io.Writer) error {
	type fileEntry struct {
		Name       string `json:"name"`
		Source     string `json:"source"`
		CryptEntry string `json:"crypt_entry"`
		Bytes      uint64 `json:"bytes"`
		SHA256     string `json:"sha256,omitempty"`
	}
	type entryJSON struct {
		Type      string      `json:"type"`
		Category  string      `json:"category,omitempty"`
		Recursive bool        `json:"recursive"`
		Path      string      `json:"path"`
		Status    string      `json:"status"`
		Files     []fileEntry `json:"files,omitempty"`
		Error     string      `json:"error,omitempty"`
	}
	type rootJSON struct {
		Report struct {
			Hostname   string `json:"hostname"`
			Timestamp  string `json:"timestamp"`
			Entries    int    `json:"entries"`
			TotalFiles int    `json:"total_files"`
		} `json:"report"`
		Artifacts []entryJSON `json:"artifacts"`
	}

	var root rootJSON
	root.Report.Hostname = r.hostname
	root.Report.Timestamp = r.timestamp
	root.Report.Entries = len(r.entries)
	root.Report.TotalFiles = r.totalFiles()

	for _, e := range r.entries {
		statusStr := map[entryStatus]string{
			statusSuccess: "success",
			statusPartial: "partial",
			statusSkipped: "skipped",
			statusFailure: "failed",
		}[e.Status]

		ej := entryJSON{
			Type:      string(e.Entry.Type),
			Category:  e.Entry.Category,
			Recursive: e.Entry.Recursive,
			Path:      e.Entry.Path,
			Status:    statusStr,
			Error:     e.ErrMsg,
		}
		for _, res := range e.Results {
			ej.Files = append(ej.Files, fileEntry{
				Name:       filepath.Base(res.OutputPath),
				Source:     res.SourcePath,
				CryptEntry: res.OutputPath,
				Bytes:      res.BytesCopied,
				SHA256:     res.SHA256,
			})
		}
		root.Artifacts = append(root.Artifacts, ej)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

func (r *Report) SaveJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.writeJSON(f)
}

func (r *Report) ToJSONBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := r.writeJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

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
		return fmt.Sprintf("%d bytes", b)
	}
}

// ── Memory Dump Recording ─────────────────────────────────────────────────────

type memoryDumpInfo struct {
	success    bool
	zipEntry   string
	bytes      uint64
	elapsedSec float64
	errMsg     string
}

// AddMemoryDumpSuccess records a successful memory dump.
func (r *Report) AddMemoryDumpSuccess(zipEntry string, bytes uint64, elapsedSec float64) {
	r.memDump = &memoryDumpInfo{
		success:    true,
		zipEntry:   zipEntry,
		bytes:      bytes,
		elapsedSec: elapsedSec,
	}
}

// AddMemoryDumpSkipped records a failed or skipped memory dump.
func (r *Report) AddMemoryDumpSkipped(errMsg string) {
	r.memDump = &memoryDumpInfo{success: false, errMsg: errMsg}
}
