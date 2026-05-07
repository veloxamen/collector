// Package report provides functionality to generate forensic collection reports
// in text and JSON formats.
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

type entryStatus int

const (
	statusSuccess entryStatus = iota
	statusPartial             // some files failed
	statusSkipped             // zero files found
	statusFailure
)

// EntryResult represents the collection outcome for a single configuration entry.
type EntryResult struct {
	Category  string
	Target    string
	Successes []collect.ResultSet
	Skips     []string
	Failures  []map[string]string // path → error message
	Status    entryStatus
}

// Report maintains the aggregate statistics and detailed results of a collection session.
type Report struct {
	starttime    time.Time
	hostname     string
	results      []EntryResult
	memDump      *memoryDumpInfo // nil if not attempted
	totalCount   int
	successCount int
	skipCount    int
	failureCount int
}

// New initializes a new Report with the given start time and hostname.
func New(starttime time.Time, hostname string) *Report {
	return &Report{starttime: starttime, hostname: hostname}
}

// GenerateEntry initializes a result entry for the specified configuration item.
func (r *Report) GenerateEntry(entry config.Entry) {
	r.results = append(r.results, EntryResult{
		Category: entry.Category,
		Target:   entry.Target,
	})
}

// AddSuccess records a successfully collected artifact and updates the status.
func (r *Report) AddSuccess(category string, target string, result collect.ResultSet) {
	i := r.findIndex(category, target)
	if i < 0 {
		return
	}
	r.results[i].Successes = append(r.results[i].Successes, result)
	r.totalCount++
	r.successCount++
	r.updateStatus(i)
}

// AddSkipped records an artifact that was skipped (e.g., file not found).
func (r *Report) AddSkipped(category string, target string, path string) {
	i := r.findIndex(category, target)
	if i < 0 {
		return
	}
	r.results[i].Skips = append(r.results[i].Skips, path)
	r.skipCount++
	r.updateStatus(i)
}

// AddFailure records an artifact collection error and updates entry status.
func (r *Report) AddFailure(category string, target string, fail map[string]error) {
	i := r.findIndex(category, target)
	if i < 0 {
		return
	}
	// Convert map[string]error → map[string]string for JSON serialisation.
	m := make(map[string]string, len(fail))
	for k, v := range fail {
		m[k] = v.Error()
	}
	r.results[i].Failures = append(r.results[i].Failures, m)
	r.totalCount++
	r.failureCount++
	r.updateStatus(i)
}

// findIndex returns the slice index of the EntryResult matching (category, target),
// or -1 if not found.
func (r *Report) findIndex(category, target string) int {
	for i := range r.results {
		if r.results[i].Category == category && r.results[i].Target == target {
			return i
		}
	}
	return -1
}

// updateStatus recalculates the Status field for results[i] from its current
// Successes / Skips / Failures slices.
func (r *Report) updateStatus(i int) {
	e := &r.results[i]
	hasSuccess := len(e.Successes) > 0
	hasFail := len(e.Failures) > 0
	hasSkip := len(e.Skips) > 0

	switch {
	case hasSuccess && !hasFail:
		e.Status = statusSuccess
	case hasSuccess && hasFail:
		e.Status = statusPartial
	case hasFail && !hasSuccess:
		e.Status = statusFailure
	case hasSkip && !hasSuccess && !hasFail:
		e.Status = statusSkipped
	}
}

// totalBytes calculates the total number of bytes copied.
func totalBytes(results []collect.ResultSet) uint64 {
	var t uint64
	for _, r := range results {
		t += r.BytesCopied
	}
	return t
}

// PrintSummary shows the result summary on the console.
func (r *Report) PrintSummary() {
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║               Collection Summary                     ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("  Hostname       : %s\n", r.hostname)
	if r.memDump != nil {
		if r.memDump.success {
			fmt.Printf("  Memory Dump    : SUCCESS %s (%.1f sec)\n",
				r.memDump.zipEntry, r.memDump.elapsedSec)
		} else {
			fmt.Printf("  Memory Dump    : FAIL (%s)\n", r.memDump.errMsg)
		}
	} else {
		fmt.Printf("  Memory Dump    : - skipped\n")
	}
	fmt.Printf("  Target         : %d entries (%d files)\n", len(r.results), r.totalCount)
	fmt.Printf("  Success        : %d files\n", r.successCount)
	if r.skipCount > 0 {
		fmt.Printf("  Skipped        : %d files\n", r.skipCount)
	}
	if r.failureCount > 0 {
		fmt.Printf("  Failed         : %d files\n", r.failureCount)
	}
	fmt.Println()
}

// WriteText generates the report message for the txt format report.
func (r *Report) writeText(w io.Writer) {
	fmt.Fprintln(w, "Artifact Collection Report")
	fmt.Fprintln(w, "==========================")
	fmt.Fprintf(w, "Hostname   : %s\n", r.hostname)
	fmt.Fprintf(w, "Started    : %s\n", r.starttime.Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Finished   : %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Fprintf(w, "Targets    : %d total / %d success / %d skip / %d fail\n\n",
		len(r.results),
		r.countByStatus(statusSuccess)+r.countByStatus(statusPartial),
		r.countByStatus(statusSkipped),
		r.countByStatus(statusFailure),
	)
	fmt.Fprintln(w, "--------------------------")

	for _, e := range r.results {
		switch e.Status {
		case statusSuccess, statusPartial:
			statusStr := "SUCCESS"
			if e.Status == statusPartial {
				statusStr = "PARTIAL"
			}
			fmt.Fprintf(w, "[%s] [%s] %s\n", statusStr, e.Category, e.Target)
			fmt.Fprintf(w, "  Files     : %d (%s)\n", len(e.Successes), formatBytes(totalBytes(e.Successes)))
			if len(e.Failures) > 0 {
				fmt.Fprintln(w, "  Warnings  :")
				for _, m := range e.Failures {
					for path, msg := range m {
						fmt.Fprintf(w, "    File : %s\n      %s\n", path, msg)
					}
				}
			}
			for _, res := range e.Successes {
				if res.SHA256 != "" {
					fmt.Fprintf(w, "    - %s (%s)  %s\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied), res.SHA256)
				} else {
					fmt.Fprintf(w, "    - %s (%s)\n",
						filepath.Base(res.OutputPath), formatBytes(res.BytesCopied))
				}
			}
		case statusSkipped:
			fmt.Fprintf(w, "[SKIPPED] [%s] %s\n", e.Category, e.Target)
			for _, s := range e.Skips {
				fmt.Fprintf(w, "    - %s\n", s)
			}
		case statusFailure:
			fmt.Fprintf(w, "[FAILED] [%s] %s\n", e.Category, e.Target)
			fmt.Fprintln(w, "  Errors :")
			for _, m := range e.Failures {
				for path, msg := range m {
					fmt.Fprintf(w, "    File : %s\n      %s\n", path, msg)
				}
			}
		}
		fmt.Fprintln(w)
	}
}

// SaveText saves the txt format report file.
func (r *Report) SaveText(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	r.writeText(f)
	return nil
}

// ToTextBytes converts report contents to the txt format suitable byte array.
func (r *Report) ToTextBytes() []byte {
	var buf bytes.Buffer
	r.writeText(&buf)
	return buf.Bytes()
}

// writeJSON generates the report message for the JSON format report.
func (r *Report) writeJSON(w io.Writer) error {
	type fileEntry struct {
		Name       string `json:"name"`
		Source     string `json:"source"`
		CryptEntry string `json:"crypt_entry"`
		Bytes      uint64 `json:"bytes"`
		SHA256     string `json:"sha256,omitempty"`
	}
	type entryJSON struct {
		Category  string              `json:"category,omitempty"`
		Target    string              `json:"path"`
		Status    string              `json:"status"`
		Successes []fileEntry         `json:"successes,omitempty"`
		Skips     []string            `json:"skips,omitempty"`
		Failures  []map[string]string `json:"errors,omitempty"`
	}
	type rootJSON struct {
		Report struct {
			Hostname   string `json:"hostname"`
			Started    string `json:"started"`
			Finished   string `json:"finished"`
			Entries    int    `json:"entries"`
			TotalFiles int    `json:"total_files"`
			Success    int    `json:"success"`
			Skipped    int    `json:"skipped"`
			Failed     int    `json:"failed"`
		} `json:"report"`
		Artifacts []entryJSON `json:"artifacts"`
	}

	var root rootJSON
	root.Report.Hostname = r.hostname
	root.Report.Started = r.FormatTime(r.starttime)
	root.Report.Finished = r.FormatTime(time.Now())
	root.Report.Entries = len(r.results)
	root.Report.TotalFiles = r.totalCount
	root.Report.Success = r.successCount
	root.Report.Skipped = r.skipCount
	root.Report.Failed = r.failureCount

	statusLabel := map[entryStatus]string{
		statusSuccess: "success",
		statusPartial: "partial",
		statusSkipped: "skipped",
		statusFailure: "failed",
	}

	for _, e := range r.results {
		ej := entryJSON{
			Category: e.Category,
			Target:   e.Target,
			Status:   statusLabel[e.Status],
		}
		for _, res := range e.Successes {
			ej.Successes = append(ej.Successes, fileEntry{
				Name:       filepath.Base(res.OutputPath),
				Source:     res.SourcePath,
				CryptEntry: res.OutputPath,
				Bytes:      res.BytesCopied,
				SHA256:     res.SHA256,
			})
		}
		ej.Skips = append(ej.Skips, e.Skips...)
		ej.Failures = append(ej.Failures, e.Failures...)
		root.Artifacts = append(root.Artifacts, ej)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(root)
}

// SaveText saves the JSON format report file.
func (r *Report) SaveJSON(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return r.writeJSON(f)
}

// ToJSONBytes converts report contents to the JSON report suitable byte array.
func (r *Report) ToJSONBytes() ([]byte, error) {
	var buf bytes.Buffer
	if err := r.writeJSON(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// formatBytes converts a byte count into a human-readable string with appropriate units.
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

func (r *Report) countByStatus(s entryStatus) int {
	cnt := 0
	for _, e := range r.results {
		if e.Status == s {
			cnt++
		}
	}
	return cnt
}

// FormatTime converts timestamp to local human readable format.
func (r *Report) FormatTime(timestamp time.Time) string {
	return timestamp.Local().Format("2006-01-02 15:04:05")
}
