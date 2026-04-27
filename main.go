//go:build windows

// artifact_collector collects Windows forensic artifacts and optionally
// acquires a physical memory dump, all stored in a single RSA-encrypted file.
//
// Usage:
//
//	artifact_collector.exe [options]
//	  -mem                Run memory dump BEFORE artifact collection (requires winpmem)
//	  -config <path>      Artifact definition CSV (default: built-in)
//	  -output <dir>       Output directory (default: current directory)
//	  -hash               Compute SHA-256 hashes (default: true)
//	  -json-report        Also write a JSON report
//	  -verbose            Enable verbose logging
//
// The output file is named:
//
//	<hostname>.<pembase>
//
// where <pembase> is the stem of the public key filename (e.g. "2026q2" from "2026q2.pub").
//
// Output file contents (named entries inside the encrypted bundle):
//   - Artifact files (e.g. "C/Windows/System32/config/SYSTEM")
//   - collection_report.txt
//   - memdump.zip  (only when -mem is specified)
//
// Requirements:
//   - *.pub (RSA public key) in the same directory as the executable
//   - Administrator privileges (self-requested via UAC if not already elevated)
//   - winpmem_mini_x64.exe (or variant) when using -mem
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"collector/internal/collect"
	"collector/internal/config"
	"collector/internal/crypto"
	"collector/internal/memory"
	"collector/internal/privilege"
	"collector/internal/report"
)

func main() {
	doMem := flag.Bool("mem", false, "Acquire physical memory dump before artifact collection")
	configFile := flag.String("config", "", "Artifact definition CSV (default: built-in)")
	outputDir := flag.String("output", "", "Output directory (default: current directory)")
	doHash := flag.Bool("hash", true, "Compute SHA-256 hashes")
	jsonReport := flag.Bool("json-report", false, "Also write a JSON report")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	} else {
		log.SetOutput(discard{})
	}

	// ── UAC self-elevation ────────────────────────────────────────────────────
	if !privilege.IsAdmin() {
		fmt.Println("[*] Requesting Administrator privileges (UAC)...")
		if err := privilege.RelaunchElevated(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] UAC elevation failed: %v\n", err)
			os.Exit(1)
		}
		os.Exit(0)
	}

	// ── Locate public key file ────────────────────────────────────────────────
	pubPath, err := crypto.FindPubKeyPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		fmt.Fprintf(os.Stderr, "        Place the RSA public key file (*.pub) in the same directory as the executable.\n")
		os.Exit(1)
	}

	// ── Load RSA public key ───────────────────────────────────────────────────
	pub, err := crypto.LoadPublicKey(pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to load public key: %v\n", err)
		os.Exit(1)
	}

	// ── Session naming ────────────────────────────────────────────────────────
	hostname, _ := os.Hostname()
	keyBase := crypto.KeyBaseName(pubPath) // e.g. "2026q2"

	outDir := *outputDir
	if outDir == "" {
		outDir = execDir()
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Cannot create output directory: %v\n", err)
		os.Exit(1)
	}

	// Output file: <hostname>.<keybase>  (e.g. "DESKTOP-ABC.2026q2")
	artifactFile := filepath.Join(outDir, hostname+"."+keyBase)

	// ── Load configuration ────────────────────────────────────────────────────
	cfg2 := config.NewNew()
	if *configFile != "" {
		err = config.LoadAndMerge(cfg2, *configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config: %v\n", err)
			os.Exit(1)
		}
	}
	err = config.Extend(cfg2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to extend collection targets: %v\n", err)
		os.Exit(1)
	}
	// old one
	cfg := config.New()
	if *configFile != "" {
		cfg, err = config.Load(*configFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config: %v\n", err)
			os.Exit(1)
		}
	}

	// Enumelate paths based on config

	// ── Enable backup privileges ──────────────────────────────────────────────
	if err := privilege.EnableBackupPrivilege(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to enable backup privilege: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("artifact_collector  host=%s  key=%s\n", hostname, keyBase)
	fmt.Printf("  output → %s\n\n", artifactFile)

	// ── Open encrypted output stream ──────────────────────────────────────────
	ew, err := crypto.NewEncWriter(artifactFile, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to create encrypted file: %v\n", err)
		os.Exit(1)
	}

	rep := report.New(hostname)

	// ── Memory dump (runs BEFORE artifact collection) ─────────────────────────
	if *doMem {
		fmt.Println("[MEM] Acquiring physical memory dump...")
		if err := privilege.EnableDebugPrivilege(); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Could not enable SeDebugPrivilege: %v\n", err)
		}
		result, err := memory.AcquireAndCompress(hostname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ Memory dump failed: %v\n", err)
			rep.AddMemoryDumpSkipped(err.Error())
		} else {
			if err := ew.WriteEntry("memdump.zip", result.ZipData); err != nil {
				fmt.Fprintf(os.Stderr, "  ! Failed to write memdump.zip: %v\n", err)
				rep.AddMemoryDumpSkipped("write to bundle failed: " + err.Error())
			} else {
				rep.AddMemoryDumpSuccess("memdump.zip", uint64(len(result.ZipData)), result.ElapsedSec)
				fmt.Printf("  ✓ memdump.zip  raw=%.2f GB  time=%.0fs\n",
					float64(result.RawBytes)/float64(1<<30), result.ElapsedSec)
			}
		}
		fmt.Println()
	}

	// ── Collect artifacts ─────────────────────────────────────────────────────
	fmt.Println("[COLLECT] Collecting artifacts...")
	col := collect.New(*doHash, ew)

	for _, entry := range cfg.Entries {
		results, err := col.CollectEntry(cfg, entry)
		label := fmt.Sprintf("[%s] %s", entry.Category, entry.Path)
		if err != nil {
			fmt.Printf("  ✗ %s\n      %v\n", label, err)
			rep.AddFailure(entry, err.Error())
			continue
		}
		if len(results) == 0 {
			fmt.Printf("  ~ %s  (skipped: no files)\n", label)
			rep.AddSkipped(entry)
			continue
		}
		fmt.Printf("  ✓ %s  %d file(s)\n", label, len(results))
		rep.AddSuccess(entry, results)
	}
	col.Close()
	fmt.Println()

	// ── Write report into encrypted bundle ────────────────────────────────────
	rep.PrintSummary()
	if err := ew.WriteEntry("collection_report.txt", rep.ToTextBytes()); err != nil {
		fmt.Fprintf(os.Stderr, "  ! Failed to write report: %v\n", err)
	}
	if *jsonReport {
		if b, err := rep.ToJSONBytes(); err == nil {
			ew.WriteEntry("collection_report.json", b)
		}
	}

	if err := ew.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to finalise encrypted file: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("[DONE] %s\n", artifactFile)
}

func execDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
