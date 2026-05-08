//go:build windows

// Package main implements a forensic artifact collector for Windows.
// It collects system artifacts and physical memory into an RSA-encrypted bundle.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"collector/internal/collect"
	"collector/internal/config"
	"collector/internal/memory"
	"collector/internal/privilege"
	"collector/internal/report"
	"collector/internal/vault"
)

func main() {
	doMem := flag.Bool("mem", false, "Acquire physical memory dump before artifact collection")
	configFile := flag.String("config", "", "Artifact definition JSON (default: built-in)")
	outputDir := flag.String("output", "", "Output directory (default: current directory)")
	doHash := flag.Bool("hash", false, "Compute SHA-256 hashes")
	jsonReport := flag.Bool("json-report", false, "Also write a JSON report")
	verbose := flag.Bool("verbose", false, "Enable verbose logging, mainly for debug")
	flag.Parse()

	if *verbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	} else {
		log.SetOutput(discard{})
	}

	// Request Administrator privileges via UAC if not already elevated.
	if !privilege.IsAdmin() {
		fmt.Println("[*] Requesting Administrator privileges (UAC)...")
		if err := privilege.RelaunchElevated(); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] UAC elevation failed: %v\n", err)
			WaitAndClose()
		}
		os.Exit(0)
	}

	// Locate the RSA public key file in the executable directory.
	pubPath, err := vault.FindPubKeyPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		fmt.Fprintf(os.Stderr, "        Place the RSA public key file (*.pub) in the same directory as the executable.\n")
		WaitAndClose()
	}

	hostname, _ := os.Hostname()
	keyBase := vault.KeyBaseName(pubPath)

	outDir := *outputDir
	if outDir == "" {
		outDir = execDir()
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Cannot create output directory: %v\n", err)
		WaitAndClose()
	}

	// Generate the name of result : <hostname>.<keybase>  (e.g. "DESKTOP-ABC.2026q2")
	resultFile := filepath.Join(outDir, hostname+"."+keyBase)

	// Record starting time.
	starttime := time.Now()

	// Initialize report package.
	rep := report.New(starttime, hostname)

	fmt.Printf("collector  host=%s  key=%s start=%s\n", hostname, keyBase, rep.FormatTime(starttime))
	fmt.Printf("  output → %s\n\n", resultFile)

	// Load RSA public key.
	pub, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to load public key: %v\n", err)
		WaitAndClose()
	}

	// Initialize encryption writer.
	ew, err := vault.NewEncWriter(resultFile, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to create encrypted file: %v\n", err)
		WaitAndClose()
	}
	// abortAndClose removes the incomplete output file and exits.
	abortAndClose := func() {
		ew.Close() //nolint:errcheck
		os.Remove(resultFile)
		WaitAndClose()
	}

	// Dump loaded memory if the option is chosen.
	if *doMem {
		fmt.Println("[MEM] Acquiring physical memory dump...")
		if err := privilege.EnableDebugPrivilege(); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Could not enable SeDebugPrivilege: %v\n", err)
		}
		result, err := memory.AcquireAndCompress(hostname)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! Memory dump failed: %v\n", err)
			rep.AddMemoryDumpSkipped(err.Error())
		} else {
			if err := ew.WriteEntry("memdump.zip", result.ZipData); err != nil {
				fmt.Fprintf(os.Stderr, "  ! Failed to write memdump.zip: %v\n", err)
				rep.AddMemoryDumpSkipped("write to bundle failed: " + err.Error())
			} else {
				rep.AddMemoryDumpSuccess("memdump.zip", uint64(len(result.ZipData)), result.ElapsedSec)
				fmt.Printf("  SUCCESS memdump.zip  raw=%.2f GB  time=%.0fs\n",
					float64(result.RawBytes)/float64(1<<30), result.ElapsedSec)
			}
		}
		fmt.Println()
	}

	// Load artifact collection configuration.
	fmt.Println("[PREP] Setup config...")
	cfg := config.New()
	if *configFile != "" {
		if err = config.Load(cfg, *configFile); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config: %v\n", err)
			abortAndClose()
		}
	}

	// Enumerate paths based on config.
	fmt.Println("[PREP] Enumerating files to be collected...")
	entries, profiles, err := config.Prepare(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to enumerate collection targets: %v\n", err)
		abortAndClose()
	}
	fmt.Println("  Users to be collected:")
	for _, p := range profiles {
		fmt.Printf("    %s: %s, %s\n", p.SID, p.Username, p.ProfilePath)
	}

	// Register all entries into the report before collection starts.
	for _, entry := range entries {
		rep.GenerateEntry(entry)
	}

	// Enable backup privileges.
	if err := privilege.EnableBackupPrivilege(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to enable backup privilege: %v\n", err)
		abortAndClose()
	}

	// Collect artifacts.
	fmt.Println("[COLLECT] Collecting artifacts...")
	col := collect.New(*doHash, ew)

	for _, entry := range entries {
		fmt.Printf("Target: %s\n", entry.Target)

		label := fmt.Sprintf("[%s] %s", entry.Category, entry.Target)

		if len(entry.Paths) == 0 {
			fmt.Printf("  ~ %s  (skipped: no files found)\n", label)
			// rep.AddSkipped records a skip when the target file does not exist.
			rep.AddSkipped(entry.Category, entry.Target, entry.Target)
			fmt.Printf("  Done: %s, 0 file(s)\n", label)
			continue
		}

		for _, path := range entry.Paths {
			result, err := col.ReadAndEncrypt(path)
			if err != nil {
				fmt.Printf("  Failed: %s, %s\n%v\n", label, path, err)
				rep.AddFailure(entry.Category, entry.Target, map[string]error{path: err})
				continue
			} else if result.OutputPath == "" {
				// fmt.Printf("  ~ %s: %s  (file not found)\n", label, path)
				rep.AddSkipped(entry.Category, entry.Target, path)
				continue
			}
			// fmt.Printf("  ✓ %s: %s\n", label, path)
			rep.AddSuccess(entry.Category, entry.Target, result)
		}
		fmt.Printf("  Done: %s, %d file(s)\n", label, len(entry.Paths))
	}
	col.Close()
	fmt.Println()

	// Finalize and write collection reports to the bundle.
	rep.PrintSummary()
	if err := ew.WriteEntry("collection_report.txt", rep.ToTextBytes()); err != nil {
		fmt.Fprintf(os.Stderr, "  ! Failed to write report: %v\n", err)
	}
	if *jsonReport {
		if b, err := rep.ToJSONBytes(); err == nil {
			ew.WriteEntry("collection_report.json", b)
		} else {
			fmt.Fprintf(os.Stderr, "  ! Failed to serialise JSON report: %v\n", err)
		}
	}

	if err := ew.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to finalize encrypted file: %v\n", err)
		WaitAndClose()
	}
	fmt.Printf("[DONE] %s\n", resultFile)
}

func execDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

// WaitAndClose blocks for user input before exiting the process.
func WaitAndClose() {
	fmt.Println("\nPress any key to close...")
	fmt.Scanln()
	os.Exit(1)
}

// discard is a helper type that ignores all input to satisfy io.Writer.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
