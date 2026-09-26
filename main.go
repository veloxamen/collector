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

// Package main implements a forensic artifact collector for Windows.
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
	"collector/internal/ntfs"
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
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	doUsnJrnl := flag.Bool("usnjrnl", false, "Also collect $UsnJrnl")
	flag.Parse()

	const maxArtifactBytes uint64 = 1 << 30 // 1 GiB
	ntfs.SetMaxArtifactBytes(maxArtifactBytes)
	fmt.Printf("[*] Build: streaming read path enabled, threshold = %d MB\n", maxArtifactBytes/(1<<20))

	if *verbose {
		log.SetFlags(log.Ltime | log.Lshortfile)
	} else {
		log.SetOutput(discard{})
	}

	if !privilege.IsAdmin() {
		fmt.Fprintln(os.Stderr, "[ERROR] Administrator privileges are required to run this tool.")
		fmt.Fprintln(os.Stderr, "        Launch it via run_elevated.bat, or start it from an elevated command prompt / PowerShell.")
		waitAndClose()
	}

	pubPath, err := vault.FindPubKeyPath()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
		fmt.Fprintf(os.Stderr, "        Place the RSA public key file (*.pub) in the executable directory.\n")
		waitAndClose()
	}

	hostname, _ := os.Hostname()
	keyBase := vault.KeyBaseName(pubPath)

	outDir := *outputDir
	if outDir == "" {
		outDir = execDir()
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Cannot create output directory: %v\n", err)
		waitAndClose()
	}

	resultFile := filepath.Join(outDir, hostname+"."+keyBase)
	starttime := time.Now()
	rep := report.New(starttime, hostname)

	fmt.Printf("collector  host=%s  key=%s start=%s\n", hostname, keyBase, rep.FormatTime(starttime))
	fmt.Printf("  output → %s\n\n", resultFile)

	pub, err := vault.LoadPublicKey(pubPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to load public key: %v\n", err)
		waitAndClose()
	}

	ew, err := vault.NewEncWriter(resultFile, pub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to create encrypted file: %v\n", err)
		waitAndClose()
	}

	abortAndClose := func() {
		ew.Close() //nolint:errcheck
		os.Remove(resultFile)
		waitAndClose()
	}

	if *doMem {
		fmt.Println("[MEM] Acquiring physical memory dump...")
		if err := privilege.EnableDebugPrivilege(); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] Could not enable SeDebugPrivilege: %v\n", err)
		}
		result, err := memory.AcquireAndCompress(hostname, ew)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ! Memory dump failed: %v\n", err)
			rep.AddMemoryDumpSkipped(err.Error())
		} else {
			rep.AddMemoryDumpSuccess(result.ZipEntry, result.ZipBytes, result.ElapsedSec)
			fmt.Printf("  SUCCESS %s  raw=%.2f GB  time=%.0fs\n",
				result.ZipEntry, float64(result.RawBytes)/float64(1<<30), result.ElapsedSec)
		}
		fmt.Println()
	}

	fmt.Println("[PREP] Setup config...")
	cfg := config.New()
	if *configFile != "" {
		if err = config.Load(cfg, *configFile); err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] Failed to load config: %v\n", err)
			abortAndClose()
		}
	}
	if *doUsnJrnl {
		cfg.StaticEntries = append(cfg.StaticEntries, config.UsnJrnlEntry)
		fmt.Println("  $UsnJrnl collection enabled (-usnjrnl)")
	}

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

	for _, entry := range entries {
		rep.GenerateEntry(entry)
	}

	if err := privilege.EnableBackupPrivilege(); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Failed to enable backup privilege: %v\n", err)
		abortAndClose()
	}

	fmt.Println("[COLLECT] Collecting artifacts...")
	col := collect.New(*doHash, ew)

	for _, entry := range entries {
		fmt.Printf("Target: %s\n", entry.Target)
		label := fmt.Sprintf("[%s] %s", entry.Category, entry.Target)

		if len(entry.Paths) == 0 {
			fmt.Printf("  ~ %s  (skipped: no files found)\n", label)
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
				rep.AddSkipped(entry.Category, entry.Target, path)
				continue
			}
			rep.AddSuccess(entry.Category, entry.Target, result)
		}
		fmt.Printf("  Done: %s, %d file(s)\n", label, len(entry.Paths))
	}
	col.Close()
	fmt.Println()

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
		waitAndClose()
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

func waitAndClose() {
	fmt.Println("\nPress any key to close...")
	fmt.Scanln()
	os.Exit(1)
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
