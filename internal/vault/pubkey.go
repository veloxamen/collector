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

// Package vault provides RSA-OAEP and AES-256-GCM encryption capabilities
// for the forensic artifact collector.
package vault

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadPublicKey reads and parses an RSA public key from a PEM-encoded file.
// Supports both PKIX (SubjectPublicKeyInfo) and PKCS#1 PEM formats.
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key (%s): %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKIX parse failed: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key: %s", path)
		}
		return rsaPub, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %s", block.Type, path)
	}
}

// FindPubKeyPath locates the first public key file (alphabetical order)
// in the executable's directory.
func FindPubKeyPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)

	patterns := []string{"*.pub", "*.pem"}
	var matches []string
	for _, p := range patterns {
		matches, err = filepath.Glob(filepath.Join(exeDir, p))
		if err == nil && len(matches) > 0 {
			break
		}
	}

	if len(matches) == 0 {
		return "", fmt.Errorf("no .pub or .pem file found in %s", exeDir)
	}

	return matches[0], nil
}

// KeyBaseName returns the file stem of the public key to be used to
// include the key identifier in the output filename.
func KeyBaseName(keyPath string) string {
	base := filepath.Base(keyPath)
	for _, ext := range []string{".pub", ".pem"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			return base[:len(base)-len(ext)]
		}
	}
	ext := filepath.Ext(base)
	if ext != "" {
		return base[:len(base)-len(ext)]
	}
	return base
}
