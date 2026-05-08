//go:build windows

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

	// Search public key file in the executing directory.
	patterns := []string{"*.pub", "*.pem"}
	var matches []string
	for _, p := range patterns {
		matches, err = filepath.Glob(filepath.Join(exeDir, p))
		// Exit the loop once a match is found.
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
	// Strip known extensions: .pub, .pem
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
