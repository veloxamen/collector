//go:build windows

package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadPublicKey reads an RSA public key from a .pub file.
// Supports PKIX ("PUBLIC KEY") and PKCS#1 ("RSA PUBLIC KEY") PEM formats.
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

// LoadPrivateKey reads an RSA private key from a .pri file.
// Supports PKCS#1 ("RSA PRIVATE KEY") and PKCS#8 ("PRIVATE KEY") PEM formats.
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key (%s): %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("PKCS8 parse failed: %w", err)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA private key: %s", path)
		}
		return rsaKey, nil
	default:
		return nil, fmt.Errorf("unsupported PEM type %q in %s", block.Type, path)
	}
}

// FindPubKeyPath returns the path to the first *.pub file in the same directory
// as the running executable.
func FindPubKeyPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("failed to get executable path: %w", err)
	}
	exeDir := filepath.Dir(exePath)
	matches, err := filepath.Glob(filepath.Join(exeDir, "*.pub"))
	if err != nil || len(matches) == 0 {
		return "", fmt.Errorf("no *.pub file found in %s", exeDir)
	}
	return matches[0], nil
}

// KeyBaseName returns the stem of the key filename (e.g. "2026q2" from "2026q2.pub").
// This is used as the output file extension.
func KeyBaseName(keyPath string) string {
	base := filepath.Base(keyPath)
	// Strip known extensions: .pub, .pri, .pem
	for _, ext := range []string{".pub", ".pri", ".pem"} {
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
