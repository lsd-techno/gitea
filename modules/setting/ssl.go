// Copyright 2025 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package setting

import (
	"os"
)

// SSL contains SSL/TLS configuration information
var SSL = struct {
	// Core SSL/TLS configuration
	Enabled      bool   `ini:"-"`
	Protocol     string `ini:"PROTOCOL"` // "http" or "https"
	ConfigMethod string `ini:"-"`

	// Certificate and Key files
	CertFile string `ini:"CERT_FILE"`
	KeyFile  string `ini:"KEY_FILE"`

	// File existence and readability status
	CertFileExists   bool `ini:"-"`
	CertFileReadable bool `ini:"-"`
	KeyFileExists    bool `ini:"-"`
	KeyFileReadable  bool `ini:"-"`

	// SSL/TLS requirements
	MinimumVersion   string   `ini:"-"`
	MaximumVersion   string   `ini:"-"`
	CurvePreferences []string `ini:"-"`
	CipherSuites     []string `ini:"-"`

	// ACME Configuration (if using Let's Encrypt/ACME)
	AcmeEnabled   bool   `ini:"-"`
	AcmeURL       string `ini:"-"`
	AcmeEmail     string `ini:"-"`
	AcmeDirectory string `ini:"-"`
	AcmeCARoot    string `ini:"-"`
	AcmeTOS       bool   `ini:"-"`
}{
	Enabled:      false,
	ConfigMethod: "disabled",
}

// loadSSLFrom loads SSL configuration from the server section
func loadSSLFrom(rootCfg ConfigProvider) {
	// Note: SSL configuration is loaded from the [server] section by server.go
	// We use the already loaded variables: CertFile, KeyFile, SSLMinimumVersion, etc.
	// Keep `rootCfg` here for compatibility with other modules
	// and if there are any new variables that may be added in the future to SSL configuration.

	// Initialize SSL config
	SSL.Protocol = string(Protocol)
	SSL.Enabled = (Protocol == HTTPS)
	SSL.ConfigMethod = "disabled"

	// Determine SSL configuration method based on protocol
	if Protocol == HTTPS {
		if EnableAcme {
			SSL.ConfigMethod = "acme"
			SSL.AcmeEnabled = true
			SSL.AcmeURL = AcmeURL
			SSL.AcmeEmail = AcmeEmail
			SSL.AcmeDirectory = AcmeLiveDirectory
			SSL.AcmeCARoot = AcmeCARoot
			SSL.AcmeTOS = AcmeTOS
		} else if CertFile != "" && KeyFile != "" {
			SSL.ConfigMethod = "cert_key"
			SSL.CertFile = CertFile
			SSL.KeyFile = KeyFile

			// Check certificate file existence and readability
			SSL.CertFileExists = checkFileExists(SSL.CertFile)
			SSL.CertFileReadable = checkFileReadable(SSL.CertFile)

			// Check key file existence and readability
			SSL.KeyFileExists = checkFileExists(SSL.KeyFile)
			SSL.KeyFileReadable = checkFileReadable(SSL.KeyFile)
		} else {
			SSL.ConfigMethod = "misconfigured"
		}

		// Update SSL/TLS requirements
		SSL.MinimumVersion = SSLMinimumVersion
		SSL.MaximumVersion = SSLMaximumVersion
		SSL.CurvePreferences = SSLCurvePreferences
		SSL.CipherSuites = SSLCipherSuites
	}
}

// checkFileExists checks if a file exists
func checkFileExists(filePath string) bool {
	if filePath == "" {
		return false
	}
	_, err := os.Stat(filePath)
	return err == nil
}

// checkFileReadable checks if a file exists and is readable
func checkFileReadable(filePath string) bool {
	if filePath == "" {
		return false
	}

	// Check if file exists
	if !checkFileExists(filePath) {
		return false
	}

	// Try to open the file for reading
	file, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer file.Close()

	return true
}
