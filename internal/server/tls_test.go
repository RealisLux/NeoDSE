// File purpose: Verifies that generated HTTPS certificates are browser-compatible and correctly scoped.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/provisioning"
)

// TestCertificateReplacementInstallsMatchingPair checks usable keys and intended permissions.
func TestCertificateReplacementInstallsMatchingPair(t *testing.T) {
	directory := t.TempDir()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	certificate, key, err := generateServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	writer := func(path string, contents []byte, mode os.FileMode, _, _ string) error {
		return provisioning.AtomicWrite(path, contents, mode)
	}
	if err := replaceCertificateFilesWithLock(certPath, keyPath, certificate, key, writer, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("installed TLS pair is unusable: %v", err)
	}
	for path, mode := range map[string]os.FileMode{certPath: 0o644, keyPath: 0o640} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != mode {
			t.Errorf("incorrect TLS file permissions: %s: %v", path, err)
		}
	}
}

// TestCertificateReplacementRejectsUnsafePaths verifies both targets before publishing either.
func TestCertificateReplacementRejectsUnsafePaths(t *testing.T) {
	directory := t.TempDir()
	certPath := filepath.Join(directory, "server.crt")
	if err := os.WriteFile(certPath, []byte("original certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "server.key")
	if err := os.Symlink(certPath, link); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{certPath, link, directory} {
		writer := func(string, []byte, os.FileMode, string, string) error {
			t.Error("unsafe key path was detected only after publication started")
			return errors.New("unexpected write")
		}
		if err := replaceCertificateFilesWithLock(certPath, path, []byte("new certificate"), []byte("new key"), writer, nil); err == nil {
			t.Errorf("unsafe certificate/key combination was accepted: %s", path)
		}
	}
}

// TestCertificateReplacementRejectsConcurrentWriter prevents interleaved certificate/key pairs.
func TestCertificateReplacementRejectsConcurrentWriter(t *testing.T) {
	directory := t.TempDir()
	lock, err := provisioning.LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	writer := func(string, []byte, os.FileMode, string, string) error {
		t.Error("concurrent replacement reached the file writer")
		return nil
	}
	if err := replaceCertificateFilesWithLock(filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key"), nil, nil, writer, nil); err == nil {
		t.Fatal("concurrent certificate replacement was admitted")
	}
	otherLock, err := provisioning.LockDirectory(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer otherLock.Close()
	if err := replaceCertificateFilesWithLock(filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key"), nil, nil, writer, otherLock); err == nil {
		t.Fatal("unrelated directory lock bypassed concurrent-writer protection")
	}
}

// TestCertificateReplacementReusesBootstrapLock permits custom bootstrap paths
// in the already locked WireGuard directory without releasing the caller's lock.
func TestCertificateReplacementReusesBootstrapLock(t *testing.T) {
	directory := t.TempDir()
	lock, err := provisioning.LockDirectory(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
	certificate, key, err := generateServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	writer := func(path string, contents []byte, mode os.FileMode, _, _ string) error {
		return provisioning.AtomicWrite(path, contents, mode)
	}
	if err := replaceCertificateFilesWithLock(certPath, keyPath, certificate, key, writer, lock); err != nil {
		t.Fatal(err)
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		t.Fatalf("installed TLS pair is unusable: %v", err)
	}
	if second, err := provisioning.LockDirectory(directory); err == nil {
		_ = second.Close()
		t.Fatal("certificate replacement released the caller's bootstrap lock")
	}
}

// TestCertificateReplacementFailureRestoresPair covers failures before and after a rename.
func TestCertificateReplacementFailureRestoresPair(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, failAfterWrite := range []bool{false, true} {
			name := "new"
			if existing {
				name = "existing"
			}
			if failAfterWrite {
				name += "-after-publication"
			}
			t.Run(name, func(t *testing.T) {
				directory := t.TempDir()
				certPath, keyPath := filepath.Join(directory, "server.crt"), filepath.Join(directory, "server.key")
				original := map[string]string{certPath: "original certificate", keyPath: "original key"}
				if existing {
					for path, value := range original {
						if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				}
				failure := errors.New("injected key installation failure")
				writer := func(path string, contents []byte, mode os.FileMode, _, _ string) error {
					if path == keyPath && !failAfterWrite {
						return failure
					}
					if err := provisioning.AtomicWrite(path, contents, mode); err != nil {
						return err
					}
					if path == keyPath {
						return failure
					}
					return nil
				}
				err := replaceCertificateFilesWithLock(certPath, keyPath, []byte("new certificate"), []byte("new key"), writer, nil)
				if !errors.Is(err, failure) {
					t.Fatalf("lost installation error: %v", err)
				}
				for path, want := range original {
					value, err := os.ReadFile(path)
					if !existing {
						if !errors.Is(err, os.ErrNotExist) {
							t.Errorf("partial bootstrap left %s: %v", path, err)
						}
						continue
					}
					if err != nil || string(value) != want {
						t.Errorf("TLS pair was not restored: %s: %q, %v", path, value, err)
					}
					if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
						t.Errorf("original permissions were not restored: %s: %v", path, err)
					}
				}
			})
		}
	}
}

// TestGenerateServerCertificateUsesECDSAP256 verifies generate server certificate uses ecdsap 256.
func TestGenerateServerCertificateUsesECDSAP256(t *testing.T) {
	address := net.ParseIP("10.4.10.65")
	certificatePEM, keyPEM, err := generateServerCertificate([]net.IP{address})
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		t.Fatal("certificate PEM was not generated")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, ok := certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok || publicKey.Curve.Params().Name != "P-256" {
		t.Fatalf("certificate public key is %T, want ECDSA P-256", certificate.PublicKey)
	}
	if certificate.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("signature algorithm is %s, want ECDSA-SHA256", certificate.SignatureAlgorithm)
	}
	if err := certificate.VerifyHostname(address.String()); err != nil {
		t.Fatalf("controller address is absent from certificate SANs: %v", err)
	}
	if err := certificate.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatalf("loopback address is absent from certificate SANs: %v", err)
	}
	if len(certificate.IPAddresses) != 2 {
		t.Fatalf("certificate IP SANs = %v, want loopback and custom address", certificate.IPAddresses)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		t.Fatal("PKCS#8 private key PEM was not generated")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("private key is %T, want ECDSA", parsedKey)
	}
}

// TestGenerateServerCertificateUsesOnlyLoopbackByDefault verifies bootstrap certificate SANs remain local.
func TestGenerateServerCertificateUsesOnlyLoopbackByDefault(t *testing.T) {
	certificatePEM, _, err := generateServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	certificateBlock, _ := pem.Decode(certificatePEM)
	if certificateBlock == nil || certificateBlock.Type != "CERTIFICATE" {
		t.Fatal("certificate PEM was not generated")
	}
	certificate, err := x509.ParseCertificate(certificateBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.IPAddresses) != 1 || !certificate.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("certificate IP SANs = %v, want only 127.0.0.1", certificate.IPAddresses)
	}
}

// TestGenerateServerCertificateLastsThreeYears keeps the documented renewal period.
func TestGenerateServerCertificateLastsThreeYears(t *testing.T) {
	certificatePEM, _, err := generateServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certificatePEM)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().AddDate(serverCertificateYears, 0, 0)
	if difference := certificate.NotAfter.Sub(want); difference < -time.Hour || difference > time.Hour || serverCertificateYears != 3 {
		t.Fatalf("certificate expires %s, want about %s", certificate.NotAfter, want)
	}
}

// TestCertificateExpiryWarning warns within the renewal window and after expiry.
func TestCertificateExpiryWarning(t *testing.T) {
	now := time.Date(2029, 9, 1, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		notAfter time.Time
		want     string
	}{
		{now.AddDate(1, 0, 0), ""},
		{now.Add(certificateRenewalWarning + time.Hour), ""},
		{now.Add(10*24*time.Hour + time.Hour), "expires on 2029-09-11 (10 days)"},
		{now.Add(-time.Hour), "expired on 2029-09-01"},
	} {
		warning := certificateExpiryWarning(test.notAfter, now)
		if (test.want == "") != (warning == "") || !strings.Contains(warning, test.want) {
			t.Errorf("expiry %s warning = %q, want %q", test.notAfter, warning, test.want)
		}
	}
	var reports []string
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reportCertificateExpiry(ctx, now.Add(-time.Hour), func() time.Time { return now }, func(format string, values ...any) {
		reports = append(reports, fmt.Sprintf(format, values...))
	})
	if len(reports) != 2 || !strings.Contains(reports[0], "valid until 2029-09-01") || !strings.Contains(reports[1], "renew-certificate") {
		t.Fatalf("startup certificate reports = %q", reports)
	}
}

// TestRenewalKeepsGeneratedCertificateAddresses renews controller-generated
// certificates in place and refuses to silently replace an organizational one.
func TestRenewalKeepsGeneratedCertificateAddresses(t *testing.T) {
	directory := t.TempDir()
	write := func(name string, contents []byte) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	lan, _, err := generateServerCertificate([]net.IP{net.ParseIP("192.168.50.10")})
	if err != nil {
		t.Fatal(err)
	}
	loopback, _, err := generateServerCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if addresses, err := renewableCertificateAddresses(write("lan.crt", lan)); err != nil || len(addresses) != 1 || !addresses[0].Equal(net.ParseIP("192.168.50.10")) {
		t.Fatalf("LAN certificate addresses = %v, %v", addresses, err)
	}
	if addresses, err := renewableCertificateAddresses(write("loopback.crt", loopback)); err != nil || len(addresses) != 0 {
		t.Fatalf("loopback certificate addresses = %v, %v", addresses, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "controller.example"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	organizational := write("organizational.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	for _, path := range []string{organizational, write("invalid.crt", []byte("not a certificate")), filepath.Join(directory, "missing.crt")} {
		if _, err := renewableCertificateAddresses(path); err == nil {
			t.Errorf("%s was accepted for implicit renewal", filepath.Base(path))
		}
	}
}
