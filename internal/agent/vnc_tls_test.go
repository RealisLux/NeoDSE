// File purpose: Verifies authenticated VNC TLS, downgrade rejection and credential confidentiality.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"image/jpeg"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// rfbTLSFixture creates an independent loopback identity and its sole trust anchor.
func rfbTLSFixture(t *testing.T, mutate func(*x509.Certificate)) (tls.Certificate, *tls.Config, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	configuration, err := vncTLSConfig(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, configuration, encoded
}

// serveTestVeNCrypt performs the public 0.2 X509Plain upgrade without accepting alternate modes.
func serveTestVeNCrypt(connection net.Conn, configuration *tls.Config) (*tls.Conn, error) {
	if _, err := io.WriteString(connection, "RFB 003.008\n"); err != nil {
		return nil, err
	}
	if err := expectBytes(connection, []byte("RFB 003.008\n")); err != nil {
		return nil, err
	}
	if _, err := connection.Write([]byte{3, 19, 30, 1}); err != nil {
		return nil, err
	}
	if err := expectBytes(connection, []byte{19}); err != nil {
		return nil, err
	}
	if _, err := connection.Write([]byte{0, 2}); err != nil {
		return nil, err
	}
	if err := expectBytes(connection, []byte{0, 2}); err != nil {
		return nil, err
	}
	if _, err := connection.Write([]byte{0, 1, 0, 0, 1, 6}); err != nil {
		return nil, err
	}
	if err := expectBytes(connection, []byte{0, 0, 1, 6}); err != nil {
		return nil, err
	}
	if _, err := connection.Write([]byte{1}); err != nil {
		return nil, err
	}
	secure := tls.Server(connection, configuration)
	if err := secure.Handshake(); err != nil {
		return nil, err
	}
	return secure, nil
}

// TestVNCTLSCertificateFailures rejects impersonation before sending the PAM token.
func TestVNCTLSCertificateFailures(t *testing.T) {
	for _, mode := range []string{"untrusted", "expired", "wrong-address", "old-tls"} {
		t.Run(mode, func(t *testing.T) {
			certificate, configuration, _ := rfbTLSFixture(t, func(certificate *x509.Certificate) {
				if mode == "expired" {
					certificate.NotAfter = time.Now().Add(-time.Minute)
				}
				if mode == "wrong-address" {
					certificate.IPAddresses = []net.IP{net.ParseIP("127.0.0.2")}
				}
			})
			if mode == "untrusted" {
				_, configuration, _ = rfbTLSFixture(t, nil)
			}
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(2 * time.Second))
			received := make(chan bool, 1)
			go func() {
				defer server.Close()
				policy := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true}
				if mode == "old-tls" {
					policy.MinVersion = tls.VersionTLS10
					policy.MaxVersion = tls.VersionTLS11
				}
				secure, err := serveTestVeNCrypt(server, policy)
				if err != nil {
					received <- false
					return
				}
				var first [1]byte
				n, _ := secure.Read(first[:])
				received <- n != 0
			}()
			viewer := newRFBViewer(client, "must-not-leak", configuration)
			if err := viewer.initialize(); err == nil {
				t.Fatal("untrusted TLS connection accepted")
			}
			client.Close()
			if <-received {
				t.Fatal("PAM credentials sent before verified TLS")
			}
		})
	}
}

// TestVNCTLSNoDowngrade rejects legacy authentication and unauthenticated VeNCrypt modes.
func TestVNCTLSNoDowngrade(t *testing.T) {
	for _, mode := range []string{"legacy", "version", "version-rejected", "plain", "anonymous-tls", "no-password", "empty", "upgrade-rejected"} {
		t.Run(mode, func(t *testing.T) {
			_, configuration, _ := rfbTLSFixture(t, nil)
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			_ = server.SetDeadline(time.Now().Add(time.Second))
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				_, err := io.WriteString(server, "RFB 003.008\n")
				if err != nil {
					done <- err
					return
				}
				if err = expectBytes(server, []byte("RFB 003.008\n")); err != nil {
					done <- err
					return
				}
				offered := []byte{1, 19}
				if mode == "legacy" {
					offered = []byte{3, 1, 2, 30}
				}
				if _, err = server.Write(offered); err != nil {
					done <- err
					return
				}
				if mode == "legacy" {
					var b [1]byte
					n, _ := server.Read(b[:])
					if n != 0 {
						done <- io.ErrUnexpectedEOF
					} else {
						done <- nil
					}
					return
				}
				if err = expectBytes(server, []byte{19}); err != nil {
					done <- err
					return
				}
				version := []byte{0, 2}
				if mode == "version" {
					version[1] = 1
				}
				if _, err = server.Write(version); err != nil {
					done <- err
					return
				}
				if mode != "version" {
					if err = expectBytes(server, []byte{0, 2}); err != nil {
						done <- err
						return
					}
					status := byte(0)
					if mode == "version-rejected" {
						status = 1
					}
					if _, err = server.Write([]byte{status}); err != nil {
						done <- err
						return
					}
					if status == 0 {
						subtype := uint32(262)
						switch mode {
						case "plain":
							subtype = 256
						case "anonymous-tls":
							subtype = 259
						case "no-password":
							subtype = 260
						}
						count := byte(1)
						if mode == "empty" {
							count = 0
						}
						if _, err = server.Write([]byte{count}); err != nil {
							done <- err
							return
						}
						if count != 0 {
							if err = binary.Write(server, binary.BigEndian, subtype); err != nil {
								done <- err
								return
							}
						}
						if mode == "upgrade-rejected" {
							if err = expectBytes(server, []byte{0, 0, 1, 6}); err != nil {
								done <- err
								return
							}
							if _, err = server.Write([]byte{0}); err != nil {
								done <- err
								return
							}
						}
					}
				}
				var b [1]byte
				n, _ := server.Read(b[:])
				if n != 0 {
					done <- io.ErrUnexpectedEOF
				} else {
					done <- nil
				}
			}()
			viewer := newRFBViewer(client, "must-not-leak", configuration)
			if err := viewer.initialize(); err == nil {
				t.Fatal("insecure mode accepted")
			}
			client.Close()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestVNCTLSVersions confirms encrypted image streaming with TLS 1.2 and 1.3.
func TestVNCTLSVersions(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			certificate, configuration, _ := rfbTLSFixture(t, nil)
			configuration.MinVersion = version
			configuration.MaxVersion = version
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			done := make(chan error, 1)
			go func() { done <- serveTestRFB(server, certificate) }()
			viewer := newRFBViewer(client, "one-use-token", configuration)
			if err := viewer.initialize(); err != nil {
				t.Fatal(err)
			}
			frame, err := viewer.nextJPEG()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = jpeg.Decode(bytes.NewReader(frame)); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestVNCTrustPEM rejects empty, malformed, chained and unrelated PEM inputs.
func TestVNCTrustPEM(t *testing.T) {
	_, _, certificate := rfbTLSFixture(t, nil)
	for _, contents := range [][]byte{nil, []byte("invalid"), append([]byte("garbage"), certificate...), append(append([]byte(nil), certificate...), certificate...), append(append([]byte(nil), certificate...), []byte("garbage")...), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}})} {
		if _, err := vncTLSConfig(contents); err == nil {
			t.Fatal("invalid trust accepted")
		}
	}
}
