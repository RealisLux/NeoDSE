// File purpose: Verifies stock Weston authentication through the real PAM helper and JPEG capture.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"context"
	"image/jpeg"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestStockWestonVNC requires the private namespace supplied by check-weston-vnc.sh.
func TestStockWestonVNC(t *testing.T) {
	if os.Getenv("NEODSE_WESTON_TEST") != "1" {
		t.Skip("run make verify-weston-vnc for isolated Weston/PAM integration")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	a := &Agent{}
	if err := a.startVNCAuth(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); a.closeDisplayStreams(); a.workers.Wait() }()
	directory := t.TempDir()
	config := filepath.Join(directory, "weston.ini")
	if err := os.WriteFile(config, []byte("[vnc]\nrefresh-rate=10\n[output]\nname=vnc\nmode=320x180\nresizeable=false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(directory, "weston.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	westonContext, stopWeston := context.WithCancel(context.Background())
	defer stopWeston()
	command := exec.CommandContext(westonContext, "weston", "--backend=vnc", "--renderer=pixman", "--shell=kiosk-shell.so", "--idle-time=0", "--address=127.0.0.1", "--port=5900", "--vnc-tls-key=/var/lib/neodse-vnc/server.key", "--vnc-tls-cert="+vncCertificatePath, "--config="+config)
	command.Stdout, command.Stderr = logFile, logFile
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		stopWeston()
		_ = command.Wait()
		data, _ := os.ReadFile(logFile.Name())
		t.Logf("Weston log:\n%s", data)
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.DialTimeout("tcp4", displayVNCAddress, 100*time.Millisecond)
		if err == nil {
			_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			banner := make([]byte, 12)
			_, readErr := io.ReadFull(c, banner)
			_ = c.Close()
			if readErr == nil && string(banner[:4]) == "RFB " {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("Weston listener did not start")
		}
		time.Sleep(25 * time.Millisecond)
	}
	configuration, err := loadVNCTLSConfig(vncCertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("trust-file-policy", func(t *testing.T) { testVNCTrustFiles(t) })
	var used string
	for _, scenario := range []string{"untrusted certificate", "valid", "replay", "invalid", "authority unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			streamID := strings.Repeat("a", 32)
			token := used
			if scenario == "valid" || scenario == "untrusted certificate" {
				var err error
				token, err = a.prepareVNCCredential(streamID)
				if err != nil {
					t.Fatal(err)
				}
				used = token
			}
			if scenario == "invalid" {
				token = strings.Repeat("b", 43)
			}
			if scenario == "authority unavailable" {
				cancel()
				a.workers.Wait()
			}
			connection, err := net.DialTimeout("tcp4", displayVNCAddress, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			a.displayMu.Lock()
			a.displayStreams = map[string]net.Conn{streamID: connection}
			a.displayMu.Unlock()
			defer a.removeDisplayStream(streamID, connection)
			clientTLS := configuration
			if scenario == "untrusted certificate" {
				_, clientTLS, _ = rfbTLSFixture(t, nil)
			}
			viewer := newRFBViewer(connection, token, clientTLS)
			err = viewer.initialize()
			if scenario != "valid" {
				if err == nil {
					t.Fatal("unauthorized VNC client authenticated")
				}
				if scenario == "untrusted certificate" {
					if _, ok := a.vncCredentialForStream(streamID); !ok {
						t.Fatal("TLS failure consumed PAM token")
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			// Unlike an incremental idle update, the initial full frame must arrive promptly.
			deadlineTimer := time.AfterFunc(5*time.Second, func() { _ = connection.Close() })
			defer deadlineTimer.Stop()
			encoded, err := viewer.nextJPEG()
			if err != nil {
				t.Fatal(err)
			}
			frame, err := jpeg.Decode(bytes.NewReader(encoded))
			if err != nil {
				t.Fatal(err)
			}
			if frame.Bounds().Dx() != 320 || frame.Bounds().Dy() != 180 {
				t.Fatalf("unexpected mirrored image: %v", frame.Bounds())
			}
		})
	}
}

// testVNCTrustFiles checks real file metadata inside the root-mapped integration namespace.
func testVNCTrustFiles(t *testing.T) {
	t.Helper()
	contents, err := os.ReadFile(vncCertificatePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "writable-file", "writable-directory", "symlink", "directory", "oversized", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "server.crt")
			data := contents
			if mode == "oversized" {
				data = make([]byte, 16385)
			}
			if mode == "malformed" {
				data = []byte("invalid")
			}
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "writable-file":
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "writable-directory":
				if err := os.Chmod(directory, 0o777); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				os.Remove(path)
				if err := os.Symlink(vncCertificatePath, path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				os.Remove(path)
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			_, err := loadVNCTLSConfig(path)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("trust result=%v", err)
			}
		})
	}
}
