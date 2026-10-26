// File purpose: Exercises browser interactions using the production asset handler and security policy.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package dashboard

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestDashboardBrowser decodes real framed JPEG HTTP responses under the production CSP.
func TestDashboardBrowser(t *testing.T) {
	if os.Getenv("NEODSE_BROWSER_TEST") != "1" {
		t.Skip("set NEODSE_BROWSER_TEST=1 with GTK/WebKit, Python GI, and Weston installed")
	}
	mux := http.NewServeMux()
	RegisterRoutes(mux)
	var frame bytes.Buffer
	if err := jpeg.Encode(&frame, image.NewRGBA(image.Rect(0, 0, 8, 6)), nil); err != nil {
		t.Fatal(err)
	}
	var nextFrame bytes.Buffer
	red := image.NewRGBA(image.Rect(0, 0, 8, 6))
	draw.Draw(red, red.Bounds(), image.NewUniform(color.RGBA{R: 255, A: 255}), image.Point{}, draw.Src)
	if err := jpeg.Encode(&nextFrame, red, nil); err != nil {
		t.Fatal(err)
	}
	mux.HandleFunc("/browser-test/display", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(frame.Len()))
		if _, err := w.Write(length[:]); err != nil {
			return
		}
		if _, err := w.Write(frame.Bytes()); err != nil {
			return
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			return
		}
		// Keep updates flowing so the browser can deliver small buffered HTTP chunks.
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ticker.C:
			}
			binary.BigEndian.PutUint32(length[:], uint32(nextFrame.Len()))
			if _, err := w.Write(length[:]); err != nil {
				return
			}
			if _, err := w.Write(nextFrame.Bytes()); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
		}
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/bin/python3", "scripts/check-dashboard-browser.py",
		"--url", server.URL, "--output", "build/dashboard-browser")
	command.Dir = root
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { return syscall.Kill(-command.Process.Pid, syscall.SIGKILL) }
	command.WaitDelay = 5 * time.Second
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		t.Fatalf("dashboard browser checks failed: %v", err)
	}
}
