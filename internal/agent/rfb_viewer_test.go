// File purpose: Verifies the integrated RFB viewer authenticates and emits images without input.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"image"
	"image/jpeg"
	"io"
	"net"
	"testing"
	"time"
)

// TestEncodeBoundedJPEGReducesQuality verifies large frames stay within the relay bound.
func TestEncodeBoundedJPEGReducesQuality(t *testing.T) {
	frame := image.NewRGBA(image.Rect(0, 0, 256, 256))
	for index := range frame.Pix {
		frame.Pix[index] = byte((index*73 + index/11) & 0xff)
	}
	var high, reduced bytes.Buffer
	if err := jpeg.Encode(&high, frame, &jpeg.Options{Quality: jpegQualities[0]}); err != nil {
		t.Fatal(err)
	}
	if err := jpeg.Encode(&reduced, frame, &jpeg.Options{Quality: jpegQualities[1]}); err != nil {
		t.Fatal(err)
	}
	if reduced.Len() >= high.Len() {
		t.Fatalf("test image no longer exercises JPEG quality reduction: quality 90 = %d bytes, quality 82 = %d bytes", high.Len(), reduced.Len())
	}
	encoded, err := encodeBoundedJPEG(frame, reduced.Len())
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > reduced.Len() || len(encoded) >= high.Len() {
		t.Fatalf("adaptive JPEG size = %d, quality-90 size = %d, limit = %d", len(encoded), high.Len(), reduced.Len())
	}
	if _, err := encodeBoundedJPEG(frame, 1); err == nil {
		t.Fatal("impossible JPEG limit was accepted")
	}
}

// TestRFBViewerProducesJPEGWithoutInputMessages exercises the complete read-only RFB exchange.
func TestRFBViewerProducesJPEGWithoutInputMessages(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))
	serverError := make(chan error, 1)
	certificate, configuration, _ := rfbTLSFixture(t, nil)
	go func() { serverError <- serveTestRFB(server, certificate) }()

	viewer := newRFBViewer(client, "one-use-token", configuration)
	if err := viewer.initialize(); err != nil {
		t.Fatal(err)
	}
	frame, err := viewer.nextJPEG()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := jpeg.Decode(bytes.NewReader(frame))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Bounds().Dx() != 2 || decoded.Bounds().Dy() != 1 {
		t.Fatalf("JPEG bounds = %v", decoded.Bounds())
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

// serveTestRFB implements the certificate-authenticated server half of the fixture.
func serveTestRFB(connection net.Conn, certificate tls.Certificate) error {
	secure, err := serveTestVeNCrypt(connection, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12, SessionTicketsDisabled: true})
	if err != nil {
		return err
	}
	connection = secure
	var lengths [2]uint32
	if err := binary.Read(connection, binary.BigEndian, &lengths); err != nil {
		return err
	}
	if lengths != [2]uint32{9, 13} {
		return io.ErrUnexpectedEOF
	}
	if err := expectBytes(connection, []byte("neodse-uione-use-token")); err != nil {
		return err
	}
	if _, err := connection.Write([]byte{0, 0, 0, 0}); err != nil {
		return err
	}
	if err := expectBytes(connection, []byte{1}); err != nil {
		return err
	}
	serverInit := make([]byte, 24)
	binary.BigEndian.PutUint16(serverInit[0:], 2)
	binary.BigEndian.PutUint16(serverInit[2:], 1)
	if _, err := connection.Write(serverInit); err != nil {
		return err
	}
	negotiation := make([]byte, 28)
	if _, err := io.ReadFull(connection, negotiation); err != nil {
		return err
	}
	if negotiation[0] != 0 || negotiation[20] != 2 {
		return io.ErrUnexpectedEOF
	}
	request := make([]byte, 10)
	if _, err := io.ReadFull(connection, request); err != nil {
		return err
	}
	if request[0] != 3 || request[1] != 0 {
		return io.ErrUnexpectedEOF
	}
	update := []byte{
		0, 0, 0, 1,
		0, 0, 0, 0, 0, 2, 0, 1, 0, 0, 0, 0,
		0, 0, 255, 0, 0, 255, 0, 0,
	}
	if _, err := connection.Write(update); err != nil {
		return err
	}
	if _, err := io.ReadFull(connection, request); err != nil {
		return err
	}
	if request[0] != 3 || request[1] != 1 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// expectBytes verifies an exact protocol message without accepting short reads.
func expectBytes(reader io.Reader, expected []byte) error {
	actual := make([]byte, len(expected))
	if _, err := io.ReadFull(reader, actual); err != nil {
		return err
	}
	if !bytes.Equal(actual, expected) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

// TestRFBDeadlines bounds stalled handshakes and partial frames without timing out idle desktops.
func TestRFBDeadlines(t *testing.T) {
	for _, scenario := range []string{"handshake", "initial frame", "partial frame", "idle desktop"} {
		t.Run(scenario, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			viewer := newRFBViewer(client, "token", nil)
			viewer.ioTimeout = 30 * time.Millisecond
			viewer.receivedFrame = scenario == "idle desktop"
			viewer.width, viewer.height = 1, 1
			viewer.frame = image.NewRGBA(image.Rect(0, 0, 1, 1))
			done := make(chan error, 1)
			go func() {
				if scenario == "handshake" {
					done <- viewer.initialize()
				} else {
					_, err := viewer.nextJPEG()
					done <- err
				}
			}()
			if scenario == "partial frame" {
				if _, err := server.Write([]byte{0}); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "idle desktop" {
				select {
				case err := <-done:
					t.Fatalf("idle desktop interrupted: %v", err)
				case <-time.After(3 * viewer.ioTimeout):
				}
				_ = server.Close()
			}
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("stalled peer succeeded")
				}
				if scenario != "idle desktop" {
					if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
						t.Fatalf("expected deadline: %v", err)
					}
				}
			case <-time.After(time.Second):
				t.Fatal("RFB operation did not terminate")
			}
		})
	}
}
