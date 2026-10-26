// File purpose: Implements the minimal read-only RFB subset needed for JPEG capture.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/jpeg"
	"io"
	"net"
	"time"

	"github.com/RealisLux/NeoDSE/internal/wire"
)

const (
	maxRFBNameBytes = 4096
	rfbIOTimeout    = 10 * time.Second
)

var jpegQualities = [...]int{90, 82, 74, 66, 58, 50}

type rfbViewer struct {
	tlsConfig     *tls.Config
	connection    net.Conn
	ioTimeout     time.Duration
	password      string
	width         uint16
	height        uint16
	frame         *image.RGBA
	receivedFrame bool
}

// newRFBViewer creates a minimal client that can never emit remote input events.
func newRFBViewer(connection net.Conn, password string, configuration *tls.Config) *rfbViewer {
	return &rfbViewer{connection: connection, password: password, tlsConfig: configuration, ioTimeout: rfbIOTimeout}
}

// initialize negotiates RFB 3.8, authenticates, and requests the first full frame.
func (viewer *rfbViewer) initialize() error {
	if err := viewer.connection.SetDeadline(time.Now().Add(viewer.ioTimeout)); err != nil {
		return err
	}
	defer viewer.connection.SetDeadline(time.Time{})
	version := make([]byte, 12)
	if _, err := io.ReadFull(viewer.connection, version); err != nil {
		return err
	}
	if string(version) != "RFB 003.008\n" {
		return errors.New("invalid RFB version")
	}
	if err := writeRFBMessage(viewer.connection, []byte("RFB 003.008\n")); err != nil {
		return err
	}
	var count uint8
	if err := binary.Read(viewer.connection, binary.BigEndian, &count); err != nil || count == 0 {
		return errors.New("RFB server offered no security type")
	}
	types := make([]byte, count)
	if _, err := io.ReadFull(viewer.connection, types); err != nil {
		return err
	}
	if !bytes.Contains(types, []byte{19}) {
		return errors.New("RFB certificate-authenticated TLS unavailable")
	}
	if err := viewer.authenticateVeNCrypt(); err != nil {
		return err
	}
	viewer.password = ""
	var securityResult uint32
	if err := binary.Read(viewer.connection, binary.BigEndian, &securityResult); err != nil {
		return err
	}
	if securityResult != 0 {
		return errors.New("RFB authentication rejected")
	}
	if err := writeRFBMessage(viewer.connection, []byte{1}); err != nil {
		return err
	}
	return viewer.readServerInit()
}

// authenticateVeNCrypt accepts only VeNCrypt 0.2 X509Plain (262). Credentials
// and all subsequent RFB traffic are sent only after certificate verification.
func (viewer *rfbViewer) authenticateVeNCrypt() error {
	defer func() { viewer.password = "" }()
	if viewer.tlsConfig == nil {
		return errors.New("VNC TLS trust is unavailable")
	}
	if err := writeRFBMessage(viewer.connection, []byte{19}); err != nil {
		return err
	}
	var version [2]byte
	if _, err := io.ReadFull(viewer.connection, version[:]); err != nil {
		return err
	}
	if version != [2]byte{0, 2} {
		return errors.New("unsupported VeNCrypt version")
	}
	if err := writeRFBMessage(viewer.connection, version[:]); err != nil {
		return err
	}
	var accepted [1]byte
	if _, err := io.ReadFull(viewer.connection, accepted[:]); err != nil {
		return err
	}
	if accepted[0] != 0 {
		return errors.New("VeNCrypt version rejected")
	}
	var count uint8
	if err := binary.Read(viewer.connection, binary.BigEndian, &count); err != nil {
		return err
	}
	supported := false
	for range int(count) {
		var subtype uint32
		if err := binary.Read(viewer.connection, binary.BigEndian, &subtype); err != nil {
			return err
		}
		supported = supported || subtype == 262
	}
	if !supported {
		return errors.New("VeNCrypt X509Plain unavailable")
	}
	if err := binary.Write(viewer.connection, binary.BigEndian, uint32(262)); err != nil {
		return err
	}
	if _, err := io.ReadFull(viewer.connection, accepted[:]); err != nil {
		return err
	}
	if accepted[0] != 1 {
		return errors.New("VeNCrypt TLS upgrade rejected")
	}
	secure := tls.Client(viewer.connection, viewer.tlsConfig)
	if err := secure.Handshake(); err != nil {
		return fmt.Errorf("VNC TLS verification: %w", err)
	}
	viewer.connection = secure
	const username = "neodse-ui"
	passwordLength := len(viewer.password)
	if passwordLength == 0 || passwordLength > vncTokenMaxBytes {
		return errors.New("invalid VNC credential length")
	}
	credentials := make([]byte, 8+len(username)+passwordLength)
	defer clear(credentials)
	binary.BigEndian.PutUint32(credentials[:4], uint32(len(username)))
	binary.BigEndian.PutUint32(credentials[4:8], uint32(passwordLength))
	copy(credentials[8:], username)
	copy(credentials[8+len(username):], viewer.password)
	return writeRFBMessage(viewer.connection, credentials)
}

// readServerInit validates the framebuffer and selects the sole supported raw encoding.
func (viewer *rfbViewer) readServerInit() error {
	if err := binary.Read(viewer.connection, binary.BigEndian, &viewer.width); err != nil {
		return err
	}
	if err := binary.Read(viewer.connection, binary.BigEndian, &viewer.height); err != nil {
		return err
	}
	if viewer.width == 0 || viewer.height == 0 || uint64(viewer.width)*uint64(viewer.height) > wire.MaxDisplayPixels {
		return errors.New("invalid RFB framebuffer size")
	}
	pixelFormat := make([]byte, 16)
	if _, err := io.ReadFull(viewer.connection, pixelFormat); err != nil {
		return err
	}
	var nameLength uint32
	if err := binary.Read(viewer.connection, binary.BigEndian, &nameLength); err != nil || nameLength > maxRFBNameBytes {
		return errors.New("invalid RFB server name")
	}
	if _, err := io.CopyN(io.Discard, viewer.connection, int64(nameLength)); err != nil {
		return err
	}
	viewer.frame = image.NewRGBA(image.Rect(0, 0, int(viewer.width), int(viewer.height)))
	setPixelFormat := []byte{0, 0, 0, 0, 32, 24, 0, 1, 0, 255, 0, 255, 0, 255, 16, 8, 0, 0, 0, 0}
	setEncodings := []byte{2, 0, 0, 1, 0, 0, 0, 0}
	if err := writeRFBMessage(viewer.connection, append(setPixelFormat, setEncodings...)); err != nil {
		return err
	}
	return viewer.requestUpdate(false)
}

// nextJPEG applies one complete RFB update and encodes the accumulated framebuffer.
func (viewer *rfbViewer) nextJPEG() ([]byte, error) {
	for {
		// Only an already captured desktop may legitimately remain silent indefinitely.
		deadline := time.Time{}
		if !viewer.receivedFrame {
			deadline = time.Now().Add(viewer.ioTimeout)
		}
		if err := viewer.connection.SetReadDeadline(deadline); err != nil {
			return nil, err
		}
		var messageType uint8
		if err := binary.Read(viewer.connection, binary.BigEndian, &messageType); err != nil {
			return nil, err
		}
		if err := viewer.connection.SetDeadline(time.Now().Add(viewer.ioTimeout)); err != nil {
			return nil, err
		}
		switch messageType {
		case 0:
			if err := viewer.readFramebufferUpdate(); err != nil {
				return nil, err
			}
			encoded, err := encodeBoundedJPEG(viewer.frame, displayChunkBytes)
			if err != nil {
				return nil, err
			}
			if err := viewer.requestUpdate(true); err != nil {
				return nil, err
			}
			viewer.receivedFrame = true
			return encoded, nil
		case 2:
			continue
		case 3:
			if err := viewer.discardServerCutText(); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("unsupported RFB server message %d", messageType)
		}
	}
}

// encodeBoundedJPEG preserves the highest configured quality that fits the relay limit.
func encodeBoundedJPEG(frame image.Image, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("invalid JPEG size limit")
	}
	for _, quality := range jpegQualities {
		var encoded bytes.Buffer
		if err := jpeg.Encode(&encoded, frame, &jpeg.Options{Quality: quality}); err != nil {
			return nil, err
		}
		if encoded.Len() <= limit {
			return encoded.Bytes(), nil
		}
	}
	return nil, errors.New("encoded display frame exceeds transport limit")
}

// readFramebufferUpdate validates and applies every raw rectangle in one server update.
func (viewer *rfbViewer) readFramebufferUpdate() error {
	var padding uint8
	var rectangles uint16
	if err := binary.Read(viewer.connection, binary.BigEndian, &padding); err != nil {
		return err
	}
	if err := binary.Read(viewer.connection, binary.BigEndian, &rectangles); err != nil {
		return err
	}
	for rectangle := uint16(0); rectangle < rectangles; rectangle++ {
		var x, y, width, height uint16
		var encoding int32
		for _, value := range []any{&x, &y, &width, &height, &encoding} {
			if err := binary.Read(viewer.connection, binary.BigEndian, value); err != nil {
				return err
			}
		}
		if encoding != 0 || uint32(x)+uint32(width) > uint32(viewer.width) || uint32(y)+uint32(height) > uint32(viewer.height) {
			return errors.New("unsupported or invalid RFB rectangle")
		}
		pixels := make([]byte, int(width)*int(height)*4)
		if _, err := io.ReadFull(viewer.connection, pixels); err != nil {
			return err
		}
		for row := 0; row < int(height); row++ {
			for column := 0; column < int(width); column++ {
				source := (row*int(width) + column) * 4
				destination := viewer.frame.PixOffset(int(x)+column, int(y)+row)
				viewer.frame.Pix[destination] = pixels[source+2]
				viewer.frame.Pix[destination+1] = pixels[source+1]
				viewer.frame.Pix[destination+2] = pixels[source]
				viewer.frame.Pix[destination+3] = 255
			}
		}
	}
	return nil
}

// requestUpdate asks Weston for a full or incremental framebuffer update.
func (viewer *rfbViewer) requestUpdate(incremental bool) error {
	request := make([]byte, 10)
	request[0] = 3
	binary.BigEndian.PutUint16(request[6:8], viewer.width)
	binary.BigEndian.PutUint16(request[8:10], viewer.height)
	if incremental {
		request[1] = 1
	}
	return writeRFBMessage(viewer.connection, request)
}

// discardServerCutText consumes bounded clipboard notifications without exposing them.
func (viewer *rfbViewer) discardServerCutText() error {
	header := make([]byte, 7)
	if _, err := io.ReadFull(viewer.connection, header); err != nil {
		return err
	}
	length := binary.BigEndian.Uint32(header[3:])
	if length > 1<<20 {
		return errors.New("RFB clipboard message too large")
	}
	_, err := io.CopyN(io.Discard, viewer.connection, int64(length))
	return err
}

// writeRFBMessage handles short writes so protocol messages cannot be truncated.
func writeRFBMessage(writer io.Writer, message []byte) error {
	for len(message) > 0 {
		written, err := writer.Write(message)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		message = message[written:]
	}
	return nil
}
