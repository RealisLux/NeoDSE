// File purpose: Provides deadline-bound Linux serial I/O through the Go runtime poller.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"golang.org/x/sys/unix"
)

// serialPort owns a nonblocking tty and its shutdown cancellation callback.
type serialPort struct {
	*os.File
	stop func() bool
}

// openSerialPort configures raw 8N1 I/O with one deadline for the whole exchange.
func openSerialPort(ctx context.Context, path string, baudrate int, timeout time.Duration) (*serialPort, error) {
	if baudrate <= 0 || baudrate > config.MaxSerialBaudRate || timeout <= 0 {
		return nil, errors.New("invalid serial baud rate or exchange timeout")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// #nosec G304 -- EXC-AGENT-SERIAL-DEVICE: trusted local configuration selects a tty; termios validation precedes payload I/O.
	file, err := os.OpenFile(path, os.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	if err := configureSerialPort(file, uint32(baudrate)); err != nil {
		_ = closeSerialPort(file)
		return nil, err
	}
	if err := file.SetDeadline(time.Now().Add(timeout)); err != nil {
		_ = closeSerialPort(file)
		return nil, fmt.Errorf("serial device does not support I/O deadlines: %w", err)
	}
	return &serialPort{File: file, stop: context.AfterFunc(ctx, func() { _ = closeSerialPort(file) })}, nil
}

// configureSerialPort keeps the descriptor nonblocking while changing Linux termios2.
func configureSerialPort(file *os.File, baudrate uint32) error {
	raw, err := file.SyscallConn()
	if err != nil {
		return err
	}
	var configurationErr error
	err = raw.Control(func(fd uintptr) {
		settings, err := unix.IoctlGetTermios(int(fd), unix.TCGETS2)
		if err != nil {
			configurationErr = err
			return
		}
		if err := unix.IoctlSetInt(int(fd), unix.TIOCEXCL, 0); err != nil {
			configurationErr = err
			return
		}
		settings.Iflag, settings.Oflag, settings.Lflag = 0, 0, 0
		// Clearing HUPCL keeps DTR asserted when the port closes, so boards that
		// reset on a DTR edge are not restarted by every serial command.
		settings.Cflag &^= unix.CSIZE | unix.PARENB | unix.PARODD | unix.CMSPAR | unix.CSTOPB | unix.CRTSCTS | unix.CBAUD | unix.CIBAUD | unix.HUPCL
		settings.Cflag |= unix.CS8 | unix.CLOCAL | unix.CREAD | unix.BOTHER
		settings.Cc[unix.VMIN], settings.Cc[unix.VTIME] = 1, 0
		settings.Ispeed, settings.Ospeed = baudrate, baudrate
		configurationErr = unix.IoctlSetTermios(int(fd), unix.TCSETS2, settings)
	})
	return errors.Join(err, configurationErr)
}

// closeSerialPort releases exclusive access without waiting for queued bytes to drain.
func closeSerialPort(file *os.File) error {
	if raw, err := file.SyscallConn(); err == nil {
		_ = raw.Control(func(fd uintptr) { _ = unix.IoctlSetInt(int(fd), unix.TIOCNXCL, 0) })
	}
	return file.Close()
}

// Close unregisters cancellation and releases the tty descriptor.
func (port *serialPort) Close() error {
	port.stop()
	return closeSerialPort(port.File)
}
