// File purpose: Reads one administrator passphrase from a terminal without echo or from the first line of piped input.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"

	"golang.org/x/sys/unix"
)

// ErrPassphraseMismatch reports differing entries of a new passphrase.
var ErrPassphraseMismatch = errors.New("passphrases do not match")

// ReadPassphrase reads one line of at most limit bytes. A terminal is prompted
// on output with echo disabled; other input supplies the passphrase on its
// first line. Input is read one byte at a time so later lines, such as a
// provisioning block, stay unread. Cancellation restores the terminal.
func ReadPassphrase(ctx context.Context, input *os.File, output io.Writer, prompt string, limit int) ([]byte, error) {
	if limit < 1 {
		return nil, errors.New("invalid passphrase size limit")
	}
	restore, terminal, err := disableEcho(input)
	if err != nil {
		return nil, err
	}
	if terminal {
		defer restore()
		if _, err := io.WriteString(output, prompt); err != nil {
			return nil, err
		}
		defer func() { _, _ = io.WriteString(output, "\n") }()
	}
	passphrase, err := readLine(&blockInput{ctx: ctx, file: input}, limit)
	if contextErr := ctx.Err(); contextErr != nil {
		clear(passphrase)
		return nil, contextErr
	}
	if err != nil {
		clear(passphrase)
		return nil, err
	}
	return passphrase, nil
}

// ReadNewPassphrase reads a passphrase and, on a terminal, a matching confirmation.
func ReadNewPassphrase(ctx context.Context, input *os.File, output io.Writer, prompt string, limit int) ([]byte, error) {
	passphrase, err := ReadPassphrase(ctx, input, output, prompt, limit)
	if err != nil {
		return nil, err
	}
	if !isTerminal(input) {
		return passphrase, nil
	}
	confirmation, err := ReadPassphrase(ctx, input, output, "Repeat the passphrase: ", limit)
	if err != nil {
		clear(passphrase)
		return nil, err
	}
	defer clear(confirmation)
	if string(passphrase) != string(confirmation) {
		clear(passphrase)
		return nil, ErrPassphraseMismatch
	}
	return passphrase, nil
}

// readLine returns bytes before the first newline, or before EOF after input.
func readLine(input io.Reader, limit int) ([]byte, error) {
	line := make([]byte, 0, 64)
	var current [1]byte
	for {
		count, err := input.Read(current[:])
		if count == 1 {
			if current[0] == '\n' {
				break
			}
			if len(line) == limit {
				clear(line)
				return nil, fmt.Errorf("passphrase exceeds %d bytes", limit)
			}
			line = append(line, current[0])
			continue
		}
		if errors.Is(err, io.EOF) && len(line) > 0 {
			break
		}
		if errors.Is(err, io.EOF) {
			return nil, errors.New("no passphrase was entered")
		}
		if err != nil {
			clear(line)
			return nil, err
		}
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		return nil, errors.New("no passphrase was entered")
	}
	return line, nil
}

// descriptor returns the open file descriptor of input in system-call form.
func descriptor(input *os.File) (int, error) {
	fd := input.Fd()
	if fd == ^uintptr(0) {
		return 0, os.ErrClosed
	}
	if fd > math.MaxInt32 {
		return 0, os.ErrInvalid
	}
	return int(fd), nil
}

// isTerminal reports whether input is a terminal device.
func isTerminal(input *os.File) bool {
	fd, err := descriptor(input)
	if err != nil {
		return false
	}
	_, err = unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// disableEcho turns off terminal echo while keeping line editing and signals.
func disableEcho(input *os.File) (func(), bool, error) {
	fd, err := descriptor(input)
	if err != nil {
		return nil, false, err
	}
	original, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return func() {}, false, nil
	}
	silent := *original
	silent.Lflag &^= unix.ECHO
	silent.Lflag |= unix.ICANON | unix.ISIG
	silent.Iflag |= unix.ICRNL
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, &silent); err != nil {
		return nil, true, fmt.Errorf("disable terminal echo: %w", err)
	}
	return func() { _ = unix.IoctlSetTermios(fd, unix.TCSETS, original) }, true, nil
}
