// File purpose: Verifies passphrase input from pipes and terminals, including echo suppression and cancellation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package provisioning

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pipeInput returns a closed-writer pipe that supplies text.
func pipeInput(t *testing.T, text string) *os.File {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	if _, err := io.WriteString(writer, text); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return reader
}

// TestReadPassphraseFromPipe reads exactly one line and leaves later input unread.
func TestReadPassphraseFromPipe(t *testing.T) {
	for _, test := range []struct {
		input, want, rest string
		valid             bool
	}{
		{"secret\nNEXT=1\n", "secret", "NEXT=1\n", true},
		{"secret\r\nrest", "secret", "rest", true},
		{"secret", "secret", "", true},
		{" spaced secret \n", " spaced secret ", "", true},
		{"", "", "", false},
		{"\nsecret\n", "", "secret\n", false},
		{"1234567890123456\n", "1234567890123456", "", true},
		{"12345678901234567\n", "", "", false},
	} {
		var output bytes.Buffer
		input := pipeInput(t, test.input)
		got, err := ReadPassphrase(context.Background(), input, &output, "prompt: ", 16)
		if (err == nil) != test.valid || string(got) != test.want {
			t.Fatalf("input %q: got %q error %v", test.input, got, err)
		}
		if output.Len() != 0 {
			t.Fatalf("input %q: piped input printed %q", test.input, output.String())
		}
		if test.valid || test.input == "\nsecret\n" {
			rest, _ := io.ReadAll(input)
			if string(rest) != test.rest {
				t.Fatalf("input %q: remaining %q, want %q", test.input, rest, test.rest)
			}
		}
	}
}

// TestReadNewPassphraseFromPipeReadsOneLine needs no confirmation without a terminal.
func TestReadNewPassphraseFromPipeReadsOneLine(t *testing.T) {
	input := pipeInput(t, "first\nsecond\n")
	got, err := ReadNewPassphrase(context.Background(), input, io.Discard, "prompt: ", 64)
	if err != nil || string(got) != "first" {
		t.Fatalf("got %q error %v", got, err)
	}
}

// TestReadPassphraseHonorsCancellation stops waiting on idle input.
func TestReadPassphraseHonorsCancellation(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := ReadPassphrase(ctx, reader, io.Discard, "prompt: ", 64)
		result <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("passphrase read ignored cancellation")
	}
}

// openPseudoTerminal returns the controller and terminal ends of a new pty.
func openPseudoTerminal(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("pseudo-terminals unavailable: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	fd := int(controller.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("unlock pseudo-terminal: %v", err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Skipf("pseudo-terminal number: %v", err)
	}
	terminal, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", number), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("open pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = terminal.Close() })
	return controller, terminal
}

// TestReadPassphraseFromTerminalDisablesEcho prompts, hides typed input and restores the terminal.
func TestReadPassphraseFromTerminalDisablesEcho(t *testing.T) {
	controller, terminal := openPseudoTerminal(t)
	before, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if before.Lflag&unix.ECHO == 0 {
		t.Skip("pseudo-terminal does not start with echo")
	}
	echoed := make(chan string, 1)
	go func() {
		var seen bytes.Buffer
		buffer := make([]byte, 256)
		_ = controller.SetReadDeadline(time.Now().Add(3 * time.Second))
		typed := false
		for {
			count, err := controller.Read(buffer)
			seen.Write(buffer[:count])
			if err != nil || strings.Contains(seen.String(), "Again: ") {
				break
			}
			// Type exactly once: a second copy would arrive after echo is restored.
			if !typed && strings.Contains(seen.String(), "Passphrase: ") {
				_, _ = controller.WriteString("typed secret\n")
				typed = true
			}
		}
		echoed <- seen.String()
	}()
	got, err := ReadPassphrase(context.Background(), terminal, terminal, "Passphrase: ", 64)
	if err != nil || string(got) != "typed secret" {
		t.Fatalf("got %q error %v", got, err)
	}
	_, _ = terminal.WriteString("Again: ")
	transcript := <-echoed
	if !strings.Contains(transcript, "Passphrase: ") {
		t.Fatalf("prompt missing from terminal output %q", transcript)
	}
	if strings.Contains(transcript, "typed secret") {
		t.Fatalf("terminal echoed the passphrase: %q", transcript)
	}
	after, err := unix.IoctlGetTermios(int(terminal.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	if after.Lflag != before.Lflag || after.Iflag != before.Iflag {
		t.Fatalf("terminal flags not restored: before %#x/%#x after %#x/%#x", before.Lflag, before.Iflag, after.Lflag, after.Iflag)
	}
}

// TestReadNewPassphraseOnTerminalRequiresConfirmation rejects differing entries.
func TestReadNewPassphraseOnTerminalRequiresConfirmation(t *testing.T) {
	for name, test := range map[string]struct {
		confirmation string
		wantErr      error
	}{
		"match":    {"first entry", nil},
		"mismatch": {"other entry", ErrPassphraseMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			controller, terminal := openPseudoTerminal(t)
			go func() {
				var seen bytes.Buffer
				buffer := make([]byte, 256)
				_ = controller.SetReadDeadline(time.Now().Add(3 * time.Second))
				answered := 0
				for answered < 2 {
					count, err := controller.Read(buffer)
					seen.Write(buffer[:count])
					if err != nil {
						return
					}
					if answered == 0 && strings.Contains(seen.String(), "New: ") {
						_, _ = controller.WriteString("first entry\n")
						answered++
					}
					if answered == 1 && strings.Contains(seen.String(), "Repeat the passphrase: ") {
						_, _ = controller.WriteString(test.confirmation + "\n")
						answered++
					}
				}
			}()
			got, err := ReadNewPassphrase(context.Background(), terminal, terminal, "New: ", 64)
			if !errors.Is(err, test.wantErr) || (err == nil && string(got) != "first entry") {
				t.Fatalf("got %q error %v", got, err)
			}
		})
	}
}
