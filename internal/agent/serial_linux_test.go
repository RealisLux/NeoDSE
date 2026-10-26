// File purpose: Verifies serial exchange deadlines, cancellation, framing, and descriptor ownership with real Linux ttys.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/instruction"
	"golang.org/x/sys/unix"
)

// serialTestTTY creates an isolated master/slave tty pair without external commands.
func serialTestTTY(t *testing.T) (*os.File, string) {
	t.Helper()
	fd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	master := os.NewFile(uintptr(fd), "serial-test-master")
	t.Cleanup(func() { _ = master.Close() })
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	number, err := unix.IoctlGetInt(fd, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/dev/pts/%d", number)
	// Keep the slave alive before the agent opens it: a master read with no
	// slave descriptors returns EIO instead of waiting for the command.
	keeper, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(keeper) })
	return master, path
}

// fillSerialTestOutput holds a tty output queue full while its master is not read.
func fillSerialTestOutput(t *testing.T, fd int) {
	t.Helper()
	// The tty driver moves queued bytes asynchronously into the master buffer.
	// Refill after it settles so even a small command must wait for capacity.
	for range 20 {
		for _, buffer := range [][]byte{make([]byte, 4096), {0}} {
			for {
				_, err := unix.Write(fd, buffer)
				if errors.Is(err, unix.EAGAIN) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestSerialExchangeUsesRaw8N1AndFragmentedResponses exercises the production command path.
func TestSerialExchangeUsesRaw8N1AndFragmentedResponses(t *testing.T) {
	master, path := serialTestTTY(t)
	if err := master.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	responseDone := make(chan error, 1)
	go func() {
		command := make([]byte, len("AT+INFO?\r\n"))
		if _, err := io.ReadFull(master, command); err != nil {
			responseDone <- err
			return
		}
		if string(command) != "AT+INFO?\r\n" {
			responseDone <- fmt.Errorf("unexpected command %q", command)
			return
		}
		for _, fragment := range []string{"+INFO:Neo", "DSE\r\n", "OK\r\n"} {
			if _, err := master.Write([]byte(fragment)); err != nil {
				responseDone <- err
				return
			}
		}
		responseDone <- nil
	}()
	agent := &Agent{ctx: context.Background(), config: Config{Serial: config.SerialSettings{
		Enabled: true, Port: path, Baudrate: 115200, ResponseTimeoutMS: 1000,
	}}}
	response, err := agent.writeSerial(instruction.SerialCommand{Command: instruction.SerialInfo})
	if err != nil || response != "+INFO:NeoDSE" {
		t.Fatalf("response=%q error=%v", response, err)
	}
	if err := <-responseDone; err != nil {
		t.Fatal(err)
	}
	raw, err := master.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var settings *unix.Termios
	if err := raw.Control(func(fd uintptr) { settings, err = unix.IoctlGetTermios(int(fd), unix.TCGETS2) }); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if settings.Ispeed != 115200 || settings.Ospeed != 115200 || settings.Cflag&unix.CSIZE != unix.CS8 ||
		settings.Cflag&(unix.PARENB|unix.CSTOPB|unix.CRTSCTS|unix.HUPCL) != 0 || settings.Iflag != 0 || settings.Oflag != 0 || settings.Lflag != 0 {
		t.Fatalf("tty is not configured for raw 8N1 at the requested rate without hangup on close: %+v", settings)
	}
}

// TestSerialWriteDeadlineAndCancellation bounds a genuinely stalled tty write without leaking descriptors.
func TestSerialWriteDeadlineAndCancellation(t *testing.T) {
	for _, scenario := range []string{"deadline", "cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			_, path := serialTestTTY(t)
			filler, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(filler)
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			port, err := openSerialPort(ctx, path, 9600, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer port.Close()
			fillSerialTestOutput(t, filler)
			if scenario == "deadline" {
				if err := port.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
			}
			done := make(chan error, 1)
			go func() { _, err := port.Write([]byte("AT+STATUS?\r\n")); done <- err }()
			if scenario == "cancellation" {
				select {
				case err := <-done:
					t.Fatalf("tty output was not stalled: %v", err)
				case <-time.After(50 * time.Millisecond):
				}
				cancel()
			}
			select {
			case err := <-done:
				if scenario == "deadline" && !errors.Is(err, os.ErrDeadlineExceeded) {
					t.Fatalf("write deadline error=%v", err)
				}
				if scenario == "cancellation" && !errors.Is(err, os.ErrClosed) {
					t.Fatalf("cancelled write error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled serial write retained its worker")
			}
			_ = port.Close()
			// The pre-existing filler remains open, so this also proves that
			// close released TIOCEXCL rather than relying on the final tty close.
			reopened, err := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("serial close retained exclusive access: %v", err)
			}
			_ = unix.Close(reopened)
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(after) != len(before) {
				t.Fatalf("serial exchange leaked descriptors: before=%d after=%d error=%v", len(before), len(after), err)
			}
		})
	}
}

// TestSerialExchangeReadDeadlineAndCancellation bounds a peripheral that never acknowledges.
func TestSerialExchangeReadDeadlineAndCancellation(t *testing.T) {
	for _, scenario := range []string{"deadline", "cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			master, path := serialTestTTY(t)
			if err := master.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			agent := &Agent{ctx: ctx, config: Config{Serial: config.SerialSettings{
				Enabled: true, Port: path, Baudrate: 9600, ResponseTimeoutMS: 200,
			}}}
			if scenario == "cancellation" {
				agent.config.Serial.ResponseTimeoutMS = 5000
			}
			done := make(chan error, 1)
			go func() {
				_, err := agent.writeSerial(instruction.SerialCommand{Command: instruction.SerialStatus})
				done <- err
			}()
			command := make([]byte, len("AT+STATUS?\r\n"))
			if _, err := io.ReadFull(master, command); err != nil {
				t.Fatal(err)
			}
			if scenario == "cancellation" {
				cancel()
			}
			select {
			case err := <-done:
				want := os.ErrDeadlineExceeded
				if scenario == "cancellation" {
					want = os.ErrClosed
				}
				if !errors.Is(err, want) {
					t.Fatalf("unacknowledged command error=%v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("unacknowledged command retained its worker")
			}
		})
	}
}

// TestSerialPortRejectsInvalidConfigurationAndNonTTY fails closed before any I/O.
func TestSerialPortRejectsInvalidConfigurationAndNonTTY(t *testing.T) {
	_, ttyPath := serialTestTTY(t)
	path := filepath.Join(t.TempDir(), "regular-file")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rate := range []int{-1, 0, 115201} {
		if port, err := openSerialPort(context.Background(), ttyPath, rate, time.Second); err == nil || port != nil {
			if port != nil {
				_ = port.Close()
			}
			t.Fatalf("invalid baud rate %d accepted", rate)
		}
	}
	if port, err := openSerialPort(context.Background(), ttyPath, 9600, 0); err == nil || port != nil {
		if port != nil {
			_ = port.Close()
		}
		t.Fatal("zero exchange timeout accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := openSerialPort(ctx, path, 9600, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled serial open=%v", err)
	}
	before, _ := os.ReadDir("/proc/self/fd")
	for range 20 {
		if port, err := openSerialPort(context.Background(), path, 9600, time.Second); !errors.Is(err, unix.ENOTTY) || port != nil {
			t.Fatalf("non-tty serial open: port=%v error=%v", port, err)
		}
	}
	after, _ := os.ReadDir("/proc/self/fd")
	if len(after) != len(before) {
		t.Fatalf("failed serial opens leaked descriptors: before=%d after=%d", len(before), len(after))
	}
}
