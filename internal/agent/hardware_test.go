// File purpose: Verifies hardware-operation allowlists without invoking unsafe commands.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/cec"
	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// diagnosticCECAdapter isolates adapter configuration and command failures.
// Unused operations panic through the embedded interface to detect extra I/O.
type diagnosticCECAdapter struct {
	cecAdapter
	configureErr error
	commandErr   error
	statusErr    error
	power        cec.PowerStatus
	audioSystem  bool
	logger       func(string, ...any)
}

// ConfigurePlayback returns the simulated adapter configuration outcome.
func (device *diagnosticCECAdapter) ConfigurePlayback(string) error { return device.configureErr }

// Description identifies the isolated adapter in receipts and logs.
func (device *diagnosticCECAdapter) Description() string {
	return "device=/dev/cec-test driver=test adapter=test initiator=4"
}

// SetDebugLogger captures the logger installed by the agent.
func (device *diagnosticCECAdapter) SetDebugLogger(logger func(string, ...any)) {
	device.logger = logger
}

// Poll reports whether a separate audio system is present.
func (device *diagnosticCECAdapter) Poll(uint8) (bool, error) { return device.audioSystem, nil }

// ImageViewOn returns the simulated wake-up transmission outcome.
func (device *diagnosticCECAdapter) ImageViewOn(uint8) error { return device.commandErr }

// PowerStatus returns the simulated display observation.
func (device *diagnosticCECAdapter) PowerStatus(uint8) (cec.PowerStatus, error) {
	return device.power, device.statusErr
}

// captureCECLogs redirects the normal service logger for a synchronous test.
func captureCECLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &output
}

// TestCECCommandDiagnostics covers sent, rejected and unavailable-adapter paths
// at each diagnostic level without changing the reported command outcome.
func TestCECCommandDiagnostics(t *testing.T) {
	for _, level := range []string{"info", "verbose", "debug"} {
		for _, outcome := range []string{"sent", "transmission failed", "configuration failed", "disabled"} {
			t.Run(level+"/"+outcome, func(t *testing.T) {
				output := captureCECLogs(t)
				device := &diagnosticCECAdapter{}
				if outcome == "transmission failed" {
					device.commandErr = cec.ErrNotAcknowledged
				}
				if outcome == "configuration failed" {
					device.configureErr = cec.ErrAdapterBusy
				}
				agent := &Agent{cecDevice: device, verbose: level == "verbose", debug: level == "debug"}
				agent.config.CEC.Enabled = outcome != "disabled"
				agent.config.CEC.Device = "/dev/cec-test"
				_, err := agent.controlDisplay(instruction.DisplayOn)
				if (err == nil) != (outcome == "sent") {
					t.Fatalf("outcome=%s error=%v", outcome, err)
				}
				if level == "info" {
					if output.Len() != 0 {
						t.Fatalf("info emitted CEC diagnostics: %s", output.String())
					}
					return
				}
				result := "result=failed"
				if outcome == "sent" {
					result = "result=sent"
				}
				for _, want := range []string{"HDMI-CEC display action=on", result, "device=/dev/cec-test", "duration="} {
					if !strings.Contains(output.String(), want) {
						t.Fatalf("missing %q in %s", want, output.String())
					}
				}
				if err != nil && !strings.Contains(output.String(), err.Error()) {
					t.Fatalf("missing failure reason: %s", output.String())
				}
				if outcome == "sent" && !strings.Contains(output.String(), "initiator=4") {
					t.Fatalf("missing adapter diagnostics: %s", output.String())
				}
				if (device.logger != nil) != (level == "debug" && outcome != "disabled") {
					t.Fatal("CEC frame logger does not match debug mode")
				}
			})
		}
	}
}

// TestCECAudioFallbackDiagnostics verifies the NACK fallback remains observable
// and preserves the TV target for subsequent audio commands.
func TestCECAudioFallbackDiagnostics(t *testing.T) {
	output := captureCECLogs(t)
	device := &diagnosticCECAdapter{audioSystem: true}
	agent := &Agent{cecDevice: device, verbose: true}
	agent.config.CEC.Enabled = true
	agent.config.CEC.Device = "/dev/cec-test"
	var targets []uint8
	send := func(_ cecAdapter, target uint8) error {
		targets = append(targets, target)
		if target == cec.LogicalAddressAudioSystem {
			return cec.ErrNotAcknowledged
		}
		return nil
	}
	for range 2 {
		if _, err := agent.controlCECAudio("HDMI-CEC audio", " action=mute", send); err != nil {
			t.Fatal(err)
		}
	}
	if fmt.Sprint(targets) != "[5 0 0]" {
		t.Fatalf("audio targets=%v, want [5 0 0]", targets)
	}
	for _, want := range []string{"audio target=5", "audio fallback from=5 to=0", "action=mute result=sent", "audio_target=0"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}

// TestCECPowerDiagnostics logs first observations, transitions and failures in
// verbose mode while reserving unchanged probes for debug and respecting cadence.
func TestCECPowerDiagnostics(t *testing.T) {
	output := captureCECLogs(t)
	device := &diagnosticCECAdapter{power: cec.PowerStandby}
	agent := &Agent{cecDevice: device, verbose: true}
	agent.config.CEC.Enabled = true
	agent.refreshCECStatusIfDue()
	if !strings.Contains(output.String(), "previous=unknown current=standby") {
		t.Fatalf("missing first observation: %s", output.String())
	}
	output.Reset()
	device.power = cec.PowerOn
	agent.refreshCECStatusIfDue()
	if output.Len() != 0 {
		t.Fatal("probe ignored its polling interval")
	}
	agent.cecCheckedAt = time.Now().Add(-2 * cecStatusPollInterval)
	agent.refreshCECStatusIfDue()
	if !strings.Contains(output.String(), "previous=standby current=on") {
		t.Fatalf("missing power transition: %s", output.String())
	}
	output.Reset()
	agent.cecCheckedAt = time.Now().Add(-2 * cecStatusPollInterval)
	agent.refreshCECStatusIfDue()
	if output.Len() != 0 {
		t.Fatal("unchanged status flooded verbose logs")
	}
	agent.debug = true
	agent.cecCheckedAt = time.Now().Add(-2 * cecStatusPollInterval)
	agent.refreshCECStatusIfDue()
	if !strings.Contains(output.String(), "power status unchanged=on") {
		t.Fatalf("debug omitted successful probe: %s", output.String())
	}
	output.Reset()
	device.statusErr = cec.ErrReplyTimeout
	agent.cecCheckedAt = time.Now().Add(-2 * cecStatusPollInterval)
	agent.refreshCECStatusIfDue()
	if !strings.Contains(output.String(), "status probe failed") || !strings.Contains(output.String(), cec.ErrReplyTimeout.Error()) {
		t.Fatalf("missing probe failure: %s", output.String())
	}
}

// TestHardwareHelpersRejectUnknownCommandsBeforeExecution verifies hardware helpers reject unknown commands before execution.
func TestHardwareHelpersRejectUnknownCommandsBeforeExecution(t *testing.T) {
	if err := runSystemCommand("status"); err == nil {
		t.Fatal("arbitrary system command was accepted")
	}
}

// TestEncodeATCommandMapsStructuredActions verifies every typed serial action mapping.
func TestEncodeATCommandMapsStructuredActions(t *testing.T) {
	tests := []struct {
		action instruction.SerialCommand
		want   string
	}{
		{instruction.SerialCommand{Command: instruction.SerialBeacon, State: instruction.PeripheralOn}, "AT+BEACON=ON\r\n"},
		{instruction.SerialCommand{Command: instruction.SerialBeacon, State: instruction.PeripheralBlink, PeriodMS: 500}, "AT+BEACON=BLINK,500\r\n"},
		{instruction.SerialCommand{Command: instruction.SerialBuzzer, State: instruction.PeripheralOff}, "AT+BUZZER=OFF\r\n"},
		{instruction.SerialCommand{Command: instruction.SerialRelay, State: instruction.PeripheralOn, RelayID: 2}, "AT+RELAY=2,ON\r\n"},
		{instruction.SerialCommand{Command: instruction.SerialInfo}, "AT+INFO?\r\n"},
		{instruction.SerialCommand{Command: instruction.SerialStatus}, "AT+STATUS?\r\n"},
	}
	for _, test := range tests {
		got, err := encodeATCommand(test.action)
		if err != nil || got != test.want {
			t.Fatalf("encodeATCommand(%+v) = %q, %v; want %q", test.action, got, err, test.want)
		}
	}
}

// TestATResponseParserHandlesPartialReadsAndTerminalErrors verifies bounded response framing.
func TestATResponseParserHandlesPartialReadsAndTerminalErrors(t *testing.T) {
	response, err := readATResponse(&chunkReader{data: []byte("+STATUS:BEACON=BLINK,500\r\nOK\r\n"), size: 3}, time.Second)
	if err != nil || len(response.Data) != 1 || response.Data[0] != "+STATUS:BEACON=BLINK,500" || response.Error != "" {
		t.Fatalf("response=%+v error=%v", response, err)
	}
	response, err = readATResponse(strings.NewReader("ERROR:INVALID_ARGUMENT\r\n"), time.Second)
	if err != nil || response.Error != "INVALID_ARGUMENT" {
		t.Fatalf("error response=%+v error=%v", response, err)
	}
	if _, err := readATResponse(strings.NewReader("\r\n"), time.Second); err == nil {
		t.Fatal("empty response line was accepted")
	}
}

// chunkReader exposes predetermined fragments as a streaming reader.
type chunkReader struct {
	data []byte
	size int
}

// Read returns one configured fragment to exercise partial serial reads.
func (reader *chunkReader) Read(destination []byte) (int, error) {
	if len(reader.data) == 0 {
		return 0, io.EOF
	}
	count := min(reader.size, len(reader.data))
	copy(destination, reader.data[:count])
	reader.data = reader.data[count:]
	return count, nil
}

// TestDisplayCommandReportsHardwareFailure verifies CEC failures belong to the transient command.
func TestDisplayCommandReportsHardwareFailure(t *testing.T) {
	agent := &Agent{displayController: func(instruction.DisplayOperation) error { return errors.New("CEC unavailable") }}
	if _, err := agent.executeCommand(instruction.NewCommand(instruction.DisplayCommand{Operation: instruction.DisplayOn})); err == nil {
		t.Fatal("display command unexpectedly succeeded")
	}
}
