// File purpose: Verifies hardware-operation allowlists without invoking unsafe commands.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/RealisLux/NeoDSE/internal/instruction"
)

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
