// File purpose: Executes allowlisted CEC, audio, and serial operations through fixed local interfaces.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/RealisLux/NeoDSE/internal/cec"
	"github.com/RealisLux/NeoDSE/internal/instruction"
)

// controlAudio maps one validated action to a complete CEC key press.
func (a *Agent) controlAudio(action string) (string, error) {
	return a.controlCECAudio("HDMI-CEC audio", "", func(device *cec.Device, target uint8) error {
		return executeCECAudioAction(device, target, action)
	})
}

// executeCECAudioAction maps one validated relative audio operation to CEC.
func executeCECAudioAction(device *cec.Device, target uint8, action string) error {
	switch action {
	case "mute":
		return device.ToggleMute(target)
	case "volup":
		return device.VolumeUp(target)
	case "voldown":
		return device.VolumeDown(target)
	default:
		return fmt.Errorf("unknown audio action=%s", action)
	}
}

// controlAudioVolume sends the CEC 2.0 absolute volume command.
func (a *Agent) controlAudioVolume(level uint8) (string, error) {
	return a.controlCECAudio("HDMI-CEC audio volume", fmt.Sprintf(" level=%d", level), func(device *cec.Device, target uint8) error {
		return device.SetAudioVolumeLevel(target, level)
	})
}

// controlCECAudio sends one audio operation to the detected audio endpoint and
// falls back to the TV when a separate Audio System does not acknowledge it.
// The details name the adapter and the target that received the operation.
func (a *Agent) controlCECAudio(operation, detail string, send func(*cec.Device, uint8) error) (string, error) {
	if !a.config.CEC.Enabled {
		return "", errors.New("HDMI-CEC is disabled in agent configuration")
	}
	a.cecMu.Lock()
	defer a.cecMu.Unlock()
	device, err := a.cecDeviceLocked(true)
	if err != nil {
		return "", fmt.Errorf("%s: %w", operation, err)
	}
	target, err := a.cecAudioTargetLocked(device)
	if err != nil {
		return device.Description(), fmt.Errorf("%s target: %w", operation, err)
	}
	err = send(device, target)
	if errors.Is(err, cec.ErrNotAcknowledged) && target == cec.LogicalAddressAudioSystem {
		target = cec.LogicalAddressTV
		a.cecAudioAddress = target
		a.cecAudioAddressKnown = true
		err = send(device, target)
	}
	details := fmt.Sprintf("%s audio_target=%d%s", device.Description(), target, detail)
	if err != nil {
		return details, fmt.Errorf("%s: %w", operation, err)
	}
	return details, nil
}

// controlDisplay maps a validated display state to fixed CEC operations.
func (a *Agent) controlDisplay(state instruction.DisplayOperation) (string, error) {
	if !a.config.CEC.Enabled {
		return "", errors.New("HDMI-CEC is disabled in agent configuration")
	}
	a.cecMu.Lock()
	defer a.cecMu.Unlock()
	requirePlayback := state != instruction.DisplayOn
	device, err := a.cecDeviceLocked(requirePlayback)
	if err != nil {
		return "", fmt.Errorf("HDMI-CEC: %w", err)
	}
	target := cec.LogicalAddressTV
	switch state {
	case instruction.DisplayOn:
		err = device.ImageViewOn(target)
	case instruction.DisplayOff:
		err = device.Standby(target)
	case instruction.DisplayActive:
		err = device.ActiveSource()
	default:
		return "", fmt.Errorf("unknown display state=%s", state)
	}
	details := device.Description()
	if err != nil {
		return details, fmt.Errorf("HDMI-CEC: %w", err)
	}
	return details, nil
}

// cecPowerStatus queries the configured display and returns a normalized state
// together with the bounded diagnostic output returned in the command receipt.
func (a *Agent) cecPowerStatus() (string, string, error) {
	if !a.config.CEC.Enabled {
		return "unknown", "", errors.New("HDMI-CEC is disabled in agent configuration")
	}
	a.cecMu.Lock()
	defer a.cecMu.Unlock()
	device, err := a.cecDeviceLocked(true)
	if err != nil {
		return "unknown", "", fmt.Errorf("HDMI-CEC status: %w", err)
	}
	status, err := device.PowerStatus(cec.LogicalAddressTV)
	details := device.Description()
	if err != nil {
		return "unknown", details, fmt.Errorf("HDMI-CEC status: %w", err)
	}
	return status.String(), details, nil
}

// initializeCEC opportunistically prepares the configured kernel adapter.
func (a *Agent) initializeCEC() {
	if !a.config.CEC.Enabled {
		return
	}
	a.cecMu.Lock()
	defer a.cecMu.Unlock()
	device, err := a.cecDeviceLocked(true)
	if err != nil {
		a.verbosef("! HDMI-CEC initialization deferred: %v", err)
		return
	}
	a.verbosef("| HDMI-CEC initialized: %s", device.Description())
}

// closeCEC releases the adapter after all workers stop.
func (a *Agent) closeCEC() {
	a.cecMu.Lock()
	defer a.cecMu.Unlock()
	if a.cecDevice != nil {
		_ = a.cecDevice.Close()
		a.cecDevice = nil
	}
}

// cecDeviceLocked opens and configures the adapter while the caller owns cecMu.
func (a *Agent) cecDeviceLocked(requirePlayback bool) (*cec.Device, error) {
	if a.cecDevice == nil {
		device, err := cec.Open(a.config.CEC.Device)
		if err != nil {
			return nil, err
		}
		a.cecDevice = device
		a.cecAudioAddressKnown = false
	}
	if err := a.cecDevice.ConfigurePlayback("NeoDSE"); err != nil {
		if requirePlayback || !errors.Is(err, cec.ErrNoPhysicalAddress) {
			return nil, err
		}
	}
	return a.cecDevice, nil
}

// cecAudioTargetLocked prefers the standard Audio System address and falls back
// to the TV when no separate audio system acknowledges the polling message.
func (a *Agent) cecAudioTargetLocked(device *cec.Device) (uint8, error) {
	if a.cecAudioAddressKnown {
		return a.cecAudioAddress, nil
	}
	present, err := device.Poll(cec.LogicalAddressAudioSystem)
	if err != nil {
		return 0, err
	}
	a.cecAudioAddress = cec.LogicalAddressTV
	if present {
		a.cecAudioAddress = cec.LogicalAddressAudioSystem
	}
	a.cecAudioAddressKnown = true
	return a.cecAudioAddress, nil
}

// playSound selects an allowlisted alert file and invokes the fixed player.
func (a *Agent) playSound(profile string) error {
	var file string

	switch profile {
	case "info":
		file = a.config.Sound.Info
	case "warning":
		file = a.config.Sound.Warning
	case "critical":
		file = a.config.Sound.Critical
	default:
		return fmt.Errorf("invalid sound profile=%s", profile)
	}

	if file == "" {
		return fmt.Errorf("no sound file configured for profile=%s", profile)
	}

	a.debugf("| Playing file=%s", file)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- EXC-AGENT-AUDIO-COMMAND: the executable is fixed and file follows an argument terminator.
	if err := exec.CommandContext(ctx, "/usr/bin/aplay", "--", file).Run(); err != nil {
		return fmt.Errorf("sound: %w", err)
	}

	return nil
}

// writeSerial encodes one validated peripheral action, exchanges it with the device,
// and returns any query data. One locked transaction keeps responses paired with writes.
func (a *Agent) writeSerial(action instruction.SerialCommand) (string, error) {
	if !a.config.Serial.Enabled {
		return "", errors.New("serial is disabled")
	}
	command, err := encodeATCommand(action)
	if err != nil {
		return "", err
	}

	a.serialMu.Lock()
	defer a.serialMu.Unlock()
	ctx := a.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := time.Duration(a.config.Serial.ResponseTimeoutMS) * time.Millisecond
	port, err := openSerialPort(ctx, a.config.Serial.Port, a.config.Serial.Baudrate, timeout)
	if err != nil {
		return "", fmt.Errorf("serial open: %w", err)
	}
	defer port.Close()

	a.debugf("| Serial port=%s command=%s", a.config.Serial.Port, action.Command)

	message := []byte(command)
	for written := 0; written < len(message); {
		n, writeErr := port.Write(message[written:])
		if writeErr != nil {
			return "", fmt.Errorf("serial write: %w", writeErr)
		}
		if n < 1 {
			return "", errors.New("serial write made no progress")
		}
		written += n
	}
	response, err := readATResponse(port, timeout)
	if err != nil {
		return "", err
	}
	if response.Error != "" {
		return "", fmt.Errorf("serial device error: %s", response.Error)
	}
	return strings.Join(response.Data, "\n"), nil
}

// atResponse is the deterministic response grammar: optional data lines and a final OK,
// or a final ERROR[:reason].
type atResponse struct {
	Data  []string
	Error string
}

// encodeATCommand is deliberately small and maps only public, validated intent to AT text.
func encodeATCommand(action instruction.SerialCommand) (string, error) {
	if err := action.Validate(); err != nil {
		return "", fmt.Errorf("serial action: %w", err)
	}
	var command string
	switch action.Command {
	case instruction.SerialBeacon:
		mode := strings.ToUpper(string(action.State))
		if action.State == instruction.PeripheralBlink {
			command = fmt.Sprintf("AT+BEACON=%s,%d", mode, action.PeriodMS)
		} else {
			command = "AT+BEACON=" + mode
		}
	case instruction.SerialBuzzer:
		command = "AT+BUZZER=" + strings.ToUpper(string(action.State))
	case instruction.SerialRelay:
		command = fmt.Sprintf("AT+RELAY=%d,%s", action.RelayID, strings.ToUpper(string(action.State)))
	case instruction.SerialInfo:
		command = "AT+INFO?"
	case instruction.SerialStatus:
		command = "AT+STATUS?"
	default:
		return "", errors.New("unsupported serial action")
	}
	return command + "\r\n", nil
}

// readATResponse collects partial serial reads until a final response line or deadline.
func readATResponse(port io.Reader, timeout time.Duration) (atResponse, error) {
	deadline := time.Now().Add(timeout)
	var pending string
	response := atResponse{}
	buffer := make([]byte, 128)
	received := 0
	for time.Now().Before(deadline) {
		n, err := port.Read(buffer)
		if err != nil {
			return atResponse{}, fmt.Errorf("serial read: %w", err)
		}
		if n == 0 {
			continue
		}
		received += n
		if received > 4096 {
			return atResponse{}, errors.New("serial response exceeds 4096 bytes")
		}
		pending += string(buffer[:n])
		for {
			lineEnd := strings.IndexByte(pending, '\n')
			if lineEnd < 0 {
				break
			}
			line := strings.TrimSuffix(pending[:lineEnd], "\r")
			pending = pending[lineEnd+1:]
			final, done, parseErr := parseATResponseLine(line)
			if parseErr != nil {
				return atResponse{}, parseErr
			}
			if done {
				final.Data = response.Data
				return final, nil
			}
			response.Data = append(response.Data, line)
		}
	}
	return atResponse{}, errors.New("serial response timeout")
}

// parseATResponseLine recognizes final response lines; any other non-empty line is query data.
func parseATResponseLine(line string) (atResponse, bool, error) {
	if line == "OK" {
		return atResponse{}, true, nil
	}
	if line == "ERROR" {
		return atResponse{Error: "ERROR"}, true, nil
	}
	if reason, ok := strings.CutPrefix(line, "ERROR:"); ok {
		if reason == "" || strings.ContainsAny(reason, "\r\n") {
			return atResponse{}, false, errors.New("invalid serial error response")
		}
		return atResponse{Error: reason}, true, nil
	}
	if line == "" || strings.ContainsRune(line, '\r') {
		return atResponse{}, false, errors.New("invalid serial response line")
	}
	return atResponse{}, false, nil
}
