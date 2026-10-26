// File purpose: Defines, validates, and serializes typed transient controller commands.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package instruction

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// CommandType identifies one transient, expiring operation.
type CommandType string

const (
	CommandDisplay       CommandType = "display"
	CommandDisplayVolume CommandType = "display_volume"
	CommandSound         CommandType = "sound"
	CommandSerial        CommandType = "serial"
	CommandBanner        CommandType = "banner"
	CommandReload        CommandType = "reload"
	CommandRestart       CommandType = "restart"
	CommandReboot        CommandType = "reboot"
	CommandShutdown      CommandType = "shutdown"
)

// DisplayCommand selects one bounded HDMI-CEC display operation.
type DisplayCommand struct {
	Operation DisplayOperation `json:"operation"`
}

// Validate verifies one HDMI-CEC display command.
func (command DisplayCommand) Validate() error {
	if !command.Operation.Valid() {
		return errors.New("invalid display operation")
	}
	return nil
}

// BannerSeverity controls the visual urgency of one transient banner.
type BannerSeverity string

const (
	BannerInfo     BannerSeverity = "info"
	BannerWarning  BannerSeverity = "warning"
	BannerCritical BannerSeverity = "critical"
)

// Valid reports whether severity is supported by the UI.
func (severity BannerSeverity) Valid() bool {
	return severity == BannerInfo || severity == BannerWarning || severity == BannerCritical
}

// DisplayVolumeCommand sets an absolute HDMI-CEC audio level.
type DisplayVolumeCommand struct {
	Level uint8 `json:"level"`
}

// Validate verifies the CEC percentage range.
func (command DisplayVolumeCommand) Validate() error {
	if command.Level > 100 {
		return errors.New("audio volume must be between 0 and 100")
	}
	return nil
}

// SoundProfile is one bundled notification-sound profile.
type SoundProfile string

const (
	SoundInfo     SoundProfile = "info"
	SoundWarning  SoundProfile = "warning"
	SoundCritical SoundProfile = "critical"
)

// Valid reports whether profile is available as a bundled sound.
func (profile SoundProfile) Valid() bool {
	return profile == SoundInfo || profile == SoundWarning || profile == SoundCritical
}

// SoundCommand selects one bundled notification sound profile.
type SoundCommand struct {
	Profile SoundProfile `json:"profile"`
}

// Validate verifies one notification-sound command.
func (command SoundCommand) Validate() error {
	if !command.Profile.Valid() {
		return errors.New("invalid sound profile")
	}
	return nil
}

// SerialOperation identifies one supported peripheral action or query.
type SerialOperation string

const (
	SerialBeacon SerialOperation = "beacon"
	SerialBuzzer SerialOperation = "buzzer"
	SerialRelay  SerialOperation = "relay"
	SerialInfo   SerialOperation = "info"
	SerialStatus SerialOperation = "status"
)

// PeripheralState is a state accepted by one or more peripheral actions.
type PeripheralState string

const (
	PeripheralOn    PeripheralState = "on"
	PeripheralOff   PeripheralState = "off"
	PeripheralBlink PeripheralState = "blink"
)

const (
	minBlinkPeriodMS = 100
	maxBlinkPeriodMS = 60000
	minRelayID       = 1
	maxRelayID       = 32
)

// SerialCommand expresses peripheral intent. The agent maps it to its local AT protocol;
// this public command never carries arbitrary serial or AT text.
type SerialCommand struct {
	Command  SerialOperation `json:"command"`
	State    PeripheralState `json:"state,omitempty"`
	PeriodMS int             `json:"period_ms,omitempty"`
	RelayID  int             `json:"relay_id,omitempty"`
}

// Validate verifies all action-specific fields before the command is transported or written.
func (command SerialCommand) Validate() error {
	switch command.Command {
	case SerialBeacon:
		if command.State != PeripheralOn && command.State != PeripheralOff && command.State != PeripheralBlink {
			return errors.New("invalid beacon state")
		}
		if command.State == PeripheralBlink {
			if command.PeriodMS < minBlinkPeriodMS || command.PeriodMS > maxBlinkPeriodMS {
				return fmt.Errorf("blink period must be %d-%d milliseconds", minBlinkPeriodMS, maxBlinkPeriodMS)
			}
		} else if command.PeriodMS != 0 {
			return errors.New("blink period is only valid for blink state")
		}
		if command.RelayID != 0 {
			return errors.New("beacon does not accept a relay ID")
		}
	case SerialBuzzer:
		if command.State != PeripheralOn && command.State != PeripheralOff {
			return errors.New("invalid buzzer state")
		}
		if command.PeriodMS != 0 || command.RelayID != 0 {
			return errors.New("buzzer does not accept period or relay ID")
		}
	case SerialRelay:
		if command.State != PeripheralOn && command.State != PeripheralOff {
			return errors.New("invalid relay state")
		}
		if command.RelayID < minRelayID || command.RelayID > maxRelayID {
			return fmt.Errorf("relay ID must be %d-%d", minRelayID, maxRelayID)
		}
		if command.PeriodMS != 0 {
			return errors.New("relay does not accept a period")
		}
	case SerialInfo, SerialStatus:
		if command.State != "" || command.PeriodMS != 0 || command.RelayID != 0 {
			return errors.New("serial query does not accept action fields")
		}
	default:
		return errors.New("invalid serial command")
	}
	return nil
}

// BannerMessage is bounded text rendered in the transient banner overlay.
type BannerMessage string

// BannerDuration is the number of seconds the overlay remains visible.
type BannerDuration int

// BannerCommand carries one validated transient display notification.
type BannerCommand struct {
	Message         BannerMessage  `json:"message"`
	Severity        BannerSeverity `json:"severity"`
	DurationSeconds BannerDuration `json:"duration_seconds"`
}

// Validate verifies one transient display notification.
func (command BannerCommand) Validate() error {
	message := string(command.Message)
	if strings.TrimSpace(message) == "" || !utf8.ValidString(message) || utf8.RuneCountInString(message) > 256 || strings.ContainsRune(message, '\x00') {
		return errors.New("banner message must contain 1-256 Unicode characters")
	}
	if !command.Severity.Valid() {
		return errors.New("invalid banner severity")
	}
	if command.DurationSeconds < 1 || command.DurationSeconds > 300 {
		return errors.New("banner duration must be 1-300 seconds")
	}
	return nil
}

// ReloadCommand reloads active playlist documents in their existing WebKit views.
type ReloadCommand struct{}

// Validate accepts every playlist reload command; it has no fields.
func (ReloadCommand) Validate() error { return nil }

// RestartCommand requests a GTK UI service restart.
type RestartCommand struct{}

// Validate accepts every restart command; it has no fields.
func (RestartCommand) Validate() error { return nil }

// RebootCommand requests a host reboot.
type RebootCommand struct{}

// Validate accepts every reboot command; it has no fields.
func (RebootCommand) Validate() error { return nil }

// ShutdownCommand requests a host shutdown.
type ShutdownCommand struct{}

// Validate accepts every shutdown command; it has no fields.
func (ShutdownCommand) Validate() error { return nil }

// commandPayload is the closed set of payloads accepted by NewCommand.
type commandPayload interface {
	DisplayCommand | DisplayVolumeCommand | SoundCommand | SerialCommand | BannerCommand |
		ReloadCommand | RestartCommand | RebootCommand | ShutdownCommand
	validator
}

// validator is implemented by every command payload.
type validator interface {
	Validate() error
}

// Command wraps exactly one typed payload and owns its canonical wire encoding.
type Command struct {
	payload validator
}

// NewCommand constructs a transient command from one concrete payload.
func NewCommand[T commandPayload](payload T) Command {
	return Command{payload: payload}
}

// Payload returns the concrete operation for a type switch at an execution boundary.
func (command Command) Payload() any {
	return command.payload
}

// Type returns the stable command discriminator or the empty value for an incomplete command.
func (command Command) Type() CommandType {
	switch command.payload.(type) {
	case DisplayCommand:
		return CommandDisplay
	case DisplayVolumeCommand:
		return CommandDisplayVolume
	case SoundCommand:
		return CommandSound
	case SerialCommand:
		return CommandSerial
	case BannerCommand:
		return CommandBanner
	case ReloadCommand:
		return CommandReload
	case RestartCommand:
		return CommandRestart
	case RebootCommand:
		return CommandReboot
	case ShutdownCommand:
		return CommandShutdown
	default:
		return ""
	}
}

// Validate rejects an incomplete wrapper and delegates to its concrete payload.
func (command Command) Validate() error {
	if command.payload == nil {
		return errors.New("command payload is missing")
	}
	return command.payload.Validate()
}

// commandEnvelope is the canonical discriminated JSON representation of a command.
type commandEnvelope struct {
	Type    CommandType     `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// MarshalJSON emits the canonical discriminated command envelope.
func (command Command) MarshalJSON() ([]byte, error) {
	if err := command.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(command.payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(commandEnvelope{Type: command.Type(), Payload: payload})
}

// UnmarshalJSON strictly decodes the discriminator before selecting its payload type.
func (command *Command) UnmarshalJSON(data []byte) error {
	if command == nil {
		return errors.New("command destination is nil")
	}
	var envelope commandEnvelope
	if err := decodeCommandJSON(data, &envelope); err != nil {
		return err
	}
	decoded, err := decodeCommandPayload(envelope.Type, envelope.Payload)
	if err != nil {
		return err
	}
	*command = decoded
	return nil
}

// decodeCommandPayload selects and strictly decodes the payload named by its discriminator.
func decodeCommandPayload(commandType CommandType, data []byte) (Command, error) {
	switch commandType {
	case CommandDisplay:
		return decodeTypedCommand[DisplayCommand](data)
	case CommandDisplayVolume:
		return decodeTypedCommand[DisplayVolumeCommand](data)
	case CommandSound:
		return decodeTypedCommand[SoundCommand](data)
	case CommandSerial:
		return decodeTypedCommand[SerialCommand](data)
	case CommandBanner:
		return decodeTypedCommand[BannerCommand](data)
	case CommandReload:
		return decodeTypedCommand[ReloadCommand](data)
	case CommandRestart:
		return decodeTypedCommand[RestartCommand](data)
	case CommandReboot:
		return decodeTypedCommand[RebootCommand](data)
	case CommandShutdown:
		return decodeTypedCommand[ShutdownCommand](data)
	default:
		return Command{}, fmt.Errorf("invalid command type %q", commandType)
	}
}

// decodeTypedCommand strictly decodes and validates one selected payload type.
func decodeTypedCommand[T commandPayload](data []byte) (Command, error) {
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return Command{}, errors.New("command payload is missing")
	}
	var payload T
	if err := decodeCommandJSON(data, &payload); err != nil {
		return Command{}, err
	}
	command := NewCommand(payload)
	if err := command.Validate(); err != nil {
		return Command{}, err
	}
	return command, nil
}

// decodeCommandJSON rejects unknown fields and trailing JSON values at every command boundary.
func decodeCommandJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("command input contains more than one value")
		}
		return err
	}
	return nil
}
