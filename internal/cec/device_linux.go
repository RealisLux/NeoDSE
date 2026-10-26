// File purpose: Provides a minimal pure-Go binding to the Linux HDMI-CEC userspace ABI.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package cec controls a display and its audio system through the Linux
// HDMI-CEC character device.
package cec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strconv"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LogicalAddressTV and LogicalAddressAudioSystem are the fixed CEC logical
// addresses of the display and of a separate audio system.
const (
	LogicalAddressTV          uint8  = 0
	LogicalAddressAudioSystem uint8  = 5
	logicalAddressBroadcast   uint8  = 15
	logicalAddressInvalid     uint8  = 0xff
	physicalAddressInvalid    uint16 = 0xffff

	cecCapLogAddresses uint32 = 1 << 1
	cecCapTransmit     uint32 = 1 << 2

	cecVersion14             uint8  = 0x05
	primaryDevicePlayback    uint8  = 4
	logicalAddressPlayback   uint8  = 3
	logAddressAllowRC        uint32 = 1 << 1
	vendorIDNone             uint32 = 0xffffffff
	opcodeImageViewOn        uint8  = 0x04
	opcodeStandby            uint8  = 0x36
	opcodeUserControlPressed uint8  = 0x44
	opcodeUserControlRelease uint8  = 0x45
	opcodeSetAudioVolume     uint8  = 0x73
	opcodeActiveSource       uint8  = 0x82
	opcodeGivePowerStatus    uint8  = 0x8f
	opcodeReportPowerStatus  uint8  = 0x90
	uiVolumeUp               uint8  = 0x41
	uiVolumeDown             uint8  = 0x42
	uiMute                   uint8  = 0x43

	txStatusOK       uint8 = 1 << 0
	txStatusArbLost  uint8 = 1 << 1
	txStatusNACK     uint8 = 1 << 2
	txStatusLowDrive uint8 = 1 << 3
	txStatusError    uint8 = 1 << 4
	txStatusTimeout  uint8 = 1 << 7
	rxStatusOK       uint8 = 1 << 0
	rxStatusTimeout  uint8 = 1 << 1
	rxStatusAbort    uint8 = 1 << 2
)

// Errors reported for CEC operations that the adapter or the target refused.
var (
	ErrNoPhysicalAddress = errors.New("CEC physical address is unavailable")
	ErrNotAcknowledged   = errors.New("CEC message was not acknowledged")
	ErrReplyTimeout      = errors.New("CEC reply timed out")
	ErrFeatureAbort      = errors.New("CEC target rejected the command")
	ErrAdapterBusy       = errors.New("CEC adapter is busy")
)

// PowerStatus is the normalized CEC display power state, in the order of the
// CEC Report Power Status operand.
type PowerStatus uint8

const (
	PowerOn PowerStatus = iota
	PowerStandby
	PowerToOn
	PowerToStandby
)

// String returns the public NeoDSE state name.
func (status PowerStatus) String() string {
	switch status {
	case PowerOn:
		return "on"
	case PowerStandby:
		return "standby"
	case PowerToOn, PowerToStandby:
		return "transitioning"
	default:
		return "unknown"
	}
}

// cecCaps mirrors struct cec_caps from the Linux CEC userspace ABI.
type cecCaps struct {
	Driver                [32]byte
	Name                  [32]byte
	AvailableLogAddresses uint32
	Capabilities          uint32
	Version               uint32
}

// cecLogAddresses mirrors struct cec_log_addrs from the Linux CEC userspace ABI.
type cecLogAddresses struct {
	LogAddress        [4]uint8
	LogAddressMask    uint16
	CECVersion        uint8
	NumLogAddresses   uint8
	VendorID          uint32
	Flags             uint32
	OSDName           [15]byte
	PrimaryDeviceType [4]uint8
	LogAddressType    [4]uint8
	AllDeviceTypes    [4]uint8
	Features          [4][12]uint8
}

// cecMessage mirrors struct cec_msg from the Linux CEC userspace ABI.
type cecMessage struct {
	TxTimestamp   uint64
	RxTimestamp   uint64
	Length        uint32
	Timeout       uint32
	Sequence      uint32
	Flags         uint32
	Data          [16]uint8
	Reply         uint8
	RxStatus      uint8
	TxStatus      uint8
	TxArbLostCnt  uint8
	TxNACKCnt     uint8
	TxLowDriveCnt uint8
	TxErrorCnt    uint8
}

const (
	ioctlRead        = 2
	ioctlWrite       = 1
	ioctlTypeBits    = 8
	ioctlNumberBits  = 8
	ioctlSizeBits    = 14
	ioctlNumberShift = 0
	ioctlTypeShift   = ioctlNumberShift + ioctlNumberBits
	ioctlSizeShift   = ioctlTypeShift + ioctlTypeBits
	ioctlDirShift    = ioctlSizeShift + ioctlSizeBits
)

// ioctlCode constructs one Linux generic ioctl request number.
func ioctlCode(direction, number, size uintptr) uintptr {
	return direction<<ioctlDirShift | size<<ioctlSizeShift | uintptr('a')<<ioctlTypeShift | number
}

var (
	ioctlGetCaps         = ioctlCode(ioctlRead|ioctlWrite, 0, unsafe.Sizeof(cecCaps{}))
	ioctlGetPhysical     = ioctlCode(ioctlRead, 1, unsafe.Sizeof(uint16(0)))
	ioctlGetLogAddresses = ioctlCode(ioctlRead, 3, unsafe.Sizeof(cecLogAddresses{}))
	ioctlSetLogAddresses = ioctlCode(ioctlRead|ioctlWrite, 4, unsafe.Sizeof(cecLogAddresses{}))
	ioctlTransmit        = ioctlCode(ioctlRead|ioctlWrite, 5, unsafe.Sizeof(cecMessage{}))
)

// ioctlFunc abstracts the synchronous syscall boundary for deterministic tests.
type ioctlFunc func(fd int, request uintptr, value unsafe.Pointer) error

// ioctlPointer is the single audited unsafe boundary for the Linux CEC UAPI.
func ioctlPointer[T any](value *T) unsafe.Pointer {
	return unsafe.Pointer(value) // #nosec G103 -- EXC-CEC-LINUX-ABI: pointer to caller-owned fixed-layout ioctl storage.
}

// systemIoctl invokes the fixed Linux ioctl syscall boundary.
func systemIoctl(fd int, request uintptr, value unsafe.Pointer) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), request, uintptr(value))
	if errno != 0 {
		return errno
	}
	return nil
}

// Device owns one Linux CEC adapter. Calls are serialized because message
// initiator state and bus transactions belong to the adapter as a whole.
type Device struct {
	mu        sync.Mutex
	file      *os.File
	path      string
	ioctl     ioctlFunc
	caps      cecCaps
	initiator uint8
}

// Open validates and opens one explicit Linux CEC device.
func Open(path string) (*Device, error) {
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("open CEC device %s: %w", path, err)
	}
	device := &Device{file: os.NewFile(uintptr(fd), path), path: path, ioctl: systemIoctl, initiator: logicalAddressInvalid}
	if err := device.ioctl(fd, ioctlGetCaps, ioctlPointer(&device.caps)); err != nil {
		_ = device.file.Close()
		return nil, fmt.Errorf("query CEC capabilities: %w", err)
	}
	if device.caps.Capabilities&cecCapTransmit == 0 {
		_ = device.file.Close()
		return nil, errors.New("CEC adapter does not support transmission")
	}
	return device, nil
}

// Close releases the device descriptor without clearing kernel CEC state.
func (device *Device) Close() error {
	device.mu.Lock()
	defer device.mu.Unlock()
	if device.file == nil {
		return nil
	}
	err := device.file.Close()
	device.file = nil
	return err
}

// fd returns the live adapter descriptor while the caller holds device.mu.
func (device *Device) fd() (int, error) {
	if device.file == nil {
		return -1, os.ErrClosed
	}
	return int(device.file.Fd()), nil
}

// ConfigurePlayback claims one kernel-selected Playback logical address.
func (device *Device) ConfigurePlayback(osdName string) error {
	device.mu.Lock()
	defer device.mu.Unlock()
	fd, err := device.fd()
	if err != nil {
		return err
	}
	physical, err := device.physicalAddress(fd)
	if err != nil {
		return err
	}
	// HDMI standby can invalidate the kernel's logical address after this
	// process has cached it. Wake-up must then use the unregistered initiator.
	device.initiator = logicalAddressInvalid
	var current cecLogAddresses
	if err := device.ioctl(fd, ioctlGetLogAddresses, ioctlPointer(&current)); err != nil {
		return fmt.Errorf("query CEC logical addresses: %w", mapErrno(err))
	}
	for _, address := range current.LogAddress {
		if isPlaybackAddress(address) {
			if physical == physicalAddressInvalid {
				return ErrNoPhysicalAddress
			}
			device.initiator = address
			return nil
		}
	}
	if current.NumLogAddresses != 0 {
		if physical == physicalAddressInvalid {
			return ErrNoPhysicalAddress
		}
		return errors.New("CEC adapter is already configured with a non-playback logical address")
	}
	if device.caps.Capabilities&cecCapLogAddresses == 0 {
		return errors.New("CEC adapter cannot allocate a playback logical address")
	}
	request := cecLogAddresses{CECVersion: cecVersion14, NumLogAddresses: 1, VendorID: vendorIDNone, Flags: logAddressAllowRC}
	for index := range request.LogAddress {
		request.LogAddress[index] = logicalAddressInvalid
	}
	copy(request.OSDName[:], osdName)
	request.PrimaryDeviceType[0] = primaryDevicePlayback
	request.LogAddressType[0] = logicalAddressPlayback
	if err := device.ioctl(fd, ioctlSetLogAddresses, ioctlPointer(&request)); err != nil {
		return fmt.Errorf("configure CEC playback address: %w", mapErrno(err))
	}
	// Register the desired type even while the TV is in standby. Linux rejects
	// unregistered wake-up messages until logical-address types are configured.
	if physical == physicalAddressInvalid {
		return ErrNoPhysicalAddress
	}
	if !isPlaybackAddress(request.LogAddress[0]) {
		return errors.New("kernel did not allocate a CEC playback logical address")
	}
	device.initiator = request.LogAddress[0]
	return nil
}

// physicalAddress reads the EDID-derived address using an already validated descriptor.
func (device *Device) physicalAddress(fd int) (uint16, error) {
	var address uint16
	if err := device.ioctl(fd, ioctlGetPhysical, ioctlPointer(&address)); err != nil {
		return 0, fmt.Errorf("query CEC physical address: %w", mapErrno(err))
	}
	return address, nil
}

// Description returns bounded adapter diagnostics suitable for command receipts.
func (device *Device) Description() string {
	device.mu.Lock()
	defer device.mu.Unlock()
	return fmt.Sprintf("device=%s driver=%s adapter=%s initiator=%s", device.path, cString(device.caps.Driver[:]), cString(device.caps.Name[:]), logicalAddressString(device.initiator))
}

// Poll reports whether a logical address acknowledged a header-only message.
func (device *Device) Poll(target uint8) (bool, error) {
	device.mu.Lock()
	defer device.mu.Unlock()
	message, err := device.transmit([]uint8{}, target, 0)
	if errors.Is(err, ErrNotAcknowledged) {
		return false, nil
	}
	return message != nil && err == nil, err
}

// ImageViewOn asks a display to wake. An unregistered initiator is permitted
// by the Linux ABI when the physical address is unavailable during standby.
func (device *Device) ImageViewOn(target uint8) error {
	device.mu.Lock()
	defer device.mu.Unlock()
	_, err := device.transmit([]uint8{opcodeImageViewOn}, target, 0)
	return err
}

// Standby asks a display to enter standby.
func (device *Device) Standby(target uint8) error {
	device.mu.Lock()
	defer device.mu.Unlock()
	_, err := device.transmit([]uint8{opcodeStandby}, target, 0)
	return err
}

// ActiveSource broadcasts this adapter's current EDID-derived physical address.
func (device *Device) ActiveSource() error {
	device.mu.Lock()
	defer device.mu.Unlock()
	fd, err := device.fd()
	if err != nil {
		return err
	}
	physical, err := device.physicalAddress(fd)
	if err != nil {
		return err
	}
	if physical == physicalAddressInvalid {
		return ErrNoPhysicalAddress
	}
	var encodedPhysical [2]byte
	binary.BigEndian.PutUint16(encodedPhysical[:], physical)
	_, err = device.transmit([]uint8{opcodeActiveSource, encodedPhysical[0], encodedPhysical[1]}, logicalAddressBroadcast, 0)
	return err
}

// PowerStatus requests and parses Report Power Status from one target.
func (device *Device) PowerStatus(target uint8) (PowerStatus, error) {
	device.mu.Lock()
	defer device.mu.Unlock()
	message, err := device.transmit([]uint8{opcodeGivePowerStatus}, target, opcodeReportPowerStatus)
	if err != nil {
		return 0xff, err
	}
	if message.Length < 3 || message.Data[1] != opcodeReportPowerStatus || message.Data[2] > uint8(PowerToStandby) {
		return 0xff, errors.New("CEC target returned an invalid power status")
	}
	return PowerStatus(message.Data[2]), nil
}

// VolumeUp sends one complete remote-control key press.
func (device *Device) VolumeUp(target uint8) error { return device.userControl(target, uiVolumeUp) }

// VolumeDown sends one complete remote-control key press.
func (device *Device) VolumeDown(target uint8) error { return device.userControl(target, uiVolumeDown) }

// ToggleMute sends one complete mute-toggle key press.
func (device *Device) ToggleMute(target uint8) error { return device.userControl(target, uiMute) }

// SetAudioVolumeLevel sets the absolute CEC audio level from 0 through 100.
func (device *Device) SetAudioVolumeLevel(target, level uint8) error {
	if level > 100 {
		return errors.New("CEC audio volume must be between 0 and 100")
	}
	device.mu.Lock()
	defer device.mu.Unlock()
	_, err := device.transmit([]uint8{opcodeSetAudioVolume, level}, target, 0)
	return err
}

// userControl sends one complete remote-control press and release sequence.
func (device *Device) userControl(target, command uint8) error {
	device.mu.Lock()
	defer device.mu.Unlock()
	if _, err := device.transmit([]uint8{opcodeUserControlPressed, command}, target, 0); err != nil {
		return err
	}
	_, err := device.transmit([]uint8{opcodeUserControlRelease}, target, 0)
	return err
}

// transmit builds and synchronously exchanges one bounded Linux CEC message.
func (device *Device) transmit(payload []uint8, target, reply uint8) (*cecMessage, error) {
	if target > logicalAddressBroadcast || len(payload) > 15 {
		return nil, errors.New("invalid CEC message")
	}
	fd, err := device.fd()
	if err != nil {
		return nil, err
	}
	initiator := device.initiator
	if initiator == logicalAddressInvalid {
		initiator = logicalAddressBroadcast
	}
	messageLengths := [...]uint32{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	message := &cecMessage{Length: messageLengths[len(payload)], Reply: reply}
	message.Data[0] = initiator<<4 | target
	copy(message.Data[1:], payload)
	if err := device.ioctl(fd, ioctlTransmit, ioctlPointer(message)); err != nil {
		return message, fmt.Errorf("transmit CEC message: %w", mapErrno(err))
	}
	if message.TxStatus&txStatusOK == 0 {
		return message, transmissionError(message)
	}
	if reply != 0 {
		if message.RxStatus&rxStatusAbort != 0 {
			return message, ErrFeatureAbort
		}
		if message.RxStatus&rxStatusTimeout != 0 || message.RxStatus&rxStatusOK == 0 {
			return message, ErrReplyTimeout
		}
	}
	return message, nil
}

// transmissionError maps kernel transmission status bits to stable Go errors.
func transmissionError(message *cecMessage) error {
	switch {
	case message.TxStatus&txStatusNACK != 0:
		return ErrNotAcknowledged
	case message.TxStatus&txStatusTimeout != 0:
		return ErrReplyTimeout
	case message.TxStatus&txStatusArbLost != 0:
		return errors.New("CEC arbitration was lost")
	case message.TxStatus&txStatusLowDrive != 0:
		return errors.New("CEC adapter detected low drive")
	case message.TxStatus&txStatusError != 0:
		return errors.New("CEC adapter reported a transmission error")
	default:
		return errors.New("CEC transmission failed")
	}
}

// mapErrno normalizes Linux adapter errors exposed to the agent.
func mapErrno(err error) error {
	switch {
	case errors.Is(err, unix.ENONET):
		return ErrNoPhysicalAddress
	case errors.Is(err, unix.EBUSY):
		return ErrAdapterBusy
	default:
		return err
	}
}

// isPlaybackAddress reports whether an address is one of the three CEC playback slots.
func isPlaybackAddress(address uint8) bool { return address == 4 || address == 8 || address == 11 }

// logicalAddressString formats an allocated initiator for bounded diagnostics.
func logicalAddressString(address uint8) string {
	if address == logicalAddressInvalid {
		return "unregistered"
	}
	return strconv.Itoa(int(address))
}

// cString converts one fixed-width NUL-terminated UAPI string to Go.
func cString(value []byte) string {
	for index, current := range value {
		if current == 0 {
			return string(value[:index])
		}
	}
	return string(value)
}
