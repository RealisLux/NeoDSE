// File purpose: Verifies the Linux CEC ABI layout and bounded protocol messages.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package cec

import (
	"errors"
	"os"
	"testing"
	"unsafe"
)

// testDevice constructs an isolated adapter with a deterministic ioctl boundary.
func testDevice(t *testing.T, ioctl ioctlFunc) *Device {
	t.Helper()
	file, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return &Device{file: file, path: "/dev/cec-test", ioctl: ioctl, initiator: 4, caps: cecCaps{Capabilities: cecCapLogAddresses | cecCapTransmit}}
}

// TestLinuxABILayout verifies structure sizes and ioctl numbers against the Linux UAPI.
func TestLinuxABILayout(t *testing.T) {
	if got := unsafe.Sizeof(cecCaps{}); got != 76 {
		t.Fatalf("cec_caps size=%d, want 76", got)
	}
	if got := unsafe.Sizeof(cecLogAddresses{}); got != 92 {
		t.Fatalf("cec_log_addrs size=%d, want 92", got)
	}
	if got := unsafe.Sizeof(cecMessage{}); got != 56 {
		t.Fatalf("cec_msg size=%d, want 56", got)
	}
	wants := map[string]struct{ got, want uintptr }{
		"CEC_ADAP_G_CAPS":      {ioctlGetCaps, 0xc04c6100},
		"CEC_ADAP_G_PHYS_ADDR": {ioctlGetPhysical, 0x80026101},
		"CEC_ADAP_G_LOG_ADDRS": {ioctlGetLogAddresses, 0x805c6103},
		"CEC_ADAP_S_LOG_ADDRS": {ioctlSetLogAddresses, 0xc05c6104},
		"CEC_TRANSMIT":         {ioctlTransmit, 0xc0386105},
	}
	for name, value := range wants {
		if value.got != value.want {
			t.Errorf("%s=%#x, want %#x", name, value.got, value.want)
		}
	}
}

// TestConfigurePlaybackUsesKernelAllocation verifies playback address allocation fields.
func TestConfigurePlaybackUsesKernelAllocation(t *testing.T) {
	device := testDevice(t, func(_ int, request uintptr, value unsafe.Pointer) error {
		switch request {
		case ioctlGetPhysical:
			*(*uint16)(value) = 0x2000
		case ioctlGetLogAddresses:
			addresses := (*cecLogAddresses)(value)
			for index := range addresses.LogAddress {
				addresses.LogAddress[index] = logicalAddressInvalid
			}
		case ioctlSetLogAddresses:
			addresses := (*cecLogAddresses)(value)
			if addresses.CECVersion != cecVersion14 || addresses.PrimaryDeviceType[0] != primaryDevicePlayback || addresses.LogAddressType[0] != logicalAddressPlayback {
				t.Errorf("invalid playback request: %#v", addresses)
			}
			addresses.LogAddress[0] = 8
		default:
			t.Fatalf("unexpected ioctl %#x", request)
		}
		return nil
	})
	if err := device.ConfigurePlayback("NeoDSE"); err != nil {
		t.Fatal(err)
	}
	if device.initiator != 8 {
		t.Fatalf("initiator=%d, want 8", device.initiator)
	}
}

// TestWakeDuringStandby verifies cold boot and loss of an allocated address
// both configure the adapter and wake the TV from the unregistered initiator.
func TestWakeDuringStandby(t *testing.T) {
	for _, previouslyConfigured := range []bool{false, true} {
		name := "boot-in-standby"
		if previouslyConfigured {
			name = "standby-after-allocation"
		}
		t.Run(name, func(t *testing.T) {
			physical := physicalAddressInvalid
			configured := previouslyConfigured
			configurations := 0
			device := testDevice(t, func(_ int, request uintptr, value unsafe.Pointer) error {
				switch request {
				case ioctlGetPhysical:
					*(*uint16)(value) = physical
				case ioctlGetLogAddresses:
					addresses := (*cecLogAddresses)(value)
					for index := range addresses.LogAddress {
						addresses.LogAddress[index] = logicalAddressInvalid
					}
					if configured {
						addresses.NumLogAddresses = 1
						addresses.LogAddressType[0] = logicalAddressPlayback
						if physical != physicalAddressInvalid {
							addresses.LogAddress[0] = 8
						}
					}
				case ioctlSetLogAddresses:
					if configured {
						t.Fatal("existing logical-address configuration was replaced")
					}
					addresses := (*cecLogAddresses)(value)
					if addresses.NumLogAddresses != 1 || addresses.LogAddressType[0] != logicalAddressPlayback {
						t.Fatalf("invalid playback request: %#v", addresses)
					}
					configured = true
					configurations++
				case ioctlTransmit:
					message := (*cecMessage)(value)
					wantHeader := uint8(0xf0)
					if physical != physicalAddressInvalid {
						wantHeader = 0x80
					}
					if !configured || message.Length != 2 || message.Data[0] != wantHeader || message.Data[1] != opcodeImageViewOn {
						t.Fatalf("invalid wake-up request: configured=%v message=%#v", configured, message)
					}
					message.TxStatus = txStatusOK
				default:
					t.Fatalf("unexpected ioctl %#x", request)
				}
				return nil
			})
			for range 2 {
				if err := device.ConfigurePlayback("NeoDSE"); !errors.Is(err, ErrNoPhysicalAddress) {
					t.Fatalf("ConfigurePlayback error=%v, want ErrNoPhysicalAddress", err)
				}
				if err := device.ImageViewOn(LogicalAddressTV); err != nil {
					t.Fatal(err)
				}
			}
			if configurations != 0 && previouslyConfigured || configurations != 1 && !previouslyConfigured {
				t.Fatalf("logical-address configurations=%d", configurations)
			}
			physical = 0x2000
			if err := device.ConfigurePlayback("NeoDSE"); err != nil {
				t.Fatal(err)
			}
			if err := device.ImageViewOn(LogicalAddressTV); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestPowerStatusBuildsRequestAndParsesReply verifies the request-response CEC exchange.
func TestPowerStatusBuildsRequestAndParsesReply(t *testing.T) {
	device := testDevice(t, func(_ int, request uintptr, value unsafe.Pointer) error {
		if request != ioctlTransmit {
			t.Fatalf("unexpected ioctl %#x", request)
		}
		message := (*cecMessage)(value)
		if message.Length != 2 || message.Data[0] != 0x40 || message.Data[1] != opcodeGivePowerStatus || message.Reply != opcodeReportPowerStatus {
			t.Fatalf("invalid power request: %#v", message)
		}
		message.TxStatus = txStatusOK
		message.RxStatus = rxStatusOK
		message.Length = 3
		message.Data[0] = 0x04
		message.Data[1] = opcodeReportPowerStatus
		message.Data[2] = uint8(PowerStandby)
		return nil
	})
	status, err := device.PowerStatus(LogicalAddressTV)
	if err != nil || status != PowerStandby {
		t.Fatalf("PowerStatus()=%v, %v; want standby", status, err)
	}
}

// TestAudioKeyAlwaysReleases verifies relative audio operations cannot leave a held key.
func TestAudioKeyAlwaysReleases(t *testing.T) {
	var messages [][]uint8
	device := testDevice(t, func(_ int, request uintptr, value unsafe.Pointer) error {
		if request != ioctlTransmit {
			t.Fatalf("unexpected ioctl %#x", request)
		}
		message := (*cecMessage)(value)
		messages = append(messages, append([]uint8(nil), message.Data[:message.Length]...))
		message.TxStatus = txStatusOK
		return nil
	})
	if err := device.VolumeUp(LogicalAddressAudioSystem); err != nil {
		t.Fatal(err)
	}
	want := [][]uint8{{0x45, opcodeUserControlPressed, uiVolumeUp}, {0x45, opcodeUserControlRelease}}
	if len(messages) != len(want) {
		t.Fatalf("messages=%x, want %x", messages, want)
	}
	for index := range want {
		if string(messages[index]) != string(want[index]) {
			t.Errorf("message[%d]=%x, want %x", index, messages[index], want[index])
		}
	}
}

// TestSetAudioVolumeLevel verifies the exact CEC 2.0 absolute-volume frame and bounds.
func TestSetAudioVolumeLevel(t *testing.T) {
	device := testDevice(t, func(_ int, request uintptr, value unsafe.Pointer) error {
		if request != ioctlTransmit {
			t.Fatalf("unexpected ioctl %#x", request)
		}
		message := (*cecMessage)(value)
		got := append([]uint8(nil), message.Data[:message.Length]...)
		want := []uint8{0x45, opcodeSetAudioVolume, 42}
		if string(got) != string(want) {
			t.Fatalf("message=%x, want %x", got, want)
		}
		message.TxStatus = txStatusOK
		return nil
	})
	if err := device.SetAudioVolumeLevel(LogicalAddressAudioSystem, 42); err != nil {
		t.Fatal(err)
	}
	if err := device.SetAudioVolumeLevel(LogicalAddressTV, 101); err == nil {
		t.Fatal("invalid audio volume was accepted")
	}
}

// TestPollTreatsNACKAsAbsent verifies an unacknowledged address is not an adapter error.
func TestPollTreatsNACKAsAbsent(t *testing.T) {
	device := testDevice(t, func(_ int, _ uintptr, value unsafe.Pointer) error {
		message := (*cecMessage)(value)
		message.TxStatus = txStatusNACK
		return nil
	})
	present, err := device.Poll(LogicalAddressAudioSystem)
	if err != nil || present {
		t.Fatalf("Poll()=%v, %v; want absent without error", present, err)
	}
}
