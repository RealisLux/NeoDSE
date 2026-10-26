// File purpose: Verifies safe WireGuard address allocation and provisioning metadata parsing.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"strings"
	"testing"
)

// TestCanceledProvisionCommandDoesNotStart rejects canceled controller
// maintenance before parsing configuration or opening its authority store.
func TestCanceledProvisionCommandDoesNotStart(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runProvisionCommand(ctx, []string{"provision-agent"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled controller provisioning error=%v", err)
	}
}

// TestMaintenanceCommandsRequireRoot names the command and the missing
// privilege before a command reads protected files or the unlock socket.
func TestMaintenanceCommandsRequireRoot(t *testing.T) {
	if err := requireRoot(0, "unlock"); err != nil {
		t.Fatalf("root was refused: %v", err)
	}
	if err := requireRoot(1000, "unlock"); err == nil || err.Error() != "neodse-server unlock must run as root; run it with sudo" {
		t.Fatalf("unprivileged caller error = %v", err)
	}
	// The dispatcher applies the check first. Root reaches the command's own
	// argument validation instead, which fails before any side effect.
	want := "unlock accepts no positional arguments"
	if os.Geteuid() != 0 {
		want = "neodse-server unlock must run as root"
	}
	if err := runProvisionCommand(context.Background(), []string{"unlock", "unexpected"}); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("dispatch error = %v, want %q", err, want)
	}
}

// TestUsageListsMaintenanceCommands keeps every documented root command
// discoverable from neodse-server --help.
func TestUsageListsMaintenanceCommands(t *testing.T) {
	var output strings.Builder
	flags := flag.NewFlagSet("neodse-server", flag.ContinueOnError)
	flags.SetOutput(&output)
	writeServerUsage(flags)
	for _, name := range []string{"bootstrap", "unlock", "change-passphrase", "provision-agent", "remove-agent", "recover-admin", "renew-certificate"} {
		if !isProvisionCommand(name) || !strings.Contains(output.String(), "\n  "+name+" ") {
			t.Errorf("command %s is not dispatched or not listed in:\n%s", name, output.String())
		}
	}
	if isProvisionCommand("--config") {
		t.Fatal("a service flag was treated as a maintenance command")
	}
}

// TestServerCommandsRejectUnexpectedArguments prevents misspelled subcommands
// and flags after a stray argument from silently starting or changing services.
func TestServerCommandsRejectUnexpectedArguments(t *testing.T) {
	for _, args := range [][]string{{"unexpected"}, {"unexpected", "--config", "/not-used.yaml"}, {"sensitive-accidental-argument"}} {
		for name, parse := range map[string]func([]string) error{
			"server": func(args []string) error {
				_, err := parseServerRunOptions(args)
				return err
			},
			"bootstrap": func(args []string) error {
				_, _, err := parseBootstrapOptions(args)
				return err
			},
			"renew-certificate": renewServerCertificate,
			"recover-admin": func(args []string) error {
				return recoverAdministrator(context.Background(), args)
			},
			"provision-agent": func(args []string) error {
				_, err := parseAgentProvisionOptions(args)
				return err
			},
			"unlock": func(args []string) error {
				return unlockController(context.Background(), args)
			},
			"change-passphrase": func(args []string) error {
				return changeDatabasePassphrase(context.Background(), args)
			},
		} {
			t.Run(name+"/"+strings.Join(args, "_"), func(t *testing.T) {
				err := parse(args)
				if err == nil || !strings.Contains(err.Error(), "positional arguments") {
					t.Fatalf("arguments %q were not rejected before accessing service state: %v", args, err)
				}
				if strings.Contains(err.Error(), "sensitive-accidental-argument") {
					t.Fatal("argument rejection exposed an accidental secret")
				}
			})
		}
	}
}

// TestBootstrapAddressRejectsUnusableSubnets keeps the generated configuration
// consistent with the private IPv4 addresses required by agent provisioning.
func TestBootstrapAddressRejectsUnusableSubnets(t *testing.T) {
	for _, test := range []struct {
		address string
		valid   bool
	}{
		{"10.99.0.1/24", true},
		{"10.0.0.1/8", true},
		{"172.16.0.1/12", true},
		{"192.168.0.1/16", true},
		{"192.168.0.2/30", true},
		{"10.99.0.1", false},
		{"203.0.113.1/24", false},
		{"127.0.0.1/24", false},
		{"0.0.0.0/0", false},
		{"224.0.0.1/24", false},
		{"2001:db8::1/64", false},
		{"::ffff:10.99.0.1/120", false},
		{"10.99.0.1/31", false},
		{"10.99.0.1/32", false},
		{"10.99.0.0/24", false},
		{"10.99.0.255/24", false},
		{"10.0.0.1/7", false},
		{"172.16.0.1/11", false},
		{"192.168.0.1/15", false},
	} {
		t.Run(test.address, func(t *testing.T) {
			address, err := parseBootstrapAddress(test.address)
			if !test.valid {
				if err == nil {
					t.Fatalf("unusable bootstrap address was accepted: %s", address)
				}
				return
			}
			want, _, _ := net.ParseCIDR(test.address)
			if err != nil || !address.Equal(want) {
				t.Fatalf("address=%s error=%v; want %s", address, err, want)
			}
		})
	}
}

// TestAddressAllocationRespectsPeerRanges prevents a new display from stealing existing routes.
func TestAddressAllocationRespectsPeerRanges(t *testing.T) {
	for _, test := range []struct {
		name, subnet, fields, want string
	}{
		{"comma separated", "10.20.0.1/24", "AllowedIPs = 10.20.0.2/32, 10.20.0.3/32 # existing peer\n", "10.20.0.4"},
		{"case insensitive", "10.20.0.1/24", "allowedips = 10.20.0.2/32\nAlLoWeDiPs = 10.20.0.3/32\n", "10.20.0.4"},
		{"WireGuard whitespace", "10.20.0.1/24", "Allowed IPs = 10.20.0.2 / 32, 10.20.0.3 /32\n", "10.20.0.4"},
		{"bare host route", "10.20.0.1/24", "AllowedIPs = 10.20.0.2, ::1\n", "10.20.0.3"},
		{"last IPv4 subnet", "255.255.255.253/30", "", "255.255.255.254"},
		{"last IPv4 subnet exhausted", "255.255.255.253/30", "AllowedIPs = 255.255.255.254/32\n", ""},
		{"overlapping subnets", "10.20.0.1/24", "AllowedIPs=10.20.0.0/30\nAllowedIPs=10.20.0.0/29\n", "10.20.0.8"},
		{"unrelated routes", "10.20.0.1/24", "AllowedIPs=192.168.0.0/16, ::/0\n", "10.20.0.2"},
		{"exhausted", "10.20.0.1/30", "AllowedIPs=10.20.0.2/32\n", ""},
		{"full IPv4 route", "10.20.0.1/24", "AllowedIPs=0.0.0.0/0\n", ""},
		{"invalid route", "10.20.0.1/24", "AllowedIPs=invalid\n", ""},
		{"no usable hosts", "10.20.0.1/32", "", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, subnet, err := net.ParseCIDR(test.subnet)
			if err != nil {
				t.Fatal(err)
			}
			got, err := nextAgentIP(subnet, server, parseWGFields(test.fields)["allowedips"])
			if test.want == "" {
				if err == nil {
					t.Fatalf("unsafe address allocated: %s", got)
				}
			} else if err != nil || got.String() != test.want {
				t.Fatalf("address=%s error=%v; want %s", got, err, test.want)
			}
		})
	}
}

// TestRenewCertificateRejectsIPv6 verifies certificate identity remains IPv4-only.
func TestRenewCertificateRejectsIPv6(t *testing.T) {
	for _, address := range []string{"2001:db8::1", "::ffff:192.0.2.1"} {
		if err := renewServerCertificate([]string{"--address", address}); err == nil {
			t.Errorf("IPv6 certificate address %q was accepted", address)
		}
	}
}

// TestRemoveWGPeerPreservesOtherAndUnmanagedConfiguration verifies remove wg peer preserves other and unmanaged configuration.
func TestRemoveWGPeerPreservesOtherAndUnmanagedConfiguration(t *testing.T) {
	configuration := `[Interface]
Address = 10.20.0.1/24
PrivateKey = server-key

# NeoDSEAgentBegin = display-a
[Peer]
PublicKey = key-a
PresharedKey = psk-a
AllowedIPs = 10.20.0.2/32
# NeoDSEAgentEnd = display-a

# operator-owned comment
[Peer]
PublicKey = manual-key
AllowedIPs = 10.30.0.0/24

# NeoDSEAgentBegin = display-b
[Peer]
PublicKey = key-b
PresharedKey = psk-b
AllowedIPs = 10.20.0.3/32
# NeoDSEAgentEnd = display-b

# trailing operator setting
PostUp = /usr/local/sbin/operator-hook
`

	result, err := removeWGPeer(configuration, "display-a")
	if err != nil {
		t.Fatal(err)
	}
	for _, preserved := range []string{
		"manual-key",
		"NeoDSEAgentBegin = display-b",
		"key-b",
		"operator-hook",
	} {
		if !strings.Contains(result, preserved) {
			t.Errorf("result did not preserve %q", preserved)
		}
	}
	for _, removed := range []string{"NeoDSEAgentBegin = display-a", "key-a", "psk-a"} {
		if strings.Contains(result, removed) {
			t.Errorf("result retained %q", removed)
		}
	}

	result, err = removeWGPeer(configuration, "display-b")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(result, "operator-hook") || strings.Contains(result, "key-b") {
		t.Fatalf("last managed block removal damaged trailing configuration:\n%s", result)
	}
}

// TestRemoveWGPeerRejectsMalformedManagedBlocks verifies remove wg peer rejects malformed managed blocks.
func TestRemoveWGPeerRejectsMalformedManagedBlocks(t *testing.T) {
	tests := map[string]string{
		"unterminated": "# NeoDSEAgentBegin = display-a\n[Peer]\n",
		"mismatched":   "# NeoDSEAgentBegin = display-a\n# NeoDSEAgentEnd = display-b\n",
		"nested":       "# NeoDSEAgentBegin = display-a\n# NeoDSEAgentBegin = display-b\n",
	}
	for name, configuration := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := removeWGPeer(configuration, "display-a"); err == nil {
				t.Fatal("malformed configuration was accepted")
			}
		})
	}
}

// TestReenrollmentReleasesAddressBeforeAllocation verifies reenrollment releases address before allocation.
func TestReenrollmentReleasesAddressBeforeAllocation(t *testing.T) {
	configuration := `[Interface]
Address = 10.20.0.1/24
PrivateKey = server-key

# NeoDSEAgentBegin = display-a
[Peer]
PublicKey = key-a
AllowedIPs = 10.20.0.2/32
# NeoDSEAgentEnd = display-a

# NeoDSEAgentBegin = display-b
[Peer]
PublicKey = key-b
AllowedIPs = 10.20.0.3/32
# NeoDSEAgentEnd = display-b
`
	withoutAgent, err := removeWGPeer(configuration, "display-a")
	if err != nil {
		t.Fatal(err)
	}
	_, network, err := net.ParseCIDR("10.20.0.1/24")
	if err != nil {
		t.Fatal(err)
	}
	address, err := nextAgentIP(network, net.ParseIP("10.20.0.1"), parseWGFields(withoutAgent)["allowedips"])
	if err != nil {
		t.Fatal(err)
	}
	if got, want := address.String(), "10.20.0.2"; got != want {
		t.Fatalf("replacement address = %s, want released address %s", got, want)
	}
}

// TestWireGuardServerIdentityRejectsRepeatedPrivateKeys keeps enrollment from
// deriving the first key while WireGuard activates the last key.
func TestWireGuardServerIdentityRejectsRepeatedPrivateKeys(t *testing.T) {
	const privateKey = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	const otherKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	for _, test := range []struct {
		name, additionalKey string
	}{
		{"single key", ""},
		{"different repeated key", otherKey},
		{"same repeated key", privateKey},
	} {
		t.Run(test.name, func(t *testing.T) {
			configuration := "[Interface]\nAddress = 10.20.0.1/24\nPrivateKey = " + privateKey + "\n"
			if test.additionalKey != "" {
				configuration += "PrIvAtE KeY = " + test.additionalKey + " # effective key\n"
			}
			key, address, err := wireGuardServerIdentity(parseWGFields(configuration))
			if test.additionalKey != "" {
				if err == nil || !strings.Contains(err.Error(), "keep exactly one PrivateKey in [Interface]") {
					t.Fatalf("repeated PrivateKey error = %v, want actionable rejection", err)
				}
				return
			}
			if err != nil || key != privateKey || address != "10.20.0.1/24" {
				t.Fatalf("single-key identity = %q, %q, %v", key, address, err)
			}
		})
	}
}

// TestEnrollmentPublicKeyPreservesOtherPeers rejects key reuse that would
// silently change an existing WireGuard peer instead of adding a new display.
func TestEnrollmentPublicKeyPreservesOtherPeers(t *testing.T) {
	configuration := `[Interface]
PrivateKey = server-private-key
# NeoDSEAgentBegin = display-a
[Peer]
PublicKey = key-a
AllowedIPs = 10.20.0.2/32
# NeoDSEAgentEnd = display-a
# NeoDSEAgentBegin = display-b
[Peer]
PublicKey = key-b
AllowedIPs = 10.20.0.3/32
# NeoDSEAgentEnd = display-b
[Peer]
PuBlIc KeY = manual-key # operator-managed peer
AllowedIPs = 10.30.0.1/32
`
	remaining, err := removeWGPeer(configuration, "display-a")
	if err != nil {
		t.Fatal(err)
	}
	fields := parseWGFields(remaining)
	derive := func(privateKey string) (string, error) {
		if privateKey != "server-private-key" {
			return "", errors.New("unexpected private key")
		}
		return "server-public-key", nil
	}
	for _, test := range []struct {
		name, key string
		valid     bool
	}{
		{"new device", "new-key", true},
		{"same device reenrollment", "key-a", true},
		{"another enrolled display", "key-b", false},
		{"unmanaged peer", "manual-key", false},
		{"controller", "server-public-key", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverKey, err := enrollmentPublicKey(first(fields["privatekey"]), test.key, fields["publickey"], derive)
			if (err == nil) != test.valid || (err == nil && serverKey != "server-public-key") || (err != nil && serverKey != "") {
				t.Fatalf("enrollment key valid=%t, want %t; controller key=%q error=%v", err == nil, test.valid, serverKey, err)
			}
		})
	}
	derivationFailure := errors.New("wg pubkey failed")
	if serverKey, err := enrollmentPublicKey("server-private-key", "new-key", nil, func(string) (string, error) {
		return "", derivationFailure
	}); serverKey != "" || !errors.Is(err, derivationFailure) {
		t.Fatalf("failed key derivation returned %q, %v", serverKey, err)
	}
}

// TestAgentServiceURLsFollowConfiguredListeners gives displays the configured
// transport and proxy ports at the controller's WireGuard address.
func TestAgentServiceURLsFollowConfiguredListeners(t *testing.T) {
	serverIP := net.ParseIP("10.99.0.254")
	transportURL, proxyURL, err := agentServiceURLs(serverIP, "ws://10.99.0.254:9081", "10.99.0.254:4128")
	if err != nil || transportURL != "ws://10.99.0.254:9081" || proxyURL != "http://10.99.0.254:4128" {
		t.Fatalf("service URLs = %q %q, %v", transportURL, proxyURL, err)
	}
	for _, test := range []struct{ transport, proxy string }{
		{"ws://127.0.0.1:8081", "10.99.0.254:3128"},
		{"ws://10.99.0.254", "10.99.0.254:3128"},
		{"ws://10.99.0.254:8081", "10.99.0.1:3128"},
		{"ws://10.99.0.254:8081", "invalid"},
	} {
		if _, _, err := agentServiceURLs(serverIP, test.transport, test.proxy); err == nil {
			t.Errorf("transport %q and proxy %q were accepted", test.transport, test.proxy)
		}
	}
}
