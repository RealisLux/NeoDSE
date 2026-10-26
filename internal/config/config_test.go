// File purpose: Verifies strict parsing, secure file checks, defaults, and listener validation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// writeConfig creates a securely permissioned configuration fixture.
func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestRepositoryYAMLParses verifies repository yaml parses.
func TestRepositoryYAMLParses(t *testing.T) {
	patterns := []string{
		filepath.Join("..", "..", ".github", "workflows", "*.yml"),
		filepath.Join("..", "..", "packaging", "*.yaml"),
	}
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range paths {
			contents, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var document yaml.Node
			if err := yaml.Unmarshal(contents, &document); err != nil {
				t.Errorf("%s is invalid YAML: %v", path, err)
			}
		}
	}
}

// FuzzStrictYAMLDecode exercises strict yaml decode with generated inputs.
func FuzzStrictYAMLDecode(f *testing.F) {
	f.Add("agent:\n  id: display-01\n")
	f.Add("unknown: true\n")
	f.Add("---\nserver: {}\n---\nserver: {}\n")
	f.Fuzz(func(t *testing.T, input string) {
		var destination Agent
		_ = DecodeYAML([]byte(input), &destination)
	})
}

// TestLoadAgentRejectsUnknownField verifies load agent rejects unknown field.
func TestLoadAgentRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, `
agent:
  id: display-01
  psk: "`+strings.Repeat("ab", 32)+`"
  unexpected: true
transport:
  url: ws://127.0.0.1:8081
`)
	if _, err := LoadAgent(path); err == nil {
		t.Fatal("unknown configuration field was accepted")
	}
}

// TestLoadAgentRejectsTransportCredentials verifies load agent rejects transport credentials.
func TestLoadAgentRejectsTransportCredentials(t *testing.T) {
	path := writeConfig(t, `
agent:
  id: display-01
  wireguard_interface: neodse
  psk: "`+strings.Repeat("ab", 32)+`"
transport:
  url: ws://user:password@127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
`)
	if _, err := LoadAgent(path); err == nil || !strings.Contains(err.Error(), "transport.url") {
		t.Fatalf("embedded transport credentials error = %v, want transport.url rejection", err)
	}
}

// TestLoadAgentLogLevel verifies load agent log level.
func TestLoadAgentLogLevel(t *testing.T) {
	base := `
agent:
  id: display-01
  psk: "` + strings.Repeat("ab", 32) + `"
  wireguard_interface: neodse
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
`

	cfg, err := LoadAgent(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.LogLevel != "info" {
		t.Fatalf("default agent log level = %q, want info", cfg.Agent.LogLevel)
	}

	invalid := strings.Replace(base, "  id:", "  log_level: trace\n  id:", 1)
	if _, err := LoadAgent(writeConfig(t, invalid)); err == nil {
		t.Fatal("unsupported agent log level was accepted")
	}
}

// TestLoadAgentFriendlyName verifies the optional display label is normalized and bounded.
func TestLoadAgentFriendlyName(t *testing.T) {
	base := `
agent:
  id: display-01
  friendly_name: "  Left lobby  "
  psk: "` + strings.Repeat("ab", 32) + `"
  wireguard_interface: neodse
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
`
	cfg, err := LoadAgent(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Agent.FriendlyName != "Left lobby" {
		t.Fatalf("friendly name = %q", cfg.Agent.FriendlyName)
	}
	tooLong := strings.Replace(base, `"  Left lobby  "`, `"`+strings.Repeat("🙂", 33)+`"`, 1)
	if _, err := LoadAgent(writeConfig(t, tooLong)); err == nil {
		t.Fatal("oversized friendly name was accepted")
	}
	withNUL := strings.Replace(base, `"  Left lobby  "`, `"Lobby\0hidden"`, 1)
	if _, err := LoadAgent(writeConfig(t, withNUL)); err == nil {
		t.Fatal("friendly name incompatible with renderer strings and SQLite was accepted")
	}
}

// TestLoadAgentValidationMatrix verifies load agent validation matrix.
func TestLoadAgentValidationMatrix(t *testing.T) {
	base := `
agent:
  id: display-01
  psk: "` + strings.Repeat("ab", 32) + `"
  wireguard_interface: neodse
  ui_socket: /run/neodse/ui.sock
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
sound:
  info: /usr/share/neodse/info.wav
serial:
  enabled: false
  baudrate: 9600
`
	tests := map[string]string{
		"valid":             base,
		"identifier":        strings.Replace(base, "id: display-01", "id: invalid/value", 1),
		"PSK":               strings.Replace(base, strings.Repeat("ab", 32), "invalid", 1),
		"interface missing": strings.Replace(base, "wireguard_interface: neodse", "wireguard_interface: ''", 1),
		"interface format":  strings.Replace(base, "wireguard_interface: neodse", "wireguard_interface: invalid/interface", 1),
		"UI path":           strings.Replace(base, "/run/neodse/ui.sock", "relative.sock", 1),
		"UI oversized path": strings.Replace(base, "/run/neodse/ui.sock", "/run/neodse/"+strings.Repeat("s", 97), 1),
		"IPv6 transport":    strings.Replace(base, "ws://127.0.0.1:8081", "ws://[fd00::1]:8081", 1),
		"IPv6 proxy":        strings.Replace(base, "http://127.0.0.1:3128", "http://[fd00::1]:3128", 1),
		"sound path":        strings.Replace(base, "/usr/share/neodse/info.wav", "relative.wav", 1),
		"serial settings":   strings.Replace(base, "enabled: false", "enabled: true", 1),
	}
	for name, contents := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := LoadAgent(writeConfig(t, contents))
			if name == "valid" && err != nil {
				t.Fatal(err)
			}
			if name != "valid" && err == nil {
				t.Fatal("invalid agent configuration was accepted")
			}
		})
	}
}

// TestAgentSerialBaudRateBounds enforces the supported peripheral link speeds.
func TestAgentSerialBaudRateBounds(t *testing.T) {
	base := Agent{
		Agent:     AgentSettings{ID: "display-01", PSK: strings.Repeat("ab", 32), WireGuardInterface: "neodse"},
		Transport: AgentTransport{URL: "ws://127.0.0.1:8081"},
		Proxy:     AgentProxy{URL: "http://127.0.0.1:3128"},
		CEC:       CECSettings{Device: "/dev/cec0"},
		Serial:    SerialSettings{Enabled: true, Port: "/dev/ttyUSB0", ResponseTimeoutMS: 1000},
	}
	for _, test := range []struct {
		rate  int
		valid bool
	}{{1, true}, {9600, true}, {115200, true}, {0, false}, {-1, false}, {115201, false}} {
		base.Serial.Baudrate = test.rate
		if _, err := ValidateAgent(base); (err == nil) != test.valid {
			t.Fatalf("baud rate %d: valid=%t error=%v", test.rate, test.valid, err)
		}
	}
}

// TestLoadAgentCECDefaultsAndValidation covers default CEC behavior and rejected overrides.
func TestLoadAgentCECDefaultsAndValidation(t *testing.T) {
	base := `
agent:
  id: display-01
  psk: "` + strings.Repeat("ab", 32) + `"
  wireguard_interface: neodse
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
`
	cfg, err := LoadAgent(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.CEC.Enabled || cfg.CEC.Device != "/dev/cec0" {
		t.Fatalf("CEC defaults=%+v", cfg.CEC)
	}
	for name, section := range map[string]string{
		"device":          "cec:\n  device: /dev/video0\n",
		"logical address": "cec:\n  logical_address: 0\n",
		"audio address":   "cec:\n  audio_address: 5\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, loadErr := LoadAgent(writeConfig(t, base+section)); loadErr == nil {
				t.Fatal("invalid CEC configuration was accepted")
			}
		})
	}
}

// TestLoadServerLogLevel verifies load server log level.
func TestLoadServerLogLevel(t *testing.T) {
	base := `
server:
  listen: "127.0.0.1:8443"
  tls_cert: /tmp/server.crt
  tls_key: /tmp/server.key
  proxy_internal_psk: "` + strings.Repeat("ab", 32) + `"
  transport_psk: "` + strings.Repeat("cd", 32) + `"
  transport_url: ws://127.0.0.1:8081
`

	cfg, err := LoadServer(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.LogLevel != "info" {
		t.Fatalf("default server log level = %q, want info", cfg.Server.LogLevel)
	}

	invalid := strings.Replace(base, "  listen:", "  log_level: trace\n  listen:", 1)
	if _, err := LoadServer(writeConfig(t, invalid)); err == nil {
		t.Fatal("unsupported server log level was accepted")
	}
}

// TestLoadProxyLogLevel verifies load proxy log level.
func TestLoadProxyLogLevel(t *testing.T) {
	base := `
proxy:
  listen: "127.0.0.1:3128"
  backend_url: "https://127.0.0.1:8443"
  internal_psk: "` + strings.Repeat("ab", 32) + `"
`

	cfg, err := LoadProxy(writeConfig(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Proxy.LogLevel != "info" {
		t.Fatalf("default proxy log level = %q, want info", cfg.Proxy.LogLevel)
	}
	for _, level := range []string{"info", "verbose", "debug"} {
		t.Run(level, func(t *testing.T) {
			explicit := strings.Replace(base, "  listen:", "  log_level: "+level+"\n  listen:", 1)
			loaded, loadErr := LoadProxy(writeConfig(t, explicit))
			if loadErr != nil || loaded.Proxy.LogLevel != level {
				t.Fatalf("proxy log level = %q error=%v, want %q", loaded.Proxy.LogLevel, loadErr, level)
			}
		})
	}

	invalid := strings.Replace(base, "  listen:", "  log_level: trace\n  listen:", 1)
	if _, err := LoadProxy(writeConfig(t, invalid)); err == nil {
		t.Fatal("unsupported proxy log level was accepted")
	}
}

// TestLoadRejectsConfigurationSymlink verifies load rejects configuration symlink.
func TestLoadRejectsConfigurationSymlink(t *testing.T) {
	target := writeConfig(t, "proxy:\n  listen: 127.0.0.1:3128\n")
	link := filepath.Join(t.TempDir(), "proxy.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadProxy(link); err == nil {
		t.Fatal("configuration symlink was accepted")
	}
}

// TestLoadRejectsMultipleDocuments verifies load rejects multiple documents.
func TestLoadRejectsMultipleDocuments(t *testing.T) {
	path := writeConfig(t, `
agent:
  id: display-01
  psk: "`+strings.Repeat("ab", 32)+`"
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: http://127.0.0.1:3128
---
agent:
  id: substituted
`)
	if _, err := LoadAgent(path); err == nil {
		t.Fatal("multiple YAML documents were accepted")
	}
}

// TestAgentRejectsUnknownProxyEnabledSetting verifies strict rejection of an unknown proxy field.
func TestAgentRejectsUnknownProxyEnabledSetting(t *testing.T) {
	path := writeConfig(t, `
agent:
  id: display-01
  psk: "`+strings.Repeat("ab", 32)+`"
transport:
  url: ws://127.0.0.1:8081
proxy:
  enabled: false
  url: http://127.0.0.1:3128
`)
	if _, err := LoadAgent(path); err == nil {
		t.Fatal("unknown proxy.enabled field was accepted")
	}
}

// TestTransportRejectsWildcardListener verifies transport rejects wildcard listener.
func TestTransportRejectsWildcardListener(t *testing.T) {
	path := writeConfig(t, `
transport:
  listen: 0.0.0.0:8081
  controller_psk: "`+strings.Repeat("ab", 32)+`"
`)
	if _, err := LoadTransport(path); err == nil {
		t.Fatal("wildcard transport listener was accepted")
	}
}

// TestPrivateListenersAreAccepted verifies private transport and proxy listeners.
func TestPrivateListenersAreAccepted(t *testing.T) {
	psk := strings.Repeat("ab", 32)
	transport := fmt.Sprintf(`
transport:
  listen: 10.99.0.1:8081
  controller_psk: %q
`, psk)
	if _, err := LoadTransport(writeConfig(t, transport)); err != nil {
		t.Fatalf("private transport listener was rejected: %v", err)
	}
	proxy := fmt.Sprintf(`
proxy:
  listen: 10.99.0.1:3128
  backend_url: https://127.0.0.1:8443
  internal_psk: %q
`, psk)
	if _, err := LoadProxy(writeConfig(t, proxy)); err != nil {
		t.Fatalf("private proxy listener was rejected: %v", err)
	}
}

// TestAllListenersRejectNonPrivateAndIPv6Addresses verifies every tcp4 service has the same secure binding policy.
func TestAllListenersRejectNonPrivateAndIPv6Addresses(t *testing.T) {
	psk := strings.Repeat("ab", 32)
	serverBase := `
server:
  listen: %q
  tls_cert: /cert
  tls_key: /key
  database: /database
  proxy_internal_psk: %q
  transport_psk: %q
  transport_url: ws://127.0.0.1:8081
`
	transportBase := `
transport:
  listen: %q
  controller_psk: %q
`
	proxyBase := `
proxy:
  listen: %q
  backend_url: https://127.0.0.1:8443
  internal_psk: %q
`
	tests := []struct {
		name string
		load func(string) error
	}{
		{name: "server", load: func(listen string) error {
			_, err := LoadServer(writeConfig(t, fmt.Sprintf(serverBase, listen, psk, psk)))
			return err
		}},
		{name: "transport", load: func(listen string) error {
			_, err := LoadTransport(writeConfig(t, fmt.Sprintf(transportBase, listen, psk)))
			return err
		}},
		{name: "proxy", load: func(listen string) error {
			_, err := LoadProxy(writeConfig(t, fmt.Sprintf(proxyBase, listen, psk)))
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, listen := range []string{"0.0.0.0:8443", "203.0.113.10:8443", "localhost:8443", "[::1]:8443", "[fd00::1]:8443", "127.0.0.1:", "127.0.0.1:0", "127.0.0.1:-1", "127.0.0.1:65536", "127.0.0.1:https"} {
				if err := test.load(listen); err == nil {
					t.Errorf("listener %q was accepted", listen)
				}
			}
		})
	}
}

// TestServerConfigsAcceptWireGuardInterface verifies the plaintext-link interface setting is accepted.
func TestServerConfigsAcceptWireGuardInterface(t *testing.T) {
	psk := strings.Repeat("ab", 32)
	transport := fmt.Sprintf(`
transport:
  listen: 127.0.0.1:8081
  wireguard_interface: neodse
  controller_psk: %q
`, psk)
	if _, err := LoadTransport(writeConfig(t, transport)); err != nil {
		t.Fatal("transport wireguard_interface was rejected")
	}
	proxy := fmt.Sprintf(`
proxy:
  listen: 127.0.0.1:3128
  wireguard_interface: neodse
  backend_url: https://127.0.0.1:8443
  internal_psk: %q
`, psk)
	if _, err := LoadProxy(writeConfig(t, proxy)); err != nil {
		t.Fatal("proxy wireguard_interface was rejected")
	}
}

// TestProxyRejectsWildcardListener verifies proxy rejects wildcard listener.
func TestProxyRejectsWildcardListener(t *testing.T) {
	path := writeConfig(t, `
proxy:
  listen: 0.0.0.0:3128
  backend_url: https://127.0.0.1:8443
  internal_psk: "`+strings.Repeat("ab", 32)+`"
`)
	if _, err := LoadProxy(path); err == nil {
		t.Fatal("wildcard proxy listener was accepted")
	}
}

// TestAgentProxyIsPlainHTTPOnTransportPeer verifies agent proxy is plain http on transport peer.
func TestAgentProxyIsPlainHTTPOnTransportPeer(t *testing.T) {
	base := `
agent:
  id: display-01
  wireguard_interface: neodse
  psk: "` + strings.Repeat("ab", 32) + `"
transport:
  url: ws://127.0.0.1:8081
proxy:
  url: %s
`
	if _, err := LoadAgent(writeConfig(t, fmt.Sprintf(base, "http://127.0.0.1:3128"))); err != nil {
		t.Fatalf("valid proxy fixture: %v", err)
	}
	for name, proxyURL := range map[string]string{
		"TLS proxy":      "https://127.0.0.1:3128",
		"different peer": "http://127.0.0.2:3128",
		"public address": "http://203.0.113.10:3128",
		"IPv6 address":   "http://[fd00::1]:3128",
		"missing port":   "http://127.0.0.1",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadAgent(writeConfig(t, fmt.Sprintf(base, proxyURL))); err == nil {
				t.Fatalf("insecure proxy URL %q was accepted", proxyURL)
			}
		})
	}
}

// TestAgentTransportRejectsBasePathAndMissingPort verifies agent transport rejects base path and missing port.
func TestAgentTransportRejectsBasePathAndMissingPort(t *testing.T) {
	base := `
agent:
  id: display-01
  wireguard_interface: neodse
  psk: "` + strings.Repeat("ab", 32) + `"
transport:
  url: %s
proxy:
  url: http://127.0.0.1:3128
`
	if _, err := LoadAgent(writeConfig(t, fmt.Sprintf(base, "ws://127.0.0.1:8081"))); err != nil {
		t.Fatalf("valid transport fixture: %v", err)
	}
	for _, transportURL := range []string{"ws://127.0.0.1", "ws://127.0.0.1:8081/base", "ws://[fd00::1]:8081"} {
		if _, err := LoadAgent(writeConfig(t, fmt.Sprintf(base, transportURL))); err == nil {
			t.Fatalf("invalid transport URL %q was accepted", transportURL)
		}
	}
}

// TestLoadTransportValidationMatrix verifies load transport validation matrix.
func TestLoadTransportValidationMatrix(t *testing.T) {
	base := `
transport:
  listen: %q
  controller_psk: %q
  log_level: %q
`
	validPSK := strings.Repeat("ab", 32)
	tests := []struct {
		name, listen, psk, level string
		valid                    bool
	}{
		{name: "valid", listen: "127.0.0.1:8081", psk: validPSK, level: "debug", valid: true},
		{name: "listen", listen: "invalid", psk: validPSK, level: "info"},
		{name: "hostname", listen: "localhost:8081", psk: validPSK, level: "info"},
		{name: "private address", listen: "10.0.0.1:8081", psk: validPSK, level: "info", valid: true},
		{name: "public address", listen: "203.0.113.10:8081", psk: validPSK, level: "info"},
		{name: "PSK", listen: "127.0.0.1:8081", psk: "invalid", level: "info"},
		{name: "PSK leading whitespace", listen: "127.0.0.1:8081", psk: " " + validPSK, level: "info"},
		{name: "PSK trailing whitespace", listen: "127.0.0.1:8081", psk: validPSK + " ", level: "info"},
		{name: "log level", listen: "127.0.0.1:8081", psk: validPSK, level: "trace"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := LoadTransport(writeConfig(t, fmt.Sprintf(base, test.listen, test.psk, test.level)))
			if (err == nil) != test.valid {
				t.Fatalf("LoadTransport() error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

// TestLoadProxyValidationMatrix verifies load proxy validation matrix.
func TestLoadProxyValidationMatrix(t *testing.T) {
	base := `
proxy:
  listen: %q
  backend_url: %q
  internal_psk: %q
  tls_ca: %q
  authorized_networks: %s
`
	validPSK := strings.Repeat("ab", 32)
	tests := []struct {
		name, listen, backend, psk, tlsCA, networks string
		valid                                       bool
	}{
		{name: "deny-all default", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[]", valid: true},
		{name: "private", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, tlsCA: "/etc/neodse/ca.crt", networks: "[10.20.0.0/16]", valid: true},
		{name: "public", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[8.8.8.0/24]", valid: true},
		{name: "all IPv4", listen: "10.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[0.0.0.0/0]", valid: true},
		{name: "listen", listen: "invalid", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[]"},
		{name: "public address", listen: "203.0.113.10:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[]"},
		{name: "backend scheme", listen: "127.0.0.1:3128", backend: "http://127.0.0.1:8443", psk: validPSK, networks: "[]"},
		{name: "backend credentials", listen: "127.0.0.1:3128", backend: "https://user@127.0.0.1:8443", psk: validPSK, networks: "[]"},
		{name: "IPv6 backend", listen: "127.0.0.1:3128", backend: "https://[::1]:8443", psk: validPSK, networks: "[]"},
		{name: "TLS CA", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, tlsCA: "relative", networks: "[]"},
		{name: "PSK", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: "invalid", networks: "[]"},
		{name: "CIDR", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[invalid]"},
		{name: "IPv6 CIDR", listen: "127.0.0.1:3128", backend: "https://127.0.0.1:8443", psk: validPSK, networks: "[fd00::/8]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			loaded, err := LoadProxy(writeConfig(t, fmt.Sprintf(base, test.listen, test.backend, test.psk, test.tlsCA, test.networks)))
			if (err == nil) != test.valid {
				t.Fatalf("LoadProxy() error = %v, valid = %t", err, test.valid)
			}
			if test.name == "deny-all default" && len(loaded.Proxy.AuthorizedNetworks) != 0 {
				t.Fatalf("default authorized networks = %v, want empty", loaded.Proxy.AuthorizedNetworks)
			}
		})
	}
}

// TestLoadProxyCapacity applies documented defaults and rejects capacity that
// would admit no traffic or let one display exceed the fleet-wide limit.
func TestLoadProxyCapacity(t *testing.T) {
	base := "proxy:\n  listen: 127.0.0.1:3128\n  backend_url: https://127.0.0.1:8443\n  internal_psk: " + strings.Repeat("ab", 32) + "\n"
	for _, test := range []struct {
		name, settings string
		global, agent  int
		valid          bool
	}{
		{name: "defaults", global: DefaultProxyConnections, agent: DefaultProxyAgentConnections, valid: true},
		{name: "explicit zero defaults", settings: "  max_connections: 0\n  max_agent_connections: 0\n", global: DefaultProxyConnections, agent: DefaultProxyAgentConnections, valid: true},
		{name: "configured", settings: "  max_connections: 4096\n  max_agent_connections: 64\n", global: 4096, agent: 64, valid: true},
		{name: "equal limits", settings: "  max_connections: 8\n  max_agent_connections: 8\n", global: 8, agent: 8, valid: true},
		{name: "negative global", settings: "  max_connections: -1\n"},
		{name: "global too large", settings: fmt.Sprintf("  max_connections: %d\n", MaxProxyConnections+1)},
		{name: "negative agent", settings: "  max_agent_connections: -1\n"},
		{name: "agent too large", settings: fmt.Sprintf("  max_connections: %d\n  max_agent_connections: %d\n", MaxProxyConnections, MaxProxyAgentConnections+1)},
		{name: "agent above global", settings: "  max_connections: 8\n  max_agent_connections: 9\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			loaded, err := LoadProxy(writeConfig(t, base+test.settings))
			if (err == nil) != test.valid {
				t.Fatalf("LoadProxy() error = %v, valid = %t", err, test.valid)
			}
			if test.valid && (loaded.Proxy.MaxConnections != test.global || loaded.Proxy.MaxAgentConnections != test.agent) {
				t.Fatalf("capacity = %d/%d, want %d/%d", loaded.Proxy.MaxConnections, loaded.Proxy.MaxAgentConnections, test.global, test.agent)
			}
		})
	}
}

// TestLoadServerRejectsInvalidRetentionPathsAndCredentials verifies load server rejects invalid retention paths and credentials.
func TestLoadServerRejectsInvalidRetentionPathsAndCredentials(t *testing.T) {
	base := `
server:
  listen: "127.0.0.1:8443"
  tls_cert: %q
  tls_key: %q
  database: %q
  proxy_internal_psk: %q
  transport_psk: %q
  transport_url: %q
  event_retention_days: %d
`
	validPSK := strings.Repeat("ab", 32)
	tests := []struct {
		name, cert, key, database, proxyPSK, transportPSK, transportURL string
		retention                                                       int
		valid                                                           bool
	}{
		{name: "valid", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://127.0.0.1:8081", retention: 30, valid: true},
		{name: "retention", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://127.0.0.1:8081", retention: 3651},
		{name: "certificate", cert: "relative", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://127.0.0.1:8081", retention: 30},
		{name: "transport URL", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "wss://127.0.0.1:8081", retention: 30},
		{name: "public transport", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://203.0.113.10:8081", retention: 30},
		{name: "transport hostname", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://transport.example:8081", retention: 30},
		{name: "normalized path", cert: "/etc/../tmp/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: validPSK, transportURL: "ws://127.0.0.1:8081", retention: 30},
		{name: "transport PSK", cert: "/cert", key: "/key", database: "/database", proxyPSK: validPSK, transportPSK: "invalid", transportURL: "ws://127.0.0.1:8081", retention: 30},
		{name: "proxy PSK", cert: "/cert", key: "/key", database: "/database", proxyPSK: "invalid", transportPSK: validPSK, transportURL: "ws://127.0.0.1:8081", retention: 30},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			contents := fmt.Sprintf(base, test.cert, test.key, test.database, test.proxyPSK, test.transportPSK, test.transportURL, test.retention)
			_, err := LoadServer(writeConfig(t, contents))
			if (err == nil) != test.valid {
				t.Fatalf("LoadServer() error = %v, valid = %t", err, test.valid)
			}
		})
	}
}

// TestLoadRejectsFIFOWithoutWriter ensures file-type validation cannot hang startup.
func TestLoadRejectsFIFOWithoutWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { var cfg Agent; done <- load(path, &cfg) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "not a regular file") {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		// Release a blocked reader so a regression does not leak a worker.
		fd, err := syscall.Open(path, syscall.O_WRONLY|syscall.O_NONBLOCK, 0)
		if err == nil {
			_ = syscall.Close(fd)
		}
		t.Fatal("configuration load blocked opening a FIFO")
	}
}

// TestHTTPSBackendPorts rejects unusable endpoints before service startup.
func TestHTTPSBackendPorts(t *testing.T) {
	for _, value := range []string{"https://:8443", "https://127.0.0.1:", "https://127.0.0.1:0", "https://127.0.0.1:65536"} {
		if err := validateHTTPSURL(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
	for _, value := range []string{"https://127.0.0.1", "https://127.0.0.1:443", "https://controller.example:65535"} {
		if err := validateHTTPSURL(value); err != nil {
			t.Errorf("rejected %q: %v", value, err)
		}
	}
}

// TestValidInterfaceName accepts kernel interface names that are also safe file name components.
func TestValidInterfaceName(t *testing.T) {
	for _, valid := range []string{"neodse", "wg0", "display_1", "a.b-c"} {
		if !ValidInterfaceName(valid) {
			t.Errorf("valid interface name %q was rejected", valid)
		}
	}
	for _, invalid := range []string{"", "../neodse", "/absolute", "sixteen-characters", "contains space", "wg0/config"} {
		if ValidInterfaceName(invalid) {
			t.Errorf("unsafe interface name %q was accepted", invalid)
		}
	}
}
