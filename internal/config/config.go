// File purpose: Defines named YAML schemas and security validation for every NeoDSE service.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// Package config owns strict configuration schemas and validation for all services.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	pathpkg "path"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/keyderivation"
	"go.yaml.in/yaml/v3"
)

// Default configuration, state and runtime locations of the packaged services.
const (
	DefaultAgentPath     = "/etc/neodse/agent.yaml"
	DefaultServerPath    = "/etc/neodse/server.yaml"
	DefaultTransportPath = "/etc/neodse/transport.yaml"
	DefaultProxyPath     = "/etc/neodse/proxy.yaml"
	DefaultStateDir      = "/var/lib/neodse"
	DefaultRuntimeDir    = "/run/neodse"
)

var (
	interfaceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,14}$`)
	cecDevicePattern     = regexp.MustCompile(`^/dev/cec[0-9]+$`)
)

// Agent is the complete display-agent configuration.
type Agent struct {
	Agent     AgentSettings  `yaml:"agent"`
	Transport AgentTransport `yaml:"transport"`
	Proxy     AgentProxy     `yaml:"proxy"`
	Sound     SoundSettings  `yaml:"sound"`
	Serial    SerialSettings `yaml:"serial"`
	CEC       CECSettings    `yaml:"cec"`
}

// AgentSettings identifies an agent and its local security-sensitive endpoints.
type AgentSettings struct {
	ID                 string `yaml:"id"`
	FriendlyName       string `yaml:"friendly_name"`
	PSK                string `yaml:"psk"`
	WireGuardInterface string `yaml:"wireguard_interface"`
	UISocket           string `yaml:"ui_socket"`
	LogLevel           string `yaml:"log_level"`
}

// AgentTransport contains the controller transport URL used by an agent.
type AgentTransport struct {
	URL string `yaml:"url"`
}

// AgentProxy configures the mandatory explicit proxy used for remote content.
type AgentProxy struct {
	URL string `yaml:"url"`
}

// SoundSettings maps alert profiles to fixed local media paths.
type SoundSettings struct {
	Info     string `yaml:"info"`
	Warning  string `yaml:"warning"`
	Critical string `yaml:"critical"`
}

// SerialSettings configures the optional structured serial peripheral adapter.
type SerialSettings struct {
	Enabled           bool   `yaml:"enabled"`
	Port              string `yaml:"port"`
	Baudrate          int    `yaml:"baudrate"`
	ResponseTimeoutMS int    `yaml:"response_timeout_ms"`
}

// MaxSerialBaudRate limits peripheral command links to 115,200 baud.
const MaxSerialBaudRate = 115200

// CECSettings configures the HDMI-CEC target connected to this agent.
type CECSettings struct {
	Enabled bool   `yaml:"enabled"`
	Device  string `yaml:"device"`
}

// Server is the complete control-server configuration.
type Server struct {
	Server ServerSettings `yaml:"server"`
}

// ServerSettings contains controller listeners, secrets, storage, and retention policy.
type ServerSettings struct {
	WireGuardInterface string `yaml:"wireguard_interface"`
	Listen             string `yaml:"listen"`
	TLSCert            string `yaml:"tls_cert"`
	TLSKey             string `yaml:"tls_key"`
	ProxyInternalPSK   string `yaml:"proxy_internal_psk"`
	LogLevel           string `yaml:"log_level"`
	Database           string `yaml:"database"`
	TransportURL       string `yaml:"transport_url"`
	TransportPSK       string `yaml:"transport_psk"`
	EventRetentionDays int    `yaml:"event_retention_days"`
}

// Transport configures the independent WebSocket switching service.
type Transport struct {
	Transport TransportSettings `yaml:"transport"`
}

// TransportSettings contains the private listener and controller authentication secret.
type TransportSettings struct {
	WireGuardInterface string `yaml:"wireguard_interface"`
	Listen             string `yaml:"listen"`
	ControllerPSK      string `yaml:"controller_psk"`
	LogLevel           string `yaml:"log_level"`
}

// Proxy is the complete explicit-proxy configuration.
type Proxy struct {
	Proxy ProxySettings `yaml:"proxy"`
}

// ProxySettings contains private egress listener, backend authentication, and network policy.
type ProxySettings struct {
	WireGuardInterface  string   `yaml:"wireguard_interface"`
	Listen              string   `yaml:"listen"`
	BackendURL          string   `yaml:"backend_url"`
	InternalPSK         string   `yaml:"internal_psk"`
	TLSCA               string   `yaml:"tls_ca"`
	AuthorizedNetworks  []string `yaml:"authorized_networks"`
	MaxConnections      int      `yaml:"max_connections"`
	MaxAgentConnections int      `yaml:"max_agent_connections"`
	LogLevel            string   `yaml:"log_level"`
}

// Proxy capacity bounds concurrent requests and CONNECT tunnels. A tunnel holds
// its slot for its whole lifetime, so the fleet-wide limit must cover every
// display's open page connections and WebSockets.
const (
	DefaultProxyConnections      = 2048
	MaxProxyConnections          = 65536
	DefaultProxyAgentConnections = 32
	MaxProxyAgentConnections     = 1024
)

// LoadAgent strictly decodes and validates an agent configuration file.
func LoadAgent(path string) (Agent, error) {
	cfg := Agent{CEC: CECSettings{Enabled: true, Device: "/dev/cec0"}}
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	return ValidateAgent(cfg)
}

// ValidateAgent checks the complete in-memory configuration before provisioning publishes it.
func ValidateAgent(cfg Agent) (Agent, error) {
	cfg.Agent.FriendlyName = strings.TrimSpace(cfg.Agent.FriendlyName)
	if !identity.ValidFriendlyName(cfg.Agent.FriendlyName) {
		return cfg, errors.New("agent.friendly_name must be valid UTF-8, at most 32 characters, and contain no NUL")
	}
	if err := normalizeLogLevel("agent.log_level", &cfg.Agent.LogLevel); err != nil {
		return cfg, err
	}
	if !cecDevicePattern.MatchString(cfg.CEC.Device) {
		return cfg, errors.New("cec.device must be an explicit /dev/cecN path")
	}
	if cfg.Agent.UISocket == "" {
		cfg.Agent.UISocket = pathpkg.Join(DefaultRuntimeDir, "ui.sock")
	}
	if !isAbsoluteLinuxPath(cfg.Agent.UISocket) || len(cfg.Agent.UISocket) >= 108 {
		return cfg, errors.New("agent.ui_socket must be an absolute path shorter than 108 bytes")
	}
	if !identity.ValidAgentID(cfg.Agent.ID) {
		return cfg, errors.New("agent.id must be 1-32 characters using letters, digits, underscore, or hyphen")
	}
	if !ValidInterfaceName(cfg.Agent.WireGuardInterface) {
		return cfg, errors.New("agent.wireguard_interface is invalid")
	}
	if _, err := keyderivation.ParsePSK(cfg.Agent.PSK); err != nil {
		return cfg, fmt.Errorf("agent.psk: %w", err)
	}
	if err := validateWebSocketURL(cfg.Transport.URL); err != nil {
		return cfg, fmt.Errorf("transport.url: %w", err)
	}
	if err := validateExplicitProxyURL(cfg.Proxy.URL); err != nil {
		return cfg, fmt.Errorf("proxy.url: %w", err)
	}
	transportURL, _ := url.Parse(cfg.Transport.URL)
	proxyURL, _ := url.Parse(cfg.Proxy.URL)
	transportAddress, transportErr := netip.ParseAddr(transportURL.Hostname())
	proxyAddress, proxyErr := netip.ParseAddr(proxyURL.Hostname())
	if transportErr != nil || proxyErr != nil ||
		!transportAddress.Is4() || !proxyAddress.Is4() ||
		(!transportAddress.IsPrivate() && !transportAddress.IsLoopback()) ||
		(!proxyAddress.IsPrivate() && !proxyAddress.IsLoopback()) {
		return cfg, errors.New("transport.url and proxy.url must use private or loopback IPv4 addresses")
	}
	if transportAddress != proxyAddress {
		return cfg, errors.New("transport.url and proxy.url must use the same WireGuard peer address")
	}
	if cfg.Serial.Enabled && (strings.TrimSpace(cfg.Serial.Port) == "" || cfg.Serial.Baudrate <= 0 || cfg.Serial.Baudrate > MaxSerialBaudRate) {
		return cfg, fmt.Errorf("serial.port and serial.baudrate from 1 to %d are required when serial is enabled", MaxSerialBaudRate)
	}
	if cfg.Serial.Enabled && !isAbsoluteLinuxPath(cfg.Serial.Port) {
		return cfg, errors.New("serial.port must be an absolute path")
	}
	if cfg.Serial.Enabled && (cfg.Serial.ResponseTimeoutMS < 100 || cfg.Serial.ResponseTimeoutMS > 60000) {
		return cfg, errors.New("serial.response_timeout_ms must be 100-60000 when serial is enabled")
	}
	for name, value := range map[string]string{"sound.info": cfg.Sound.Info, "sound.warning": cfg.Sound.Warning, "sound.critical": cfg.Sound.Critical} {
		if value != "" && !isAbsoluteLinuxPath(value) {
			return cfg, fmt.Errorf("%s must be an absolute path", name)
		}
	}
	return cfg, nil
}

// LoadServer strictly decodes and validates a server configuration file.
func LoadServer(path string) (Server, error) {
	var cfg Server
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	if err := normalizeLogLevel("server.log_level", &cfg.Server.LogLevel); err != nil {
		return cfg, err
	}
	if cfg.Server.Database == "" {
		cfg.Server.Database = pathpkg.Join(DefaultStateDir, "controller.db")
	}
	if cfg.Server.EventRetentionDays == 0 {
		cfg.Server.EventRetentionDays = 30
	}
	if cfg.Server.EventRetentionDays < 1 || cfg.Server.EventRetentionDays > 3650 {
		return cfg, errors.New("event retention is outside supported bounds")
	}
	if err := validatePrivateListener(cfg.Server.Listen); err != nil {
		return cfg, fmt.Errorf("server.listen: %w", err)
	}
	if cfg.Server.TLSCert == "" || cfg.Server.TLSKey == "" {
		return cfg, errors.New("server.tls_cert and server.tls_key are required")
	}
	if !isAbsoluteLinuxPath(cfg.Server.TLSCert) || !isAbsoluteLinuxPath(cfg.Server.TLSKey) || !isAbsoluteLinuxPath(cfg.Server.Database) {
		return cfg, errors.New("server TLS and database paths must be absolute")
	}
	if err := validateWebSocketURL(cfg.Server.TransportURL); err != nil {
		return cfg, fmt.Errorf("server.transport_url: %w", err)
	}
	if err := validatePrivateURLHost(cfg.Server.TransportURL); err != nil {
		return cfg, fmt.Errorf("server.transport_url: %w", err)
	}
	if _, err := keyderivation.ParsePSK(cfg.Server.TransportPSK); err != nil {
		return cfg, fmt.Errorf("server.transport_psk: %w", err)
	}
	if _, err := keyderivation.ParsePSK(cfg.Server.ProxyInternalPSK); err != nil {
		return cfg, fmt.Errorf("server.proxy_internal_psk: %w", err)
	}
	return cfg, nil
}

// LoadTransport strictly decodes and validates transport configuration.
func LoadTransport(path string) (Transport, error) {
	var cfg Transport
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	if err := validatePrivateListener(cfg.Transport.Listen); err != nil {
		return cfg, fmt.Errorf("transport.listen: %w", err)
	}
	if _, err := keyderivation.ParsePSK(cfg.Transport.ControllerPSK); err != nil {
		return cfg, fmt.Errorf("transport.controller_psk: %w", err)
	}
	if err := normalizeLogLevel("transport.log_level", &cfg.Transport.LogLevel); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// LoadProxy strictly decodes and validates a proxy configuration file.
func LoadProxy(path string) (Proxy, error) {
	var cfg Proxy
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	if err := normalizeLogLevel("proxy.log_level", &cfg.Proxy.LogLevel); err != nil {
		return cfg, err
	}
	if err := validatePrivateListener(cfg.Proxy.Listen); err != nil {
		return cfg, fmt.Errorf("proxy.listen: %w", err)
	}
	if err := validateHTTPSURL(cfg.Proxy.BackendURL); err != nil {
		return cfg, fmt.Errorf("proxy.backend_url: %w", err)
	}
	if cfg.Proxy.TLSCA != "" && !isAbsoluteLinuxPath(cfg.Proxy.TLSCA) {
		return cfg, errors.New("proxy.tls_ca must be an absolute path")
	}
	if _, err := keyderivation.ParsePSK(cfg.Proxy.InternalPSK); err != nil {
		return cfg, fmt.Errorf("proxy.internal_psk: %w", err)
	}
	for _, value := range cfg.Proxy.AuthorizedNetworks {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return cfg, fmt.Errorf("proxy.authorized_networks contains invalid prefix %q: %w", value, err)
		}
		if !prefix.Addr().Is4() {
			return cfg, fmt.Errorf("proxy.authorized_networks contains non-IPv4 prefix %q", value)
		}
	}
	if cfg.Proxy.MaxConnections == 0 {
		cfg.Proxy.MaxConnections = DefaultProxyConnections
	}
	if cfg.Proxy.MaxAgentConnections == 0 {
		cfg.Proxy.MaxAgentConnections = DefaultProxyAgentConnections
	}
	if cfg.Proxy.MaxConnections < 1 || cfg.Proxy.MaxConnections > MaxProxyConnections {
		return cfg, fmt.Errorf("proxy.max_connections must be 1-%d", MaxProxyConnections)
	}
	if cfg.Proxy.MaxAgentConnections < 1 || cfg.Proxy.MaxAgentConnections > MaxProxyAgentConnections ||
		cfg.Proxy.MaxAgentConnections > cfg.Proxy.MaxConnections {
		return cfg, fmt.Errorf("proxy.max_agent_connections must be 1-%d and no greater than proxy.max_connections", MaxProxyAgentConnections)
	}
	return cfg, nil
}

// load opens a regular trusted configuration file and strictly decodes one bounded YAML document.
func load(path string, destination any) error {
	// Opening a FIFO must not block before the regular-file check below.
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return fmt.Errorf("open configuration %q: %w", path, err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat configuration %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("configuration %q is not a regular file", path)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != 0 && int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("configuration %q has unexpected owner uid %d", path, stat.Uid)
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && os.Geteuid() != 0 && info.Mode().Perm()&0o040 != 0 && int64(stat.Gid) != int64(os.Getegid()) {
		return fmt.Errorf("configuration %q has unexpected group gid %d", path, stat.Gid)
	}
	if info.Mode().Perm()&0o027 != 0 {
		return fmt.Errorf("configuration %q permissions %04o are too broad; expected 0640 or stricter", path, info.Mode().Perm())
	}
	contents, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil {
		return fmt.Errorf("read configuration %q: %w", path, err)
	}
	if len(contents) > 1<<20 {
		return fmt.Errorf("configuration %q exceeds 1 MiB", path)
	}
	if err := DecodeYAML(contents, destination); err != nil {
		return fmt.Errorf("decode configuration %q: %w", path, err)
	}
	return nil
}

// DecodeYAML strictly decodes one YAML document from already bounded bytes:
// unknown fields and further documents are errors.
func DecodeYAML(contents []byte, destination any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple YAML documents are forbidden")
		}
		return err
	}
	return nil
}

// normalizeLogLevel defaults an unset level to info and accepts only the
// levels that every service implements.
func normalizeLogLevel(field string, level *string) error {
	if *level == "" {
		*level = "info"
	}
	switch *level {
	case "info", "verbose", "debug":
		return nil
	default:
		return fmt.Errorf("%s must be info, verbose, or debug", field)
	}
}

// ValidInterfaceName reports whether a name is safe for a Linux network
// interface and for use as one filename component.
func ValidInterfaceName(name string) bool {
	return interfaceNamePattern.MatchString(name)
}

// validatePrivateListener permits literal loopback and private IPv4 addresses without inspecting interfaces.
func validatePrivateListener(value string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return err
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
		return errors.New("listener port must be a number from 1 to 65535")
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return errors.New("listener host must be an IP address")
	}
	if !address.Is4() {
		return errors.New("listener host must be an IPv4 address")
	}
	if address.IsUnspecified() {
		return errors.New("wildcard listeners are forbidden")
	}
	if address.IsLoopback() || address.IsPrivate() {
		return nil
	}
	return errors.New("listener address must be loopback or private")
}

// validateWebSocketURL accepts only a plain private ws endpoint with an explicit port.
func validateWebSocketURL(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}
	if u.Scheme != "ws" || u.Host == "" || u.User != nil || u.Port() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute ws:// host:port URL without credentials, path, query, or fragment")
	}
	if port, err := strconv.ParseUint(u.Port(), 10, 16); err != nil || port == 0 {
		return errors.New("must contain a valid explicit port")
	}
	return nil
}

// validatePrivateURLHost requires a literal private or loopback peer for an unencrypted service URL.
func validatePrivateURLHost(value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return err
	}
	address, err := netip.ParseAddr(parsed.Hostname())
	if err != nil || !address.Is4() || (!address.IsPrivate() && !address.IsLoopback()) {
		return errors.New("host must be a private or loopback IPv4 address")
	}
	return nil
}

// validateExplicitProxyURL accepts only a plain HTTP proxy endpoint without credentials or paths.
func validateExplicitProxyURL(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}
	if u.Scheme != "http" || u.Host == "" || u.User != nil || u.Port() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute plain-HTTP host:port URL without credentials, path, query, or fragment")
	}
	if address, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil && !address.Is4() {
		return errors.New("IPv6 proxy hosts are unsupported")
	}
	if port, err := strconv.ParseUint(u.Port(), 10, 16); err != nil || port == 0 {
		return errors.New("must contain a valid explicit port")
	}
	return nil
}

// validateHTTPSURL requires an absolute HTTPS backend URL without embedded credentials.
func validateHTTPSURL(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return err
	}
	if u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("must be an absolute HTTPS URL without embedded credentials")
	}
	if port := u.Port(); port != "" {
		if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
			return errors.New("HTTPS port must be a number from 1 to 65535")
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return errors.New("HTTPS URL contains an empty port")
	}
	if address, parseErr := netip.ParseAddr(u.Hostname()); parseErr == nil && !address.Is4() {
		return errors.New("IPv6 HTTPS hosts are unsupported")
	}
	return nil
}

// isAbsoluteLinuxPath rejects relative, non-normalized, and NUL-containing filesystem paths.
func isAbsoluteLinuxPath(value string) bool {
	return strings.HasPrefix(value, "/") && pathpkg.Clean(value) == value && !strings.ContainsRune(value, '\x00')
}
