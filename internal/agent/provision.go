// File purpose: Implements explicit agent bootstrap, enrollment, and configuration removal commands.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package agent

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/identity"
	"github.com/RealisLux/NeoDSE/internal/provisioning"
	"go.yaml.in/yaml/v3"
)

// provisionCommands lists the root commands of neodse-agent in the order --help shows them.
var provisionCommands = []struct{ name, summary string }{
	{"bootstrap", "Create the display configuration and WireGuard key"},
	{"provision", "Exchange enrollment blocks with the controller"},
	{"remove-config", "Remove the local enrollment"},
}

// isProvisionCommand reports whether name selects a root provisioning command instead of the service.
func isProvisionCommand(name string) bool {
	for _, command := range provisionCommands {
		if command.name == name {
			return true
		}
	}
	return false
}

// runProvisionCommand dispatches the explicit agent provisioning subcommands.
func runProvisionCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("provisioning command is required")
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("neodse-agent %s must run as root; run it with sudo", args[0])
	}
	return runLockedProvisionCommand(ctx, args, "/etc/wireguard")
}

// runLockedProvisionCommand holds the shared WireGuard lock across snapshots,
// operator input, durable changes, service restarts, and any rollback.
func runLockedProvisionCommand(ctx context.Context, args []string, directory string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	commands := map[string]func([]string) error{
		"bootstrap":     bootstrapAgent,
		"provision":     func(args []string) error { return provisionAgent(ctx, args) },
		"remove-config": removeAgentConfig,
	}
	command, ok := commands[args[0]]
	if !ok {
		return fmt.Errorf("unknown agent command %q", args[0])
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	lock, err := provisioning.LockDirectory(directory)
	if err != nil {
		return err
	}
	defer lock.Close()
	return command(args[1:])
}

// removeAgentConfig removes agent and WireGuard enrollment after stopping their services.
func removeAgentConfig(args []string) error {
	flags := flag.NewFlagSet("remove-config", flag.ContinueOnError)
	configPath, instance := config.DefaultAgentPath, "neodse"
	flags.StringVar(&configPath, "config", configPath, "agent configuration path")
	flags.StringVar(&instance, "instance", instance, "WireGuard instance")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("remove-config accepts no positional arguments")
	}
	if !config.ValidInterfaceName(instance) {
		return errors.New("invalid WireGuard interface name")
	}
	for _, command := range [][]string{
		{"stop", "neodse-agent.service"},
		{"disable", "wg-quick@" + instance + ".service"},
		{"stop", "wg-quick@" + instance + ".service"},
	} {
		if _, err := provisioning.Run("", "systemctl", command...); err != nil {
			return fmt.Errorf("prepare configuration removal: %w", err)
		}
	}
	for _, path := range []string{configPath, filepath.Join("/etc/wireguard", instance+".conf")} {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// bootstrapAgent creates local configuration and a private WireGuard key for later enrollment.
func bootstrapAgent(args []string) error {
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	configPath, instance, agentID, friendlyName, force := config.DefaultAgentPath, "neodse", "", "", false
	flags.StringVar(&configPath, "config", configPath, "agent configuration path")
	flags.StringVar(&instance, "instance", instance, "WireGuard instance")
	flags.StringVar(&agentID, "agent-id", agentID, "agent identifier")
	flags.StringVar(&friendlyName, "friendly-name", friendlyName, "optional display label (at most 32 characters)")
	flags.BoolVar(&force, "force", false, "replace existing bootstrap configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	friendlyName = strings.TrimSpace(friendlyName)
	if !identity.ValidFriendlyName(friendlyName) {
		return errors.New("--friendly-name must be valid UTF-8, at most 32 characters, and contain no NUL")
	}
	if !identity.ValidAgentID(agentID) {
		return errors.New("--agent-id is required and must be a valid identifier")
	}
	if !config.ValidInterfaceName(instance) {
		return errors.New("invalid WireGuard interface name")
	}
	if flags.NArg() != 0 {
		return errors.New("bootstrap accepts no positional arguments")
	}
	wgPath := filepath.Join("/etc/wireguard", instance+".conf")
	if err := validateBootstrapPaths(configPath, wgPath); err != nil {
		return err
	}
	configSnapshot, err := provisioning.SnapshotFile(configPath, 1<<20)
	if err != nil {
		return fmt.Errorf("inspect agent configuration: %w", err)
	}
	wgSnapshot, err := provisioning.SnapshotFile(wgPath, 1<<20)
	if err != nil {
		return fmt.Errorf("inspect WireGuard configuration: %w", err)
	}
	if !force && (configSnapshot.Exists() || wgSnapshot.Exists()) {
		return errors.New("agent or WireGuard configuration already exists; use --force")
	}
	privateKey, err := provisioning.Run("", "wg", "genkey")
	if err != nil {
		return err
	}
	restore := func(cause error) error {
		return errors.Join(cause, configSnapshot.Restore(), wgSnapshot.Restore())
	}
	cfg := agentBootstrapConfig(agentID, instance, friendlyName)
	if err := writeAgentConfig(configPath, cfg); err != nil {
		return restore(err)
	}
	if err := provisioning.AtomicWrite(wgPath, []byte("[Interface]\nPrivateKey = "+privateKey+"\n"), 0o600); err != nil {
		return restore(err)
	}
	if _, err := provisioning.Run("", "systemctl", "enable", "wg-quick@"+instance+".service"); err != nil {
		return restore(err)
	}
	if err := notifyBootstrapUI(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: agent bootstrap completed, but the display could not be refreshed: %v\n", err)
	}
	return nil
}

// validateBootstrapPaths prevents one output from replacing the other, including
// when different parent paths name the same directory through symbolic links.
func validateBootstrapPaths(configPath, wireGuardPath string) error {
	configuration, err := filepath.Abs(configPath)
	if err != nil {
		return err
	}
	wireGuard, err := filepath.Abs(wireGuardPath)
	if err != nil {
		return err
	}
	if configuration == wireGuard {
		return errors.New("agent and WireGuard configuration must use different files")
	}
	if filepath.Base(configuration) != filepath.Base(wireGuard) {
		return nil
	}
	configurationDirectory, err := os.Stat(filepath.Dir(configuration))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	wireGuardDirectory, err := os.Stat(filepath.Dir(wireGuard))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if os.SameFile(configurationDirectory, wireGuardDirectory) {
		return errors.New("agent and WireGuard configuration must use different files")
	}
	return nil
}

// notifyBootstrapUI identifies the display and returns it to the local page.
func notifyBootstrapUI(cfg config.Agent) error {
	bootstrapAgent := &Agent{config: cfg}
	if err := bootstrapAgent.sendUIStatus(
		"awaiting_provision",
		"info",
		"Agent bootstrapped; awaiting server provisioning",
	); err != nil {
		return fmt.Errorf("send bootstrap status: %w", err)
	}
	if err := bootstrapAgent.sendUICommand(uiDefaultRequest{Command: "default"}); err != nil {
		return fmt.Errorf("show default display: %w", err)
	}
	return nil
}

// provisionAgent validates a controller response and atomically installs configuration.
func provisionAgent(ctx context.Context, args []string) error {
	state, err := loadAgentProvisioning(args)
	if err != nil {
		return err
	}
	response, err := exchangeAgentProvisioning(ctx, state)
	if err != nil {
		return err
	}
	return applyAgentProvisioning(state, response)
}

type agentProvisioningState struct {
	configPath     string
	instance       string
	wireGuardPath  string
	originalConfig []byte
	originalWG     []byte
	config         config.Agent
	privateKey     string
}

// loadAgentProvisioning validates local bootstrap state required for enrollment.
func loadAgentProvisioning(args []string) (agentProvisioningState, error) {
	flags := flag.NewFlagSet("provision", flag.ContinueOnError)
	configPath, instance := config.DefaultAgentPath, "neodse"
	flags.StringVar(&configPath, "config", configPath, "agent configuration path")
	flags.StringVar(&instance, "instance", instance, "WireGuard instance")
	if err := flags.Parse(args); err != nil {
		return agentProvisioningState{}, err
	}
	if !config.ValidInterfaceName(instance) {
		return agentProvisioningState{}, errors.New("invalid WireGuard interface name")
	}
	if flags.NArg() != 0 {
		return agentProvisioningState{}, errors.New("provision accepts no positional arguments")
	}
	b, err := provisioning.ReadBoundedFile(configPath, 1<<20)
	if err != nil {
		return agentProvisioningState{}, err
	}
	var cfg config.Agent
	if err := config.DecodeYAML(b, &cfg); err != nil {
		return agentProvisioningState{}, err
	}
	if !identity.ValidAgentID(cfg.Agent.ID) {
		return agentProvisioningState{}, errors.New("agent is not bootstrapped")
	}
	wgPath := filepath.Join("/etc/wireguard", instance+".conf")
	wg, err := provisioning.ReadWireGuardConfig(instance)
	if err != nil {
		return agentProvisioningState{}, err
	}
	privateKey := wireGuardValue(string(wg), "PrivateKey")
	if privateKey == "" {
		return agentProvisioningState{}, errors.New("WireGuard private key is missing")
	}
	return agentProvisioningState{configPath: configPath, instance: instance, wireGuardPath: wgPath, originalConfig: b, originalWG: wg, config: cfg, privateKey: privateKey}, nil
}

// exchangeAgentProvisioning prints the local request and parses one operator-supplied response.
func exchangeAgentProvisioning(ctx context.Context, state agentProvisioningState) (provisioning.ServerResponse, error) {
	publicKey, err := provisioning.Run(state.privateKey+"\n", "wg", "pubkey")
	if err != nil {
		return provisioning.ServerResponse{}, err
	}
	writeCopyBanner(os.Stderr, "COPY TO SERVER")
	if err := provisioning.WriteAgentRequest(os.Stdout, provisioning.AgentRequest{AgentID: state.config.Agent.ID, WireGuardPublicKey: publicKey}); err != nil {
		return provisioning.ServerResponse{}, err
	}
	fmt.Fprintln(os.Stderr, "> Paste the server provisioning block, then press ENTER on an empty line.")
	values, err := provisioning.ReadBlock(ctx, os.Stdin)
	if err != nil {
		return provisioning.ServerResponse{}, err
	}
	return provisioning.ParseServerResponse(values)
}

// applyAgentProvisioning installs configuration and restores both services after any partial failure.
func applyAgentProvisioning(state agentProvisioningState, response provisioning.ServerResponse) error {
	nextWG := fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s/32\n\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nEndpoint = %s\nAllowedIPs = %s/32\nPersistentKeepalive = 25\n", state.privateKey, response.AgentAddress, response.ServerPublicKey, response.PresharedKey, response.ServerEndpoint, response.ServerAddress)
	state.config.Agent.PSK = strings.ToLower(response.AgentPSK)
	state.config.Agent.WireGuardInterface = state.instance
	state.config.Transport.URL = response.TransportURL
	state.config.Proxy.URL = response.ProxyURL
	validated, err := config.ValidateAgent(state.config)
	if err != nil {
		return err
	}
	state.config = validated
	if err := provisioning.AtomicWriteWithRollback(state.wireGuardPath, state.originalWG, []byte(nextWG), 0o600); err != nil {
		return err
	}
	if err := writeAgentConfig(state.configPath, state.config); err != nil {
		return restoreAgentProvisioning(state, err)
	}
	if _, err := provisioning.Run("", "systemctl", "restart", "wg-quick@"+state.instance+".service"); err != nil {
		return restartAfterAgentRestore(state, err, false)
	}
	if _, err := provisioning.Run("", "systemctl", "restart", "neodse-agent.service"); err != nil {
		return restartAfterAgentRestore(state, err, true)
	}
	return nil
}

// restoreAgentProvisioning restores durable files and their expected ownership.
func restoreAgentProvisioning(state agentProvisioningState, cause error) error {
	var restoreErrors []error
	if err := provisioning.AtomicWrite(state.wireGuardPath, state.originalWG, 0o600); err != nil {
		restoreErrors = append(restoreErrors, fmt.Errorf("restore WireGuard configuration: %w", err))
	}
	if err := provisioning.WriteServiceFile(state.configPath, state.originalConfig, 0o600, "neodse-agent", "neodse-agent"); err != nil {
		restoreErrors = append(restoreErrors, fmt.Errorf("restore agent configuration: %w", err))
	}
	return errors.Join(append([]error{cause}, restoreErrors...)...)
}

// restartAfterAgentRestore restores durable state and restarts affected services.
func restartAfterAgentRestore(state agentProvisioningState, cause error, restartAgent bool) error {
	cause = restoreAgentProvisioning(state, cause)
	if _, err := provisioning.Run("", "systemctl", "restart", "wg-quick@"+state.instance+".service"); err != nil {
		cause = errors.Join(cause, fmt.Errorf("restart restored WireGuard configuration: %w", err))
	}
	if restartAgent {
		if _, err := provisioning.Run("", "systemctl", "restart", "neodse-agent.service"); err != nil {
			cause = errors.Join(cause, fmt.Errorf("restart agent with restored configuration: %w", err))
		}
	}
	return cause
}

// agentBootstrapConfig constructs a complete unprovisioned agent configuration.
func agentBootstrapConfig(agentID, instance, friendlyName string) config.Agent {
	return config.Agent{
		Agent: config.AgentSettings{
			ID:                 agentID,
			FriendlyName:       friendlyName,
			WireGuardInterface: instance,
			UISocket:           filepath.Join(config.DefaultRuntimeDir, "ui.sock"),
			LogLevel:           "info",
		},
		Serial: config.SerialSettings{
			Enabled:           false,
			Port:              "/dev/ttyUSB0",
			Baudrate:          9600,
			ResponseTimeoutMS: 5000,
		},
		Sound: config.SoundSettings{
			Info:     "/usr/share/neodse/info.wav",
			Warning:  "/usr/share/neodse/warning.wav",
			Critical: "/usr/share/neodse/critical.wav",
		},
		CEC: config.CECSettings{Enabled: false, Device: "/dev/cec0"},
	}
}

// writeAgentConfig serializes and atomically writes completed agent configuration.
func writeAgentConfig(path string, cfg config.Agent) error {
	b, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return provisioning.WriteServiceFile(path, b, 0o600, "neodse-agent", "neodse-agent")
}

// wireGuardValue extracts one exact field from bounded WireGuard configuration.
func wireGuardValue(contents, key string) string {
	for line := range strings.SplitSeq(contents, "\n") {
		left, right, ok := strings.Cut(line, "=")
		if ok && strings.TrimSpace(left) == key {
			return strings.TrimSpace(right)
		}
	}
	return ""
}

// writeCopyBanner prints a clearly delimited operator transfer heading.
func writeCopyBanner(w *os.File, title string) {
	fmt.Fprintf(w, "\n========================================\n%s\n========================================\n\n", title)
}
