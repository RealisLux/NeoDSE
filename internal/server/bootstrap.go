// File purpose: Bootstraps controller, transport, proxy, WireGuard, TLS and the encrypted database with durable configuration writes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/RealisLux/NeoDSE/internal/config"
	"github.com/RealisLux/NeoDSE/internal/provisioning"
	"github.com/RealisLux/NeoDSE/internal/store"
	"github.com/RealisLux/NeoDSE/internal/storekey"
	"go.yaml.in/yaml/v3"
)

// bootstrapServer validates paths, generates secrets, and atomically writes initial service configuration.
func bootstrapServer(ctx context.Context, args []string) error {
	options, serverIP, err := parseBootstrapOptions(args)
	if err != nil {
		return err
	}
	// Ask for the passphrase before any file changes, so an abort leaves nothing behind.
	fmt.Fprintln(os.Stderr, "> Choose the passphrase that unlocks the controller database after every restart.")
	fmt.Fprintln(os.Stderr, "> Store it safely: without it the database cannot be recovered.")
	passphrase, err := readNewDatabasePassphrase(ctx, os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	key, err := storekey.GenerateKey()
	if err != nil {
		clear(passphrase)
		return err
	}
	defer clear(key)
	keyslot, err := storekey.Seal(key, passphrase)
	clear(passphrase)
	if err != nil {
		return err
	}
	// Another administrator may have completed bootstrap while this command
	// waited for its passphrase. Serialize and recheck before changing files.
	if err := os.MkdirAll(filepath.Dir(options.wireGuardPath), 0o700); err != nil {
		return err
	}
	lock, err := provisioning.LockDirectory(filepath.Dir(options.wireGuardPath))
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := checkBootstrapTargets(options); err != nil {
		return err
	}
	plan, err := buildBootstrapPlan(options, serverIP, lock)
	if err != nil {
		return err
	}
	if err := writeBootstrapPlan(options, plan); err != nil {
		return err
	}
	return initializeBootstrapAuthority(ctx, options, plan.serverConfig, key, keyslot)
}

type bootstrapOptions struct {
	configPath    string
	proxyPath     string
	transportPath string
	instance      string
	addressCIDR   string
	endpoint      string
	adminName     string
	listenPort    int
	force         bool
	databasePath  string
	certPath      string
	keyPath       string
	wireGuardPath string
}

type bootstrapPlan struct {
	serverConfig    config.Server
	proxyConfig     config.Proxy
	transportConfig config.Transport
	wireGuardConfig []byte
}

// parseBootstrapOptions validates privileged flags and refuses unsafe replacement targets.
func parseBootstrapOptions(args []string) (bootstrapOptions, net.IP, error) {
	options := bootstrapOptions{configPath: config.DefaultServerPath, proxyPath: config.DefaultProxyPath, transportPath: config.DefaultTransportPath, instance: "neodse", adminName: "initial-admin", listenPort: 51820}
	flags := flag.NewFlagSet("bootstrap", flag.ContinueOnError)
	flags.StringVar(&options.configPath, "config", options.configPath, "server configuration path")
	flags.StringVar(&options.proxyPath, "proxy-config", options.proxyPath, "proxy configuration path")
	flags.StringVar(&options.transportPath, "transport-config", options.transportPath, "transport configuration path")
	flags.StringVar(&options.instance, "instance", options.instance, "WireGuard interface name")
	flags.StringVar(&options.addressCIDR, "server-address", "", "WireGuard server IPv4 CIDR")
	flags.StringVar(&options.endpoint, "server-endpoint", "", "public WireGuard endpoint host:port")
	flags.StringVar(&options.adminName, "admin-name", options.adminName, "initial administrator service-account name")
	flags.IntVar(&options.listenPort, "listen-port", options.listenPort, "WireGuard UDP port")
	flags.BoolVar(&options.force, "force", false, "replace generated configuration")
	if err := flags.Parse(args); err != nil {
		return options, nil, err
	}
	if flags.NArg() != 0 {
		return options, nil, errors.New("bootstrap accepts no positional arguments")
	}
	if !config.ValidInterfaceName(options.instance) || options.addressCIDR == "" || options.endpoint == "" || options.listenPort < 1 || options.listenPort > 65535 {
		return options, nil, errors.New("valid --instance, --server-address, --server-endpoint, and --listen-port values are required")
	}
	if err := normalizeBootstrapOptions(&options); err != nil {
		return options, nil, err
	}
	serverIP, err := parseBootstrapAddress(options.addressCIDR)
	if err != nil {
		return options, nil, err
	}
	if err := provisioning.ValidateServerEndpoint(options.endpoint); err != nil {
		return options, nil, fmt.Errorf("--server-endpoint: %w", err)
	}
	options.wireGuardPath = filepath.Join("/etc/wireguard", options.instance+".conf")
	options.databasePath = filepath.Join(config.DefaultStateDir, "controller.db")
	options.certPath = filepath.Join(filepath.Dir(options.configPath), "server.crt")
	options.keyPath = filepath.Join(filepath.Dir(options.configPath), "server.key")
	if err := checkBootstrapTargets(options); err != nil {
		return options, nil, err
	}
	return options, serverIP, nil
}

// normalizeBootstrapOptions validates operator input before prompting or writing
// files. Absolute configuration paths also keep the generated TLS references
// valid when an operator supplies a relative --config path.
func normalizeBootstrapOptions(options *bootstrapOptions) error {
	options.adminName = strings.TrimSpace(options.adminName)
	if options.adminName == "" || len(options.adminName) > 128 || !utf8.ValidString(options.adminName) || strings.ContainsRune(options.adminName, '\x00') {
		return errors.New("--admin-name must be 1-128 bytes of valid UTF-8 without NUL")
	}
	for _, path := range []*string{&options.configPath, &options.proxyPath, &options.transportPath} {
		if strings.TrimSpace(*path) == "" {
			return errors.New("bootstrap configuration paths must not be empty")
		}
		absolute, err := filepath.Abs(*path)
		if err != nil {
			return fmt.Errorf("resolve bootstrap configuration path: %w", err)
		}
		*path = absolute
	}
	return nil
}

// checkBootstrapAuthorityPath refuses both existing authority and recoverable
// files before bootstrap writes a keyslot or creates a database.
func checkBootstrapAuthorityPath(databasePath string) error {
	if err := store.CheckCreatePath(databasePath); err != nil {
		return fmt.Errorf("bootstrap requires a new authority database path: %w", err)
	}
	keyslotPath := storekey.Path(databasePath)
	if _, err := os.Lstat(keyslotPath); err == nil {
		return fmt.Errorf("bootstrap cannot replace database keyslot %s: %w", keyslotPath, os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect database keyslot %s: %w", keyslotPath, err)
	}
	return nil
}

// checkBootstrapTargets is repeated under the provisioning lock after input,
// so an earlier successful preflight never authorizes replacing newer files.
func checkBootstrapTargets(options bootstrapOptions) error {
	// Distinct flags can still name the same file through ../ or a symlinked
	// parent. Refuse aliases before one output can overwrite another format.
	paths := []string{options.databasePath, storekey.Path(options.databasePath), options.databasePath + "-wal", options.databasePath + "-shm", options.databasePath + "-journal",
		options.configPath, options.proxyPath, options.transportPath, options.certPath, options.keyPath, options.wireGuardPath}
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		canonical, err := bootstrapTargetPath(path)
		if err != nil {
			return fmt.Errorf("inspect bootstrap target %s: %w", path, err)
		}
		for other, previous := range seen {
			if canonical == other || strings.HasPrefix(canonical, other+string(filepath.Separator)) || strings.HasPrefix(other, canonical+string(filepath.Separator)) {
				return fmt.Errorf("bootstrap targets must use different paths without nesting: %s and %s", previous, path)
			}
		}
		seen[canonical] = path
	}
	if err := checkBootstrapAuthorityPath(options.databasePath); err != nil {
		return err
	}
	for _, path := range []string{options.configPath, options.proxyPath, options.transportPath, options.certPath, options.keyPath, options.wireGuardPath} {
		if info, err := os.Lstat(path); err == nil {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("bootstrap target %s is not a regular file", path)
			}
			if !options.force {
				return fmt.Errorf("%s already exists; use --force to replace generated configuration", path)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect generated configuration %s: %w", path, err)
		}
	}
	return nil
}

// bootstrapTargetPath resolves existing parent symlinks without requiring the
// target or its directory to exist. The final name is never followed: file
// publication separately refuses a symbolic link at that name.
func bootstrapTargetPath(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	parent, suffix := filepath.Dir(absolute), filepath.Base(absolute)
	for {
		resolved, err := filepath.EvalSymlinks(parent)
		if err == nil {
			return filepath.Join(resolved, suffix), nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		if _, statErr := os.Lstat(parent); statErr == nil {
			// An existing parent that cannot resolve is a dangling symlink.
			return "", err
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return "", statErr
		}
		suffix = filepath.Join(filepath.Base(parent), suffix)
		parent = filepath.Dir(parent)
	}
}

// parseBootstrapAddress rejects unusable WireGuard subnets before bootstrap writes any files.
func parseBootstrapAddress(value string) (net.IP, error) {
	serverIP, network, err := net.ParseCIDR(value)
	if err != nil || serverIP.To4() == nil || !serverIP.IsPrivate() {
		return nil, errors.New("--server-address must be a private IPv4 host address with a CIDR prefix")
	}
	ones, bits := network.Mask.Size()
	if bits != 32 || ones > 30 {
		return nil, errors.New("--server-address subnet must have room for the server and at least one agent")
	}
	broadcast := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(broadcast, binary.BigEndian.Uint32(network.IP.To4())|(^uint32(0)>>ones))
	if !network.IP.IsPrivate() || !broadcast.IsPrivate() || serverIP.Equal(network.IP) || serverIP.Equal(broadcast) {
		return nil, errors.New("--server-address must use a host address in a wholly private IPv4 subnet")
	}
	return serverIP, nil
}

// buildBootstrapPlan generates secrets and constructs all service configuration values.
func buildBootstrapPlan(options bootstrapOptions, serverIP net.IP, lock *os.File) (bootstrapPlan, error) {
	privateKey, err := provisioning.Run("", "wg", "genkey")
	if err != nil {
		return bootstrapPlan{}, err
	}
	transportPSK, err := provisioning.RandomPSK()
	if err != nil {
		return bootstrapPlan{}, err
	}
	proxyPSK, err := provisioning.RandomPSK()
	if err != nil {
		return bootstrapPlan{}, err
	}
	if err := writeServerCertificateWithLock(options.certPath, options.keyPath, nil, lock); err != nil {
		return bootstrapPlan{}, err
	}
	var serverConfig config.Server
	serverConfig.Server.WireGuardInterface = options.instance
	serverConfig.Server.Listen = "127.0.0.1:8443"
	serverConfig.Server.TLSCert, serverConfig.Server.TLSKey = options.certPath, options.keyPath
	serverConfig.Server.ProxyInternalPSK = proxyPSK
	serverConfig.Server.LogLevel = "info"
	serverConfig.Server.Database = options.databasePath
	serverConfig.Server.TransportURL = "ws://" + net.JoinHostPort(serverIP.String(), "8081")
	serverConfig.Server.TransportPSK = transportPSK
	serverConfig.Server.EventRetentionDays = 30
	var proxyConfig config.Proxy
	proxyConfig.Proxy.WireGuardInterface = options.instance
	proxyConfig.Proxy.Listen = net.JoinHostPort(serverIP.String(), "3128")
	proxyConfig.Proxy.BackendURL = "https://127.0.0.1:8443"
	proxyConfig.Proxy.InternalPSK = proxyPSK
	proxyConfig.Proxy.TLSCA = options.certPath
	proxyConfig.Proxy.MaxConnections = config.DefaultProxyConnections
	proxyConfig.Proxy.MaxAgentConnections = config.DefaultProxyAgentConnections
	proxyConfig.Proxy.LogLevel = "info"
	var transportConfig config.Transport
	transportConfig.Transport.WireGuardInterface = options.instance
	transportConfig.Transport.Listen = net.JoinHostPort(serverIP.String(), "8081")
	transportConfig.Transport.ControllerPSK = transportPSK
	transportConfig.Transport.LogLevel = "info"
	wg := fmt.Sprintf("# NeoDSEEndpoint = %s\n[Interface]\nPrivateKey = %s\nAddress = %s\nListenPort = %d\n", options.endpoint, privateKey, options.addressCIDR, options.listenPort)
	return bootstrapPlan{serverConfig: serverConfig, proxyConfig: proxyConfig, transportConfig: transportConfig, wireGuardConfig: []byte(wg)}, nil
}

// writeBootstrapPlan atomically writes service YAML and WireGuard configuration with least privilege.
func writeBootstrapPlan(options bootstrapOptions, plan bootstrapPlan) error {
	configurations := []struct {
		path  string
		group string
		value any
	}{
		{path: options.configPath, group: "neodse-server", value: plan.serverConfig},
		{path: options.proxyPath, group: "neodse-proxy", value: plan.proxyConfig},
		{path: options.transportPath, group: "neodse-transport", value: plan.transportConfig},
	}
	for _, configuration := range configurations {
		contents, err := yaml.Marshal(configuration.value)
		if err != nil {
			return err
		}
		if err := provisioning.WriteServiceFile(configuration.path, contents, 0o640, "root", configuration.group); err != nil {
			return err
		}
	}
	if err := provisioning.AtomicWrite(options.wireGuardPath, plan.wireGuardConfig, 0o600); err != nil {
		return err
	}
	return nil
}

// initializeBootstrapAuthority writes the keyslot, creates the encrypted
// database with the first account, and enables services. The controller
// starts locked until an administrator runs neodse-server unlock.
func initializeBootstrapAuthority(ctx context.Context, options bootstrapOptions, serverConfig config.Server, key, keyslot []byte) error {
	if err := checkBootstrapAuthorityPath(options.databasePath); err != nil {
		return err
	}
	keyslotPath := storekey.Path(options.databasePath)
	if err := provisioning.CreateServiceFile(keyslotPath, keyslot, 0o600, "neodse-server", "neodse-server"); err != nil {
		return fmt.Errorf("write database keyslot: %w", err)
	}
	controller := newServer(serverConfig, "bootstrap")
	database, err := store.Create(ctx, options.databasePath, key)
	if err != nil {
		_ = os.Remove(keyslotPath)
		return fmt.Errorf("create controller database: %w", err)
	}
	controller.store = database
	_, token, err := controller.createServiceAccount(ctx, serviceAccountInput{Name: options.adminName, Roles: []Role{RoleAdministrator}, AllAgents: true}, true)
	closeProvisioningDatabase(controller)
	if err != nil {
		for _, path := range []string{options.databasePath, options.databasePath + "-wal", options.databasePath + "-shm", options.databasePath + "-journal", keyslotPath} {
			_ = os.Remove(path)
		}
		return err
	}
	fmt.Fprintln(os.Stderr, "> Store this administrator token now; it will not be shown again.")
	fmt.Fprintln(os.Stdout, token)
	if _, err := provisioning.Run("", "chown", "-h", "neodse-server:neodse-server", options.databasePath); err != nil {
		return err
	}
	_, err = provisioning.Run("", "systemctl", "enable", "--now", "wg-quick@"+options.instance+".service")
	if err != nil {
		return err
	}
	if _, err = provisioning.Run("", "systemctl", "enable", "--now", "neodse-transport.service", "neodse-server.service", "neodse-proxy.service"); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "> The controller starts locked. Run sudo neodse-server unlock now and after every restart.")
	return nil
}

// The generated controller certificate lasts three years. The proxy verifies
// it for every authorization, so an expired certificate stops all display
// content: renew it with neodse-server renew-certificate before then.
const (
	serverCertificateCommonName = "NeoDSE controller"
	serverCertificateYears      = 3
)

// generateServerCertificate creates a browser-compatible self-signed ECDSA certificate.
func generateServerCertificate(additionalAddresses []net.IP) ([]byte, []byte, error) {
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1")}
	for _, address := range additionalAddresses {
		if address == nil {
			return nil, nil, errors.New("certificate address must be an IP address")
		}
		ipAddresses = append(ipAddresses, address)
	}
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now().UTC()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: serverCertificateCommonName}, NotBefore: now.Add(-5 * time.Minute), NotAfter: now.AddDate(serverCertificateYears, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IPAddresses: ipAddresses}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

// writeServerCertificate generates and installs a constrained certificate and private key.
func writeServerCertificate(certPath, keyPath string, additionalAddresses []net.IP) error {
	return writeServerCertificateWithLock(certPath, keyPath, additionalAddresses, nil)
}

// writeServerCertificateWithLock reuses bootstrap's directory lock when the
// certificate files share their directory with the WireGuard configuration.
func writeServerCertificateWithLock(certPath, keyPath string, additionalAddresses []net.IP, lock *os.File) error {
	certificatePEM, keyPEM, err := generateServerCertificate(additionalAddresses)
	if err != nil {
		return err
	}
	return replaceCertificateFilesWithLock(certPath, keyPath, certificatePEM, keyPEM, provisioning.WriteServiceFile, lock)
}

// replaceCertificateFilesWithLock restores the previous pair if either durable
// write fails. Services must be stopped during renewal: two files cannot be
// renamed together. It borrows a caller-held exclusive directory lock only when
// that lock covers the key directory; otherwise it acquires its own.
func replaceCertificateFilesWithLock(certPath, keyPath string, certificatePEM, keyPEM []byte,
	writeFile func(string, []byte, os.FileMode, string, string) error, heldDirectory *os.File,
) error {
	if filepath.Clean(certPath) == filepath.Clean(keyPath) {
		return errors.New("certificate and private key require different paths")
	}
	directory := filepath.Dir(keyPath)
	if err := os.MkdirAll(directory, 0o750); err != nil {
		return err
	}
	locked := false
	if heldDirectory != nil {
		heldInfo, err := heldDirectory.Stat()
		if err != nil {
			return err
		}
		directoryInfo, err := os.Stat(directory)
		if err != nil {
			return err
		}
		locked = heldInfo.IsDir() && os.SameFile(heldInfo, directoryInfo)
	}
	if !locked {
		lock, err := provisioning.LockDirectory(directory)
		if err != nil {
			return err
		}
		defer lock.Close()
	}
	certificate, err := provisioning.SnapshotFile(certPath, 1<<20)
	if err != nil {
		return fmt.Errorf("inspect certificate: %w", err)
	}
	key, err := provisioning.SnapshotFile(keyPath, 1<<20)
	if err != nil {
		return fmt.Errorf("inspect private key: %w", err)
	}
	restore := func(cause error) error {
		return errors.Join(cause, certificate.Restore(), key.Restore())
	}
	if err := writeFile(certPath, certificatePEM, 0o644, "root", "root"); err != nil {
		return restore(err)
	}
	if err := writeFile(keyPath, keyPEM, 0o640, "root", "neodse-server"); err != nil {
		return restore(err)
	}

	return nil
}
