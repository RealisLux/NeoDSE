// File purpose: Verifies that bootstrap preserves authority and configuration created after its initial preflight.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RealisLux/NeoDSE/internal/storekey"
)

// bootstrapTestPaths confines all bootstrap targets to one empty test directory.
func bootstrapTestPaths(t *testing.T) bootstrapOptions {
	t.Helper()
	directory := t.TempDir()
	return bootstrapOptions{
		databasePath:  filepath.Join(directory, "controller.db"),
		configPath:    filepath.Join(directory, "server.yaml"),
		proxyPath:     filepath.Join(directory, "proxy.yaml"),
		transportPath: filepath.Join(directory, "transport.yaml"),
		certPath:      filepath.Join(directory, "server.crt"),
		keyPath:       filepath.Join(directory, "server.key"),
		wireGuardPath: filepath.Join(directory, "wireguard.conf"),
	}
}

// TestBootstrapRejectsAliasedTargets prevents valid flags from publishing YAML
// over a key, certificate, database, or another service's configuration.
func TestBootstrapRejectsAliasedTargets(t *testing.T) {
	for name, alias := range map[string]func(*testing.T, *bootstrapOptions){
		"service configuration": func(t *testing.T, options *bootstrapOptions) { options.proxyPath = options.configPath },
		"certificate":           func(t *testing.T, options *bootstrapOptions) { options.transportPath = options.certPath },
		"private key":           func(t *testing.T, options *bootstrapOptions) { options.configPath = options.keyPath },
		"database":              func(t *testing.T, options *bootstrapOptions) { options.configPath = options.databasePath },
		"keyslot": func(t *testing.T, options *bootstrapOptions) {
			options.configPath = storekey.Path(options.databasePath)
		},
		"wal":     func(t *testing.T, options *bootstrapOptions) { options.proxyPath = options.databasePath + "-wal" },
		"shm":     func(t *testing.T, options *bootstrapOptions) { options.proxyPath = options.databasePath + "-shm" },
		"journal": func(t *testing.T, options *bootstrapOptions) { options.proxyPath = options.databasePath + "-journal" },
		"nested target": func(t *testing.T, options *bootstrapOptions) {
			options.proxyPath = filepath.Join(options.configPath, "proxy.yaml")
		},
		"normalized path": func(t *testing.T, options *bootstrapOptions) {
			options.proxyPath = filepath.Dir(options.configPath) + "/unused/../" + filepath.Base(options.configPath)
		},
		"symlinked parent": func(t *testing.T, options *bootstrapOptions) {
			directory := filepath.Dir(options.configPath)
			link := filepath.Join(directory, "alias")
			if err := os.Symlink(directory, link); err != nil {
				t.Fatal(err)
			}
			options.configPath = filepath.Join(directory, "new", "server.yaml")
			options.proxyPath = filepath.Join(link, "new", "server.yaml")
		},
	} {
		t.Run(name, func(t *testing.T) {
			options := bootstrapTestPaths(t)
			alias(t, &options)
			for _, force := range []bool{false, true} {
				options.force = force
				if err := checkBootstrapTargets(options); err == nil || !strings.Contains(err.Error(), "different paths") {
					t.Fatalf("force=%t accepted overlapping outputs: %v", force, err)
				}
			}
		})
	}
}

// TestBootstrapNormalizesInput rejects invalid administrator names before any
// secret generation, and makes relative configuration paths safe to embed.
func TestBootstrapNormalizesInput(t *testing.T) {
	for _, name := range []string{"", " \t ", strings.Repeat("a", 129), "invalid UTF-8 \xff", "admin\x00name"} {
		options := bootstrapTestPaths(t)
		options.adminName = name
		if err := normalizeBootstrapOptions(&options); err == nil || !strings.Contains(err.Error(), "--admin-name") {
			t.Fatalf("invalid administrator name accepted: %v", err)
		}
	}
	options := bootstrapOptions{adminName: " initial-admin ", configPath: "server.yaml", proxyPath: "proxy.yaml", transportPath: "transport.yaml"}
	if err := normalizeBootstrapOptions(&options); err != nil {
		t.Fatal(err)
	}
	if options.adminName != "initial-admin" {
		t.Fatalf("administrator name = %q", options.adminName)
	}
	for _, path := range []string{options.configPath, options.proxyPath, options.transportPath} {
		if !filepath.IsAbs(path) {
			t.Fatalf("generated configuration references a relative path: %q", path)
		}
	}
	options.proxyPath = ""
	if err := normalizeBootstrapOptions(&options); err == nil {
		t.Fatal("empty configuration path accepted")
	}
}

// TestBootstrapForceRefusesNonregularTargets catches unsafe targets before an
// earlier generated file can be replaced, even when --force was requested.
func TestBootstrapForceRefusesNonregularTargets(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		name := "directory"
		if symlink {
			name = "symlink"
		}
		t.Run(name, func(t *testing.T) {
			options := bootstrapTestPaths(t)
			options.force = true
			if symlink {
				if err := os.Symlink("missing-target", options.proxyPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Mkdir(options.proxyPath, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := checkBootstrapTargets(options); err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("force accepted an unsafe target: %v", err)
			}
		})
	}
	options := bootstrapTestPaths(t)
	parent := filepath.Join(filepath.Dir(options.proxyPath), "dangling")
	if err := os.Symlink("missing-directory", parent); err != nil {
		t.Fatal(err)
	}
	options.proxyPath = filepath.Join(parent, "new", "proxy.yaml")
	if err := checkBootstrapTargets(options); err == nil {
		t.Fatal("dangling parent symlink was accepted")
	}
}

// TestBootstrapRechecksTargets models another command completing while the
// first command is still waiting for its passphrase. Force never permits
// replacing an existing authority or its recoverable files.
func TestBootstrapRechecksTargets(t *testing.T) {
	for _, target := range []string{"database", "keyslot", "wal", "shm", "journal", "config", "proxy", "transport", "certificate", "private-key", "wireguard"} {
		t.Run(target, func(t *testing.T) {
			options := bootstrapTestPaths(t)
			if err := checkBootstrapTargets(options); err != nil {
				t.Fatal(err)
			}
			paths := map[string]string{
				"database": options.databasePath, "keyslot": storekey.Path(options.databasePath),
				"wal": options.databasePath + "-wal", "shm": options.databasePath + "-shm", "journal": options.databasePath + "-journal",
				"config": options.configPath, "proxy": options.proxyPath, "transport": options.transportPath,
				"certificate": options.certPath, "private-key": options.keyPath, "wireguard": options.wireGuardPath,
			}
			path := paths[target]
			if err := os.WriteFile(path, []byte("completed by another command"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := checkBootstrapTargets(options); err == nil {
				t.Fatal("stale preflight permitted replacing a newly created target")
			}
			options.force = true
			err := checkBootstrapTargets(options)
			authority := target == "database" || target == "keyslot" || target == "wal" || target == "shm" || target == "journal"
			if authority && !errors.Is(err, os.ErrExist) {
				t.Fatalf("force permitted replacing authority: %v", err)
			}
			if !authority && err != nil {
				t.Fatalf("force refused generated configuration: %v", err)
			}
			contents, err := os.ReadFile(path)
			if err != nil || string(contents) != "completed by another command" {
				t.Fatalf("preflight modified the existing target: %q, %v", contents, err)
			}
		})
	}
}

// TestBootstrapInitializationPreservesExistingAuthority guards the final write
// boundary directly, without requiring installation accounts or host files.
func TestBootstrapInitializationPreservesExistingAuthority(t *testing.T) {
	for _, target := range []string{"database-and-keyslot", "keyslot-only", "dangling-keyslot"} {
		t.Run(target, func(t *testing.T) {
			options := bootstrapTestPaths(t)
			if err := checkBootstrapTargets(options); err != nil {
				t.Fatal(err)
			}
			keyslotPath := storekey.Path(options.databasePath)
			if target == "database-and-keyslot" {
				if err := os.WriteFile(options.databasePath, []byte("existing authority"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if target == "dangling-keyslot" {
				if err := os.Symlink("recoverable-keyslot", keyslotPath); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(keyslotPath, []byte("existing keyslot"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := initializeBootstrapAuthority(context.Background(), options, Config{}, testDatabaseKey, []byte("replacement keyslot")); !errors.Is(err, os.ErrExist) {
				t.Fatalf("initialize error = %v, want already exists", err)
			}
			if target == "dangling-keyslot" {
				if link, err := os.Readlink(keyslotPath); err != nil || link != "recoverable-keyslot" {
					t.Fatalf("existing keyslot link changed: %q, %v", link, err)
				}
			} else if contents, err := os.ReadFile(keyslotPath); err != nil || string(contents) != "existing keyslot" {
				t.Fatalf("existing keyslot changed: %q, %v", contents, err)
			}
			if target == "database-and-keyslot" {
				if contents, err := os.ReadFile(options.databasePath); err != nil || string(contents) != "existing authority" {
					t.Fatalf("existing authority changed: %q, %v", contents, err)
				}
			} else if _, err := os.Lstat(options.databasePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("refused initialization created a database: %v", err)
			}
		})
	}
}
