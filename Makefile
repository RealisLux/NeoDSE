# NeoDSE — local build and verification entry points.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

SHELL := /bin/bash
.SHELLFLAGS := -e -o pipefail -c
export GOTOOLCHAIN := local

BUILD_DIR ?= build
DIST_DIR ?= dist
VERSION ?= 0.0.0-local
COMPONENT ?= auto
FORMAT ?= auto
SELINUX_DEVEL ?= /usr/share/selinux/devel
SANITIZER_OPTIONS ?= detect_leaks=1:halt_on_error=1
UNDEFINED_SANITIZER_OPTIONS ?= halt_on_error=1
# Local checks use tools installed on PATH; CI uses maintained Actions.
ACTIONLINT ?= actionlint
GOLANGCI_LINT ?= golangci-lint
GOVULNCHECK ?= govulncheck
NFPM_VERSION := v2.48.0
NFPM := $(abspath $(BUILD_DIR)/tools/nfpm)
FUZZ_TIME ?= 15s
NODE ?= node
CLANG_FORMAT ?= clang-format-19

GOFLAGS ?= -trimpath -buildmode=pie -mod=readonly
# Strip DWARF only. The Go symbol table lets binary-mode govulncheck attribute
# findings to linked packages; without it, every symbol of a required module
# with an advisory counts as reachable.
GO_LDFLAGS := -w -X main.version=$(VERSION)
UI_WARNING_FLAGS := -Wall -Wextra -Wformat=2 -Wformat-signedness -Werror -Wpedantic
UI_HARDENING_CFLAGS := -fPIE -fstack-protector-strong -fno-common -D_FORTIFY_SOURCE=3
UI_CFLAGS := -std=c17 -O2 -pipe $(UI_HARDENING_CFLAGS) $(UI_WARNING_FLAGS) \
	-DNEODSE_VERSION='"$(VERSION)"'
UI_TEST_CFLAGS := -std=c17 -O2 -pipe $(UI_HARDENING_CFLAGS) $(UI_WARNING_FLAGS)
UI_SANITIZER_CFLAGS := -std=c17 -O1 -g -fno-omit-frame-pointer \
	-fsanitize=address,undefined $(UI_WARNING_FLAGS)
UI_LDFLAGS := -pie -Wl,-z,relro,-z,now

# Third-party headers are compiled under the project's strict warning policy, so
# package include paths must be system include paths.  Some GTK releases expand
# G_DECLARE_FINAL_TYPE with an extra top-level semicolon, which is a pedantic
# diagnostic in both GCC and Clang but is outside this project's control.
system_cflags = $$(pkg-config --cflags $(1) | sed -E 's@(^|[[:space:]])-I@\1-isystem @g')

.PHONY: all build agent server transport proxy ui vnc-auth-helper ui-test ui-test-sanitize ui-sanitize test security-coverage verify verify-go verify-security verify-binaries packaging-tools fuzz-smoke verify-native verify-native-sanitize verify-contracts verify-actions verify-modules verify-packaging selinux-policy package-local clean

all: build ui vnc-auth-helper

build: agent server transport proxy

agent:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/neodse-agent" ./cmd/neodse-agent

server:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/neodse-server" ./cmd/neodse-server

transport:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/neodse-transport" ./cmd/neodse-transport

proxy:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/neodse-proxy" ./cmd/neodse-proxy

.PHONY: verify-native-dependencies
verify-native-dependencies:
	pkg-config --print-errors --exists gtk4 webkitgtk-6.0 json-glib-1.0

ui: verify-native-dependencies
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(UI_CFLAGS) ui/*.c -o "$(BUILD_DIR)/neodse-ui" \
		$(call system_cflags,gtk4 webkitgtk-6.0 json-glib-1.0) \
		$$(pkg-config --libs gtk4 webkitgtk-6.0 json-glib-1.0) \
		$(UI_LDFLAGS)

vnc-auth-helper:
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags "$(GO_LDFLAGS)" -o "$(BUILD_DIR)/neodse-vnc-auth" ./cmd/neodse-vnc-auth

ui-test:
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(UI_TEST_CFLAGS) ui/tests/validation_test.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-validation-test" \
		$(call system_cflags,glib-2.0) $$(pkg-config --libs glib-2.0) \
		-pie -Wl,-z,relro,-z,now
	"$(BUILD_DIR)/neodse-ui-validation-test"
	$(CC) $(UI_TEST_CFLAGS) ui/tests/ipc_test.c ui/ipc.c ui/ipc_transport.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-ipc-test" \
		$(call system_cflags,gtk4 webkitgtk-6.0 json-glib-1.0) \
		$$(pkg-config --libs gtk4 webkitgtk-6.0 json-glib-1.0) \
		-pthread -Wl,--wrap=calloc,--wrap=strdup -pie -Wl,-z,relro,-z,now
	"$(BUILD_DIR)/neodse-ui-ipc-test"
	$(CC) $(UI_TEST_CFLAGS) ui/tests/ipc_server_test.c ui/ipc_server.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-ipc-server-test" \
		$(call system_cflags,glib-2.0) $$(pkg-config --libs glib-2.0) \
		-pthread -Wl,--wrap=accept4,--wrap=bind,--wrap=lstat,--wrap=chmod,--wrap=unlink,--wrap=getpwnam \
		-pie -Wl,-z,relro,-z,now
	"$(BUILD_DIR)/neodse-ui-ipc-server-test"
	# Inert GTK/WebKit stand-ins need headers only; clocks and timers are wrapped.
	$(CC) $(UI_TEST_CFLAGS) -DG_DISABLE_CAST_CHECKS ui/tests/playlist_test.c ui/playlist.c \
		-o "$(BUILD_DIR)/neodse-ui-playlist-test" \
		$(call system_cflags,gtk4 webkitgtk-6.0) $$(pkg-config --libs glib-2.0) \
		-Wl,--wrap=time,--wrap=g_timeout_add_seconds,--wrap=g_source_remove \
		-pie -Wl,-z,relro,-z,now
	"$(BUILD_DIR)/neodse-ui-playlist-test"

ui-test-sanitize:
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(UI_SANITIZER_CFLAGS) ui/tests/validation_test.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-validation-test-sanitize" \
		$(call system_cflags,glib-2.0) $$(pkg-config --libs glib-2.0) \
		-fsanitize=address,undefined -Wl,-z,relro,-z,now
	ASAN_OPTIONS=$(SANITIZER_OPTIONS) UBSAN_OPTIONS=$(UNDEFINED_SANITIZER_OPTIONS) \
		"$(BUILD_DIR)/neodse-ui-validation-test-sanitize"
	$(CC) $(UI_SANITIZER_CFLAGS) ui/tests/ipc_test.c ui/ipc.c ui/ipc_transport.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-ipc-test-sanitize" \
		$(call system_cflags,gtk4 webkitgtk-6.0 json-glib-1.0) \
		$$(pkg-config --libs gtk4 webkitgtk-6.0 json-glib-1.0) \
		-pthread -Wl,--wrap=calloc,--wrap=strdup -fsanitize=address,undefined \
		-Wl,-z,relro,-z,now
	ASAN_OPTIONS=$(SANITIZER_OPTIONS) UBSAN_OPTIONS=$(UNDEFINED_SANITIZER_OPTIONS) \
		"$(BUILD_DIR)/neodse-ui-ipc-test-sanitize"
	$(CC) $(UI_SANITIZER_CFLAGS) ui/tests/ipc_server_test.c ui/ipc_server.c ui/validation.c \
		-o "$(BUILD_DIR)/neodse-ui-ipc-server-test-sanitize" \
		$(call system_cflags,glib-2.0) $$(pkg-config --libs glib-2.0) \
		-pthread -Wl,--wrap=accept4,--wrap=bind,--wrap=lstat,--wrap=chmod,--wrap=unlink,--wrap=getpwnam \
		-fsanitize=address,undefined -Wl,-z,relro,-z,now
	ASAN_OPTIONS=$(SANITIZER_OPTIONS) UBSAN_OPTIONS=$(UNDEFINED_SANITIZER_OPTIONS) \
		"$(BUILD_DIR)/neodse-ui-ipc-server-test-sanitize"
	# Keep the production playlist code under the same deterministic clock fixture.
	$(CC) $(UI_SANITIZER_CFLAGS) -DG_DISABLE_CAST_CHECKS ui/tests/playlist_test.c ui/playlist.c \
		-o "$(BUILD_DIR)/neodse-ui-playlist-test-sanitize" \
		$(call system_cflags,gtk4 webkitgtk-6.0) $$(pkg-config --libs glib-2.0) \
		-Wl,--wrap=time,--wrap=g_timeout_add_seconds,--wrap=g_source_remove \
		-fsanitize=address,undefined -Wl,-z,relro,-z,now
	ASAN_OPTIONS=$(SANITIZER_OPTIONS) UBSAN_OPTIONS=$(UNDEFINED_SANITIZER_OPTIONS) \
		"$(BUILD_DIR)/neodse-ui-playlist-test-sanitize"

ui-sanitize: verify-native-dependencies
	mkdir -p "$(BUILD_DIR)"
	$(CC) $(UI_SANITIZER_CFLAGS) -DNEODSE_VERSION='"$(VERSION)"' \
		ui/*.c -o "$(BUILD_DIR)/neodse-ui-sanitize" \
		$(call system_cflags,gtk4 webkitgtk-6.0 json-glib-1.0) \
		$$(pkg-config --libs gtk4 webkitgtk-6.0 json-glib-1.0) \
		-fsanitize=address,undefined -Wl,-z,relro,-z,now

test:
	go test ./...

security-coverage:
	bash scripts/check-security-coverage.sh

verify: verify-go verify-contracts verify-dashboard verify-actions

verify-go: verify-modules
	test -z "$$(gofmt -l cmd internal)"
	go vet ./...
	go test ./...
	go test -race ./...

# These three integrations have dedicated mandatory gates. Every other skip
# means release prerequisites or regression evidence are missing.
.PHONY: verify-release-tests
verify-release-tests:
	mkdir -p "$(BUILD_DIR)/release-review"
	go test -json -count=1 ./... | tee "$(BUILD_DIR)/release-review/unit-tests.jsonl" | \
		python3 scripts/check-test-results.py \
		--allow-skip github.com/RealisLux/NeoDSE/internal/agent:TestStockWestonVNC \
		--allow-skip github.com/RealisLux/NeoDSE/internal/dashboard:TestDashboardBrowser \
		--allow-skip github.com/RealisLux/NeoDSE/internal/server:TestFleetIntegration

# nFPM is a packaging command, not a NeoDSE module dependency. Install the
# upstream version without maintaining its transitive module graph here.
packaging-tools:
	mkdir -p "$(dir $(NFPM))"
	GOBIN="$(dir $(NFPM))" go install github.com/goreleaser/nfpm/v2/cmd/nfpm@$(NFPM_VERSION)

# Convenience checks for developers with the analyzers installed locally.
# GitHub Actions runs the publishers' integrations for these checks.
verify-security:
	"$(GOLANGCI_LINT)" run ./cmd/... ./internal/...
	"$(GOVULNCHECK)" ./...
	$(MAKE) verify-binaries

verify-binaries: build vnc-auth-helper
	@for binary in "$(BUILD_DIR)"/neodse-agent "$(BUILD_DIR)"/neodse-server \
		"$(BUILD_DIR)"/neodse-transport "$(BUILD_DIR)"/neodse-proxy \
		"$(BUILD_DIR)"/neodse-vnc-auth; do \
		"$(GOVULNCHECK)" -mode=binary "$${binary}" || exit 1; \
	done

fuzz-smoke:
	go test ./internal/instruction -run '^$$' -fuzz FuzzDesiredStateValidation -fuzztime "$(FUZZ_TIME)"
	go test ./internal/protocol -run '^$$' -fuzz FuzzProtocolFrame -fuzztime "$(FUZZ_TIME)"
	go test ./internal/proxy -run '^$$' -fuzz FuzzProxyCredentials -fuzztime "$(FUZZ_TIME)"
	go test ./internal/config -run '^$$' -fuzz FuzzStrictYAMLDecode -fuzztime "$(FUZZ_TIME)"
	go test ./internal/provisioning -run '^$$' -fuzz FuzzProvisioningBlock -fuzztime "$(FUZZ_TIME)"

verify-native: build ui vnc-auth-helper ui-test
	$(CLANG_FORMAT) --dry-run --Werror ui/*.c ui/*.h ui/tests/*.c

verify-native-sanitize: ui-test-sanitize ui-sanitize

verify-contracts: verify-packaging
	@for script in scripts/*.sh; do bash -n "$${script}" || exit 1; done
	shellcheck -x scripts/*.sh
	cd internal/swagger/vendor && sha256sum --check MANIFEST.sha256
	go test -count=1 ./internal/config ./internal/swagger ./internal/quality

verify-actions:
	"$(ACTIONLINT)" -shellcheck shellcheck \
		-ignore 'label "ubuntu-26\.04(-arm)?" is unknown'

verify-modules:
	go mod verify
	go mod tidy -diff

verify-packaging:
	@if grep -REn '^[[:space:]]*(bindir|dependencies):' packaging/*.yaml; then \
		echo 'GoReleaser-only packaging fields found; standalone nFPM requires depends.' >&2; \
		exit 1; \
	fi
	@if grep -REn '^[[:space:]]*-[[:space:]]+src:.*\$\{' packaging/*.yaml; then \
		echo 'Variables in contents.src are not expanded by standalone nFPM.' >&2; \
		exit 1; \
	fi

selinux-policy:
	@test -f "$(SELINUX_DEVEL)/Makefile" || { \
		echo 'Missing $(SELINUX_DEVEL)/Makefile; install selinux-policy-devel for the target Enterprise Linux release.' >&2; \
		exit 1; \
	}
	mkdir -p $(BUILD_DIR)/selinux
	install -m 0644 selinux/neodse.te selinux/neodse.fc $(BUILD_DIR)/selinux/
	$(MAKE) -C $(BUILD_DIR)/selinux -f $(SELINUX_DEVEL)/Makefile neodse.pp

package-local: verify-packaging
	bash scripts/build-local-packages.sh --version "$(VERSION)" --component "$(COMPONENT)" --format "$(FORMAT)"

clean:
	rm -rf -- ./build ./dist

.PHONY: verify-dashboard
verify-dashboard:
	$(NODE) --test internal/dashboard/*.test.js

.PHONY: verify-dashboard-browser
verify-dashboard-browser: verify-native-dependencies
	mkdir -p "$(BUILD_DIR)"
	NEODSE_BROWSER_TEST=1 go test -json -count=1 -timeout=3m ./internal/dashboard -run '^TestDashboardBrowser$$' | \
		tee "$(BUILD_DIR)/dashboard-browser-tests.jsonl" | python3 scripts/check-test-results.py \
		--require-test github.com/RealisLux/NeoDSE/internal/dashboard:TestDashboardBrowser

INTEGRATION_DURATION ?= 1m
INTEGRATION_TIMEOUT ?= 3m
INTEGRATION_INTERVAL ?= 1s
INTEGRATION_RACE ?= true
.PHONY: integration
integration:
	mkdir -p "$(BUILD_DIR)"
	NEODSE_INTEGRATION_DURATION=$(INTEGRATION_DURATION) NEODSE_INTEGRATION_INTERVAL=$(INTEGRATION_INTERVAL) go test -json -race=$(INTEGRATION_RACE) -timeout=$(INTEGRATION_TIMEOUT) -count=1 ./internal/server -run '^TestFleetIntegration$$' | \
		tee "$(BUILD_DIR)/fleet-tests.jsonl" | python3 scripts/check-test-results.py \
		--require-test github.com/RealisLux/NeoDSE/internal/server:TestFleetIntegration

WESTON_TEST_RUNNER ?=
.PHONY: verify-weston-vnc
verify-weston-vnc: vnc-auth-helper
	go test -c -o $(BUILD_DIR)/weston-vnc.test ./internal/agent
	$(WESTON_TEST_RUNNER) scripts/check-weston-vnc.sh $(BUILD_DIR)/weston-vnc.test $(BUILD_DIR)/neodse-vnc-auth

WIREGUARD_TEST_RUNNER ?=
.PHONY: verify-wireguard-sockets
verify-wireguard-sockets:
	mkdir -p "$(BUILD_DIR)"
	go test -c -o "$(BUILD_DIR)/wireguard-sockets.test" ./internal/config
	$(WIREGUARD_TEST_RUNNER) scripts/check-wireguard-sockets.sh "$(BUILD_DIR)/wireguard-sockets.test"
