// File purpose: Enforces source headers, registered analyzer exceptions, and the persistence, service, SELinux, workflow and package contracts.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

package quality

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var goSuppressionIDPattern = regexp.MustCompile(`#nosec\s+\S+\s+--\s+(EXC-[A-Z0-9-]+):`)
var cSuppressionIDPattern = regexp.MustCompile(`cppcheck-suppress\s+\S+\s+--\s+(EXC-[A-Z0-9-]+):`)
var suppressionHeadingPattern = regexp.MustCompile(`(?m)^### (EXC-[A-Z0-9-]+)$`)

// TestGoFilesUseCanonicalHeader enforces file provenance and purpose headers.
func TestGoFilesUseCanonicalHeader(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"cmd", "internal", "tools"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			checkGoFileDocumentation(t, root, path)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
}

// TestCFilesUseCanonicalHeader enforces the shared metadata block for C sources and headers.
func TestCFilesUseCanonicalHeader(t *testing.T) {
	root := repositoryRoot(t)
	err := filepath.WalkDir(filepath.Join(root, "ui"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		extension := filepath.Ext(path)
		if entry.IsDir() || (extension != ".c" && extension != ".h") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !hasCanonicalCHeader(source) {
			relative, _ := filepath.Rel(root, path)
			t.Errorf("%s: header must contain purpose, copyright, SPDX, and project lines in canonical order", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk ui: %v", err)
	}
}

// TestSecuritySuppressionsAreRegistered rejects anonymous, duplicate, and stale analyzer exceptions.
func TestSecuritySuppressionsAreRegistered(t *testing.T) {
	root := repositoryRoot(t)
	sourceIDs := make(map[string]int)
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if count := strings.Count(string(source), "#nosec"); count != len(goSuppressionIDPattern.FindAllSubmatch(source, -1)) {
				relative, _ := filepath.Rel(root, path)
				t.Errorf("%s: every #nosec needs a registered EXC identifier", relative)
			}
			for _, match := range goSuppressionIDPattern.FindAllSubmatch(source, -1) {
				sourceIDs[string(match[1])]++
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
	err := filepath.WalkDir(filepath.Join(root, "ui"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || (filepath.Ext(path) != ".c" && filepath.Ext(path) != ".h") {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if count := strings.Count(string(source), "cppcheck-suppress"); count != len(cSuppressionIDPattern.FindAllSubmatch(source, -1)) {
			relative, _ := filepath.Rel(root, path)
			t.Errorf("%s: every cppcheck suppression needs a registered EXC identifier", relative)
		}
		for _, match := range cSuppressionIDPattern.FindAllSubmatch(source, -1) {
			sourceIDs[string(match[1])]++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	documentation, err := os.ReadFile(filepath.Join(root, "docs", "SECURITY_EXCEPTIONS.md"))
	if err != nil {
		t.Fatal(err)
	}
	documentedIDs := make(map[string]int)
	for _, match := range suppressionHeadingPattern.FindAllSubmatch(documentation, -1) {
		documentedIDs[string(match[1])]++
	}
	for id, count := range sourceIDs {
		if count != 1 || documentedIDs[id] != 1 {
			t.Errorf("%s: source occurrences=%d registry entries=%d, want exactly one of each", id, count, documentedIDs[id])
		}
	}
	for id, count := range documentedIDs {
		if count != 1 || sourceIDs[id] != 1 {
			t.Errorf("%s: registry entries=%d source occurrences=%d, want exactly one of each", id, count, sourceIDs[id])
		}
	}
}

// TestClientPersistenceContract guards the source-level stateless-client boundary.
func TestClientPersistenceContract(t *testing.T) {
	root := repositoryRoot(t)
	forbidden := []string{"os.WriteFile(", "os.Create(", "os.OpenFile(", "os.Rename(", "os.Mkdir(", "os.MkdirAll(", "os.Remove(", "os.Chmod("}
	err := filepath.WalkDir(filepath.Join(root, "internal", "agent"), func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		// vnc_auth owns only an ephemeral AF_UNIX socket below /run/neodse-vnc-auth;
		// provision.go is the separately reviewed durable configuration boundary.
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") ||
			filepath.Base(path) == "provision.go" || filepath.Base(path) == "vnc_auth.go" {
			return nil
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, operation := range forbidden {
			// The serial boundary opens an existing tty without creating or
			// truncating files, and rejects non-ttys before exchanging data.
			if filepath.Base(path) == "serial_linux.go" && operation == "os.OpenFile(" {
				for _, flag := range []string{"os.O_CREATE", "os.O_TRUNC", "os.O_APPEND"} {
					if strings.Contains(string(source), flag) {
						t.Errorf("serial device open must not use persistence flag %s", flag)
					}
				}
				continue
			}
			if strings.Contains(string(source), operation) {
				relative, _ := filepath.Rel(root, path)
				t.Errorf("%s: runtime client persistence operation %s is forbidden", relative, operation)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	requireFileText(t, root, "ui/webview.c", "webkit_network_session_new_ephemeral()")
	for _, value := range []string{
		"Environment=XDG_CACHE_HOME=/run/neodse-ui/cache",
		"Environment=XDG_CONFIG_HOME=/run/neodse-ui/config",
		"Environment=XDG_DATA_HOME=/run/neodse-ui/data",
		"ReadWritePaths=/run/neodse",
	} {
		requireFileText(t, root, "systemd/neodse-ui.service", value)
	}
	for _, value := range []string{
		"gtk_widget_set_can_target(renderer_state()->notification_banner, FALSE)",
		"gtk_widget_set_can_target(renderer_state()->friendly_name, FALSE)",
	} {
		requireFileText(t, root, "ui/overlays.c", value)
	}
	requireFileText(t, root, "ui/webview.c", "gtk_widget_set_focusable(GTK_WIDGET(view), TRUE)")
	requireFileText(t, root, "ui/playlist.c", "gtk_widget_grab_focus(view)")
}

// TestControllerPersistenceContract keeps SQL ownership inside the concrete store package.
func TestControllerPersistenceContract(t *testing.T) {
	root := repositoryRoot(t)
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			usesSQL := strings.Contains(string(source), `"database/sql"`) || strings.Contains(string(source), `"github.com/ncruces/go-sqlite3`)
			storeRoot := filepath.Join(root, "internal", "store") + string(filepath.Separator)
			if usesSQL && !strings.HasPrefix(path, storeRoot) {
				relative, _ := filepath.Rel(root, path)
				t.Errorf("%s: durable SQL access must be owned by internal/store", relative)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", directory, err)
		}
	}
}

// TestControllerUnitProtectsDatabaseKey keeps the unlock socket directory and the
// memory protections for the unsealed database key in the controller unit.
func TestControllerUnitProtectsDatabaseKey(t *testing.T) {
	root := repositoryRoot(t)
	requireFileText(t, root, "internal/server/unlock.go", `"/run/neodse-server/unlock.sock"`)
	for _, marker := range []string{
		"RuntimeDirectory=neodse-server", "RuntimeDirectoryMode=0700", "MemorySwapMax=0", "LimitCORE=0",
	} {
		requireFileText(t, root, "systemd/neodse-server.service", marker)
	}
}

// TestAutomationFilesParseAndUseCurrentRunner verifies YAML syntax and the supported runner baseline.
func TestAutomationFilesParseAndUseCurrentRunner(t *testing.T) {
	root := repositoryRoot(t)
	paths := []string{filepath.Join(root, ".github", "dependabot.yml")}
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	paths = append(paths, workflows...)
	for _, path := range paths {
		source, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var document any
		if err := yaml.Unmarshal(source, &document); err != nil {
			relative, _ := filepath.Rel(root, path)
			t.Errorf("%s: invalid YAML: %v", relative, err)
		}
		if strings.Contains(path, filepath.Join(".github", "workflows")) {
			text := string(source)
			relative, _ := filepath.Rel(root, path)
			for _, unsupported := range []string{"ubuntu-latest", "ubuntu-24.04"} {
				if strings.Contains(text, unsupported) {
					t.Errorf("%s: unsupported runner label %q", relative, unsupported)
				}
			}
			if !strings.Contains(text, "ubuntu-26.04") {
				t.Errorf("%s: Ubuntu 26.04 runner baseline is missing", relative)
			}
		}
	}
}

// TestProxyLoggingPackagingContract keeps request summaries on the standard service logger.
func TestProxyLoggingPackagingContract(t *testing.T) {
	root := repositoryRoot(t)
	requireFileText(t, root, "internal/proxy/proxy.go", `p.verboseLog("proxy request", attributes...)`)
	for _, relative := range []string{
		"internal/proxy/proxy.go", "internal/proxy/app.go", "internal/proxy/handler.go",
		"systemd/neodse-proxy.service", "selinux/neodse.te", "selinux/neodse.fc",
		"packaging/nfpm-server-deb.yaml", "packaging/nfpm-server-rpm.yaml", "scripts/postinstall-server.sh",
	} {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		text := string(source)
		for _, forbidden := range []string{`"log/syslog"`, "/dev/log", "rsyslog", "logrotate"} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s: project-managed proxy log dependency %q", relative, forbidden)
			}
		}
	}
}

// TestSELinuxRuntimeContract keeps confined service access aligned with accepted configuration.
func TestSELinuxRuntimeContract(t *testing.T) {
	root := repositoryRoot(t)
	for _, marker := range []string{
		`gen_context(system_u:object_r:neodse_server_exec_t,s0)`,
		`gen_context(system_u:object_r:neodse_transport_exec_t,s0)`,
		`gen_context(system_u:object_r:neodse_proxy_exec_t,s0)`,
		`/etc/neodse(/.*)?`,
		`/var/lib/neodse(/.*)?`,
		`/run/neodse-server(/.*)?`,
	} {
		requireFileText(t, root, "selinux/neodse.fc", marker)
	}
	for _, marker := range []string{
		"corenet_tcp_bind_all_unreserved_ports(neodse_server_t)",
		"allow neodse_server_t transproxy_port_t:tcp_socket name_connect;",
		"manage_files_pattern(neodse_server_t, neodse_server_var_lib_t, neodse_server_var_lib_t)",
		"manage_sock_files_pattern(neodse_server_t, neodse_server_runtime_t, neodse_server_runtime_t)",
		"allow unconfined_t neodse_server_t:unix_stream_socket connectto;",
		"corenet_tcp_bind_all_unreserved_ports(neodse_transport_t)",
		"corenet_tcp_bind_all_unreserved_ports(neodse_proxy_t)",
		"corenet_tcp_connect_all_ports(neodse_proxy_t)",
		"read_files_pattern(neodse_proxy_t, cert_t, cert_t)",
		"sysnet_read_config(neodse_proxy_t)",
		// The Go runtime reads the cgroup CPU limit at startup.
		"fs_read_cgroup_files(neodse_server_t)",
		"fs_read_cgroup_files(neodse_transport_t)",
		"fs_read_cgroup_files(neodse_proxy_t)",
	} {
		requireFileText(t, root, "selinux/neodse.te", marker)
	}
	// The controller serves TLS but never verifies peers against system roots.
	source, err := os.ReadFile(filepath.Join(root, "selinux/neodse.te"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(source), "neodse_server_t, cert_t") || strings.Contains(string(source), "neodse_server_t cert_t") {
		t.Error("selinux/neodse.te: the controller must not read the system certificate store")
	}
}

// TestReleaseWorkflowPreservesTargetAndPublicationContract guards the supported package matrix and publication gates.
func TestReleaseWorkflowPreservesTargetAndPublicationContract(t *testing.T) {
	root := repositoryRoot(t)
	source, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, required := range []string{
		"needs: [release-policy, quality-gate, codeql]", "needs: [release-policy, packages, quality-gate, codeql]",
		"uses: ./.github/workflows/codeql.yml", "needs.codeql.result == 'success'",
		`git rev-parse --verify "${GITHUB_REF}^{commit}"`,
		`release_branch=dev`, `refs/remotes/origin/${release_branch}^{commit}`, `.verification.verified == true`, "bash scripts/publish-release.sh",
		"pattern: package-*", "spdx-json=", "--source-name", "--fail-on high",
		"--output json", ".vulnerabilities.json", "actions/attest-build-provenance@",
		"SHA256SUMS",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("release workflow is missing %q", required)
		}
	}
	for _, forbidden := range []string{"actions/attest@", "sbom-path:", "dir:release-sbom"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("release workflow must not publish SBOM attestations: %q", forbidden)
		}
	}
	requireFileText(t, root, ".github/workflows/codeql.yml", "workflow_call:")
	requireFileText(t, root, ".github/workflows/codeql.yml", "if: github.event.repository.private == false")
}

// TestReleaseScannerVersionsArePinned requires source-built, verified scanners
// from one pinned graph in the package job.
func TestReleaseScannerVersionsArePinned(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Uses string `yaml:"uses"`
				Run  string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(source, &workflow); err != nil {
		t.Fatal(err)
	}
	for _, job := range []string{"packages"} {
		verified := false
		generated := false
		details := workflow.Jobs[job]
		for _, step := range details.Steps {
			if strings.HasPrefix(step.Uses, "anchore/") {
				t.Errorf("%s: downloaded scanner bypasses the source/binary vulnerability gate", job)
			}
			if strings.Contains(step.Run, "make verify-sbom-tools") {
				verified = true
			}
			if strings.Contains(step.Run, "build/tools/syft scan") {
				generated = true
				if !verified {
					t.Errorf("%s: SBOM generation precedes scanner verification", job)
				}
			}
		}
		if !verified || !generated {
			t.Errorf("%s: source-built scanner verification and SBOM generation are required", job)
		}
	}
	module, err := os.ReadFile(filepath.Join(repositoryRoot(t), "tools", "sbom", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"syft", "grype"} {
		pin := regexp.MustCompile(`(?m)^\s*github.com/anchore/` + tool + ` v[0-9]+\.[0-9]+\.[0-9]+(?: // indirect)?$`)
		if len(pin.FindAll(module, -1)) != 1 {
			t.Errorf("%s requires one explicit stable module version", tool)
		}
	}
}

// TestPackagedServicesAreIPv4Only prevents configuration and sandbox policy from diverging.
func TestPackagedServicesAreIPv4Only(t *testing.T) {
	root := repositoryRoot(t)
	services, err := filepath.Glob(filepath.Join(root, "systemd", "*.service"))
	if err != nil {
		t.Fatal(err)
	}
	if len(services) == 0 {
		t.Fatal("no packaged systemd services found")
	}
	for _, service := range services {
		source, readErr := os.ReadFile(service)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if strings.Contains(string(source), "AF_INET6") {
			t.Errorf("%s: IPv6 address family is enabled", filepath.Base(service))
		}
	}
	for relative, marker := range map[string]string{
		"internal/agent/app.go":        `DialContext(ctx, "tcp4", address)`,
		"internal/proxy/network.go":    `LookupNetIP(ctx, "ip4", host)`,
		"internal/server/transport.go": `DialContext(ctx, "tcp4", address)`,
	} {
		requireFileText(t, root, relative, marker)
	}
}

// TestWestonVNCProfileKeepsRemoteAccessExplicit guards the loopback-only,
// authenticated, display-only capture surface.
func TestWestonVNCProfileKeepsRemoteAccessExplicit(t *testing.T) {
	root := repositoryRoot(t)
	for _, marker := range []string{
		"--backend=drm,vnc", "--port=5900", "--vnc-tls-key=%d/vnc.key",
		"--vnc-tls-cert=/var/lib/neodse-vnc/server.crt", "LoadCredential=vnc.key:/var/lib/neodse-vnc/server.key",
		"--address=127.0.0.1", "--config=/run/neodse/weston.ini", "RuntimeDirectoryMode=0750",
		"RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK",
	} {
		requireFileText(t, root, "systemd/neodse-weston.service", marker)
	}
	service, err := os.ReadFile(filepath.Join(root, "systemd/neodse-weston.service"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(service), "--disable-transport-layer-security") {
		t.Fatal("Weston must require transport encryption")
	}
	manifest, err := os.ReadFile(filepath.Join(root, "packaging/nfpm-client.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(manifest), "build/neodse-vnc-auth") {
		t.Fatal("client package must ship the pam_exec helper")
	}
	if !strings.Contains(string(manifest), "scripts/neodse-drm-connected.sh") {
		t.Fatal("client package must ship the DRM connection probe")
	}
	if !strings.Contains(string(manifest), "dst: /usr/lib/udev/rules.d/71-neodse-display-hotplug.rules") {
		t.Fatal("client package must start the compositor when a display is connected after boot")
	}
	for _, marker := range []string{
		`ACTION=="change", SUBSYSTEM=="drm"`, `ENV{HOTPLUG}=="1"`,
		"systemctl --quiet is-enabled neodse-weston.service", "systemctl --no-block start neodse-weston.service",
	} {
		requireFileText(t, root, "udev/71-neodse-display-hotplug.rules", marker)
	}
	for _, marker := range []string{
		"pam_exec.so quiet expose_authtok /usr/lib/neodse/neodse-vnc-auth",
		"account required pam_exec.so quiet /usr/lib/neodse/neodse-vnc-auth",
	} {
		requireFileText(t, root, "pam/weston-remote-access", marker)
	}
	for _, marker := range []string{
		"printf 'name=%s\\n' 'vnc'", "printf 'mirror-of=%s\\n'", "printf 'resizeable=%s\\n' 'false'",
	} {
		requireFileText(t, root, "scripts/neodse-weston-config.sh", marker)
	}
	for _, marker := range []string{"127.0.0.1:5900", "stream is one-way"} {
		requireFileText(t, root, "docs/CONFIGURATION.md", marker)
	}
	for _, marker := range []string{
		"Type=notify", "NotifyAccess=main", "--modules=systemd-notify.so",
		"PAMName=login", "ExecStart=/usr/bin/weston", "--socket=wayland-0",
		"ReadWritePaths=/run/user", "Environment=WAYLAND_DISPLAY=wayland-0",
		"Environment=XDG_SESSION_CLASS=user", "Environment=XDG_SESSION_TYPE=wayland",
		"NoNewPrivileges=true", "LimitCORE=0", "Restart=on-failure", "RestartSec=15s",
		"Wants=neodse-ui.service", "ExecCondition=/usr/lib/neodse/neodse-drm-connected",
	} {
		requireFileText(t, root, "systemd/neodse-weston.service", marker)
	}
	for _, marker := range []string{
		"PartOf=neodse-weston.service", "ReadWritePaths=/run/user", "Environment=WAYLAND_DISPLAY=wayland-0",
		"ExecStartPre=/usr/lib/neodse/neodse-session-environment", "ExecStart=/usr/bin/neodse-ui",
		"RuntimeDirectory=neodse-ui", "RuntimeDirectoryMode=0700",
		"EnvironmentFile=-/run/neodse-ui/session.env", "Environment=XDG_SESSION_TYPE=wayland",
		"ExecCondition=/usr/bin/systemctl is-active --quiet neodse-weston.service", "RestartSec=15s",
	} {
		requireFileText(t, root, "systemd/neodse-ui.service", marker)
	}
	for _, marker := range []string{"d /run/neodse 0750 neodse-ui neodse-ipc -", "d /run/neodse-vnc-auth 0750 neodse-agent neodse-ipc -"} {
		requireFileText(t, root, "config/neodse.conf", marker)
	}
	agentUnit, err := os.ReadFile(filepath.Join(root, "systemd/neodse-agent.service"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(agentUnit), "Wants=neodse-ui.service") || strings.Contains(string(agentUnit), "neodse-ui.service\n") {
		t.Fatal("headless agent startup must not request the UI")
	}
	unit, err := os.ReadFile(filepath.Join(root, "systemd/neodse-weston.service"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unit), "ExecStartPost=") {
		t.Fatal("post-start commands must not open a second PAM session on Weston's virtual terminal")
	}
	rendererUnit, err := os.ReadFile(filepath.Join(root, "systemd/neodse-ui.service"))
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{string(unit), string(rendererUnit)} {
		for _, forbidden := range []string{"Environment=XDG_RUNTIME_DIR=", "/run/neodse/wayland-0", "/usr/bin/env XDG_RUNTIME_DIR="} {
			if strings.Contains(service, forbidden) {
				t.Fatalf("display services must reuse the PAM runtime directory, found %q", forbidden)
			}
		}
	}
	for _, forbidden := range []string{"PAMName=", "TTYPath="} {
		if strings.Contains(string(rendererUnit), forbidden) {
			t.Fatalf("renderer must reuse the compositor session without %s", forbidden)
		}
	}
	if strings.Contains(string(unit), "Upholds=neodse-ui.service") {
		t.Fatal("Upholds starts the UI without honoring its retry delay")
	}
	if strings.Contains(string(unit), "Restart=always") {
		t.Fatal("Restart=always retries a skipped ExecCondition")
	}
}

// TestRendererServicesHaveFiniteResourceLimits guards hostile-content containment.
func TestRendererServicesHaveFiniteResourceLimits(t *testing.T) {
	root := repositoryRoot(t)
	for relative, markers := range map[string][]string{
		"systemd/neodse-ui.service": {
			"MemoryHigh=1536M", "MemoryMax=2G", "TasksMax=384", "OOMPolicy=stop",
			"RuntimeDirectoryPreserve=yes",
			"MemoryDenyWriteExecute= and RestrictNamespaces= must remain unset",
			"and RestrictSUIDSGID= must remain unset",
			"DevicePolicy=closed", "DeviceAllow=char-drm rw",
		},
		"systemd/neodse-weston.service": {
			"MemoryHigh=256M", "MemoryMax=384M", "TasksMax=128", "OOMPolicy=stop",
			"RuntimeDirectoryPreserve=yes",
			"MemoryDenyWriteExecute= must remain unset",
		},
	} {
		for _, marker := range markers {
			requireFileText(t, root, relative, marker)
		}
	}
	for relative, forbidden := range map[string][]string{
		// Each of these breaks JavaScriptCore or WebKit's bubblewrap sandbox,
		// or hides the GPU from GTK and WebKit.
		"systemd/neodse-ui.service": {
			"MemoryDenyWriteExecute=", "RestrictNamespaces=", "ProtectHostname=",
			"ProtectKernelTunables=", "ProtectKernelLogs=", "ProcSubset=", "RestrictSUIDSGID=",
			"PrivateDevices=",
		},
		"systemd/neodse-weston.service": {"MemoryDenyWriteExecute="},
	} {
		source, err := os.ReadFile(filepath.Join(root, relative))
		if err != nil {
			t.Fatal(err)
		}
		for line := range strings.SplitSeq(string(source), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "#") {
				continue
			}
			for _, directive := range forbidden {
				if strings.HasPrefix(trimmed, directive) {
					t.Errorf("%s: incompatible directive %q is enabled", relative, directive)
				}
			}
		}
	}
}

// requireFileText reports when a security contract marker disappears from a file.
func requireFileText(t *testing.T, root, relative, required string) {
	t.Helper()
	source, err := os.ReadFile(filepath.Join(root, relative))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(source), required) {
		t.Errorf("%s: required security contract %q is missing", relative, required)
	}
}

// repositoryRoot resolves the checkout without relying on the test process working directory.
func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate quality test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
}

// checkGoFileDocumentation validates one parsed source file and reports every local violation.
func checkGoFileDocumentation(t *testing.T, root, path string) {
	t.Helper()
	source, err := os.ReadFile(path)
	if err != nil {
		t.Errorf("read %s: %v", path, err)
		return
	}
	relative, _ := filepath.Rel(root, path)
	if !hasCanonicalHeader(source) {
		t.Errorf("%s: header must contain purpose, copyright, SPDX, and project lines in canonical order", relative)
	}
}

// hasCanonicalHeader verifies the shared metadata block after any Go build constraint.
func hasCanonicalHeader(source []byte) bool {
	text := string(source)
	if strings.HasPrefix(text, "//go:build ") {
		_, remainder, found := strings.Cut(text, "\n\n")
		if !found {
			return false
		}
		text = remainder
	}
	lines := strings.SplitN(text, "\n", 6)
	return len(lines) == 6 &&
		strings.HasPrefix(lines[0], "// File purpose: ") &&
		strings.TrimSpace(strings.TrimPrefix(lines[0], "// File purpose: ")) != "" &&
		lines[1] == "// Copyright (c) 2026 RealisLux" &&
		lines[2] == "// SPDX-License-Identifier: MIT" &&
		lines[3] == "// Project: https://github.com/RealisLux/NeoDSE" &&
		lines[4] == ""
}

// hasCanonicalCHeader verifies the shared C block header and its multiline purpose.
func hasCanonicalCHeader(source []byte) bool {
	lines := strings.SplitN(string(source), "\n", 16)
	if len(lines) < 8 || lines[0] != "/*" ||
		!strings.HasPrefix(lines[1], " * File purpose: ") ||
		strings.TrimSpace(strings.TrimPrefix(lines[1], " * File purpose: ")) == "" {
		return false
	}
	copyrightIndex := -1
	for index := 2; index < len(lines); index++ {
		if lines[index] == " * Copyright (c) 2026 RealisLux" {
			copyrightIndex = index
			break
		}
		if !strings.HasPrefix(lines[index], " * ") || strings.TrimSpace(lines[index]) == "*" {
			return false
		}
	}
	return copyrightIndex >= 2 && copyrightIndex+4 < len(lines) &&
		lines[copyrightIndex+1] == " * SPDX-License-Identifier: MIT" &&
		lines[copyrightIndex+2] == " * Project: https://github.com/RealisLux/NeoDSE" &&
		lines[copyrightIndex+3] == " */" &&
		lines[copyrightIndex+4] == ""
}

// TestClientPreinstallOptionalGroups verifies missing hardware groups are optional
// while failures to add an existing group still abort installation.
func TestClientPreinstallOptionalGroups(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for package script checks")
	}
	for _, scenario := range []string{"missing-render", "missing-all", "usermod-fails"} {
		t.Run(scenario, func(t *testing.T) {
			cmd := exec.Command("bash", "-c", `
getent() {
    case "$1:$2" in
        group:neodse-ipc) printf 'neodse-ipc:x:901:\n' ;;
        group:neodse-agent) printf 'neodse-agent:x:902:\n' ;;
        passwd:neodse-agent) printf 'neodse-agent:x:902:902::/nonexistent:/usr/sbin/nologin\n' ;;
        passwd:neodse-ui) printf 'neodse-ui:x:901:901::/nonexistent:/usr/sbin/nologin\n' ;;
        group:render) return 2 ;;
        group:video|group:audio|group:dialout)
            [[ "$SCENARIO" != missing-all ]] || return 2
            printf '%s:x:44:\n' "$2" ;;
        *) return 2 ;;
    esac
}
id() {
    case "$2" in
        neodse-agent) printf 'neodse-agent\n' ;;
        neodse-ui) printf 'neodse-ipc\n' ;;
        *) return 1 ;;
    esac
}
# Account creation must never reach the host during this fixture.
dpkg-divert() { return 0; }
groupadd() { return 99; }
useradd() { return 99; }
usermod() { [[ "$SCENARIO" != usermod-fails || "$2" != video ]]; }
source "$1"
`, "preinstall-test", filepath.Join(repositoryRoot(t), "scripts", "preinstall-agent.sh"))
			cmd.Env = append(os.Environ(), "SCENARIO="+scenario)
			output, err := cmd.CombinedOutput()
			if scenario == "usermod-fails" {
				if err == nil {
					t.Fatal("installation ignored failed group membership update")
				}
			} else if err != nil {
				t.Fatalf("optional groups prevented installation: %v\n%s", err, output)
			}
		})
	}
}

// TestClientPostinstallRestartsRunningAgent checks the package lifecycle without touching host services.
func TestClientPostinstallRestartsRunningAgent(t *testing.T) {
	source, err := os.ReadFile(filepath.Join(repositoryRoot(t), "scripts", "postinstall-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	setup := filepath.Join(directory, "tls-setup")
	if err := os.WriteFile(setup, []byte("#!/bin/sh\n[ \"$SCENARIO\" != tls-setup-fails ]\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(directory, "postinstall.sh")
	// Isolate host detection and identity provisioning; service commands execute as shipped.
	if err := os.WriteFile(script, []byte(strings.NewReplacer("/run/systemd/system", directory, "/usr/lib/neodse/neodse-vnc-tls", setup).Replace(string(source))), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"running", "stopped", "restart-fails", "tls-setup-fails"} {
		t.Run(scenario, func(t *testing.T) {
			command := exec.Command("bash", "-c", `
visudo() { return 0; }
install() { return 0; }
systemd-tmpfiles() { return 0; }
systemctl() {
    printf 'systemctl %s\n' "$*"
    case "$1" in
        --no-block) [[ "$SCENARIO" != restart-fails ]] ;;
        try-restart)
            [[ "$SCENARIO" != running ]] || printf 'agent replaced\n'
            ;;
        disable|daemon-reload|enable) ;;
        *) return 99 ;;
    esac
}
source "$1"
`, "postinstall-test", script)
			command.Env = append(os.Environ(), "SCENARIO="+scenario)
			output, err := command.CombinedOutput()
			if scenario == "tls-setup-fails" {
				if err == nil || strings.Contains(string(output), "systemctl") {
					t.Fatalf("TLS setup failure was ignored: %v\n%s", err, output)
				}
				return
			}
			if scenario == "restart-fails" {
				if err == nil || strings.Contains(string(output), "try-restart") {
					t.Fatalf("renderer restart failure was ignored: %v\n%s", err, output)
				}
				return
			}
			if err != nil {
				t.Fatalf("postinstall: %v\n%s", err, output)
			}
			want := "systemctl --no-block restart neodse-weston.service\nsystemctl try-restart neodse-agent.service\n"
			if !strings.Contains(string(output), want) {
				t.Fatalf("agent was not conditionally restarted after renderer: %s", output)
			}
			if strings.Contains(string(output), "agent replaced") != (scenario == "running") {
				t.Fatalf("stopped-agent state was not preserved: %s", output)
			}
		})
	}
}

// TestRPMStagingExtractsBuiltPackage exercises real nFPM RPMs and rejects corrupt payloads.
func TestRPMStagingExtractsBuiltPackage(t *testing.T) {
	if _, err := exec.LookPath("bsdtar"); err != nil {
		t.Skip("bsdtar is required for RPM staging checks")
	}
	root := repositoryRoot(t)
	nfpm := filepath.Join(root, "build", "tools", "nfpm")
	if _, err := os.Stat(nfpm); err != nil {
		t.Skip("build the pinned nFPM with make security-tools for RPM staging checks")
	}
	dir := t.TempDir()
	payload := []byte("package content\n")
	if err := os.WriteFile(filepath.Join(dir, "payload"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	config := "name: staging-test\narch: amd64\nplatform: linux\nversion: 1.0.0\ncontents:\n  - src: payload\n    dst: /usr/share/staging-test/payload\n"
	if err := os.WriteFile(filepath.Join(dir, "nfpm.yaml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(dir, "fixture.rpm")
	build := exec.Command(nfpm, "package", "--config", "nfpm.yaml", "--packager", "rpm", "--target", pkg)
	build.Dir = dir
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v\n%s", err, output)
	}
	data, err := os.ReadFile(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "truncated", "corrupt"} {
		t.Run(mode, func(t *testing.T) {
			input := filepath.Join(dir, mode+".rpm")
			content := data
			if mode == "truncated" {
				content = data[:len(data)/2]
			}
			if mode == "corrupt" {
				content = []byte("invalid archive")
			}
			if err := os.WriteFile(input, content, 0o600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(dir, mode)
			cmd := exec.Command("bash", filepath.Join(root, "scripts", "stage-package-sbom.sh"), destination, input)
			output, err := cmd.CombinedOutput()
			if mode != "valid" {
				if err == nil {
					t.Fatal("invalid RPM extraction succeeded")
				}
				return
			}
			if err != nil {
				t.Fatalf("RPM staging failed: %v\n%s", err, output)
			}
			extracted, err := os.ReadFile(filepath.Join(destination, "valid.rpm", "payload", "usr", "share", "staging-test", "payload"))
			if err != nil || string(extracted) != string(payload) {
				t.Fatalf("incorrect payload: %q, %v", extracted, err)
			}
			copied, err := os.ReadFile(filepath.Join(destination, "valid.rpm", "valid.rpm"))
			if err != nil || string(copied) != string(data) {
				t.Fatal("staging changed the RPM archive")
			}
		})
	}
}

// TestClientFilesArePackagedAsConfiguration checks the real DEB metadata that
// preserves operator settings and local privilege restrictions during upgrades.
func TestClientFilesArePackagedAsConfiguration(t *testing.T) {
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb is required for client configuration checks")
	}
	root := repositoryRoot(t)
	nfpm := filepath.Join(root, "build", "tools", "nfpm")
	if _, err := os.Stat(nfpm); err != nil {
		t.Skip("build the pinned nFPM with make security-tools for client configuration checks")
	}
	source, err := os.ReadFile(filepath.Join(root, "packaging", "nfpm-client.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Contents []map[string]any `yaml:"contents"`
	}
	if err := yaml.Unmarshal(source, &manifest); err != nil {
		t.Fatal(err)
	}
	for _, settings := range []struct {
		path string
		mode os.FileMode
	}{
		{"/etc/sudoers.d/neodse-agent", 0o440},
		{"/etc/neodse/display.env", 0o600},
	} {
		t.Run(settings.path, func(t *testing.T) {
			var entry map[string]any
			for _, candidate := range manifest.Contents {
				if candidate["dst"] == settings.path {
					entry = candidate
				}
			}
			if entry == nil {
				t.Fatalf("client package has no configuration at %s", settings.path)
			}
			entry["src"] = filepath.Join(root, entry["src"].(string))
			fixture := map[string]any{
				"name": "neodse-config-test", "arch": "amd64", "platform": "linux", "version": "1.0.0",
				"maintainer": "NeoDSE maintainers", "contents": []map[string]any{entry},
			}
			data, err := yaml.Marshal(fixture)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			config := filepath.Join(dir, "nfpm.yaml")
			if err := os.WriteFile(config, data, 0o600); err != nil {
				t.Fatal(err)
			}
			pkg := filepath.Join(dir, "config.deb")
			build := exec.Command(nfpm, "package", "--config", config, "--packager", "deb", "--target", pkg)
			if output, err := build.CombinedOutput(); err != nil {
				t.Fatalf("build configuration package: %v\n%s", err, output)
			}
			control := filepath.Join(dir, "control")
			if output, err := exec.Command("dpkg-deb", "--control", pkg, control).CombinedOutput(); err != nil {
				t.Fatalf("extract configuration metadata: %v\n%s", err, output)
			}
			conffiles, err := os.ReadFile(filepath.Join(control, "conffiles"))
			if err != nil || strings.TrimSpace(string(conffiles)) != settings.path {
				t.Fatalf("configuration must be preserved on upgrade: %q, %v", conffiles, err)
			}
			payload := filepath.Join(dir, "payload")
			if output, err := exec.Command("dpkg-deb", "--extract", pkg, payload).CombinedOutput(); err != nil {
				t.Fatalf("extract configuration payload: %v\n%s", err, output)
			}
			info, err := os.Stat(filepath.Join(payload, settings.path))
			if err != nil || info.Mode().Perm() != settings.mode {
				t.Fatalf("configuration must have mode %04o: %v, %v", settings.mode, info, err)
			}
		})
	}
}
