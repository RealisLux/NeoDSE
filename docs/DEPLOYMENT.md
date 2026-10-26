# Deployment

Install the server package on the controller and a client package on each display.
For an existing installation, follow [upgrades and restoration](OPERATIONS.md#upgrades).

Follow these phases in order:

1. [Install](#install) the verified packages on the controller and displays.
2. [Bootstrap](#bootstrap) the controller once, then each display. This creates
   local configuration and keys; it does not enroll a display.
3. [Authorize content networks](#authorize-content-networks) on the controller.
4. [Provision displays](#provision-displays) by exchanging enrollment blocks
   between each display and the controller.
5. [Verify enrollment](#verify-enrollment) before using the dashboard or API.

## Hardware and hosting

Display clients can use x86-64 PCs/mini PCs or ARM64 boards such as Raspberry Pi 5,
provided they meet the requirements below. Client packages target Debian 13 or
Ubuntu 26.04 on `amd64` or `arm64`; these targets do not certify individual board
or GPU models.

Controllers can run headless on a physical server, VM or cloud host with WireGuard
support. Packages cover the same targets, plus Enterprise Linux 9/10 on `amd64`.
See the [package matrix](#packages) below.

Use a dedicated display host with a connected DRM/KMS output and graphics
drivers that work with the distribution's Weston DRM/VNC backends and
GTK4/WebKitGTK renderer. Check the chosen board, graphics driver and screen
before deployment. See
[display configuration](CONFIGURATION.md#weston-drm-and-vnc-outputs).

Size small deployments around the figures below; they are starting points, not
capacity guarantees. Larger fleets, live views, longer event retention and heavy
proxy use need more resources. Use SSD-backed storage for the controller.

| Host | Minimum starting point | Recommended starting point |
| --- | --- | --- |
| Display | 2 CPU, 4 GB RAM, 16 GB reliable storage | 4 CPU, 8 GB RAM, 32 GB SSD/high-endurance storage |
| Controller | 2 CPU/vCPU, 2 GB RAM, 16 GB SSD | 4 CPU/vCPU, 4 GB RAM, 32 GB SSD |

Optional features need corresponding hardware:

- **Sound:** speakers and an ALSA output accessible to `neodse-agent`.
- **Screen power and audio control:** a Linux HDMI-CEC adapter (`/dev/cecN`),
  compatible screen and cable, with CEC enabled on the screen.
- **Serial actions:** a device implementing the [NeoDSE AT protocol](ARCHITECTURE.md#serial-peripheral-protocol),
  connected to the configured serial port.

Prefer wired Ethernet. Clients need access to the controller's WireGuard
UDP endpoint; they do not need public addresses. A cloud controller needs a
stable, reachable IPv4 address or DNS name and provider firewall rules allowing
that endpoint. Exposing it to the Internet adds risk that needs host and network
protection beyond this guide.

Protect controllers and displays alike: isolate them from unrelated systems and
permit only the required traffic, as described in
[network isolation](FIREWALL.md#network-isolation).

### Time synchronization

Synchronize the clock of the controller and every display, for example with
`systemd-timesyncd` or chrony, before enrollment. The authenticated handshake
fails when the display and controller clocks differ by more than two minutes, so
a display with a wrong clock cannot connect. Commands expire five minutes after
they are issued, and synchronized playlists use wall-clock time. On isolated
networks, provide an internal NTP server that every host can reach. A board
without a battery-backed real-time clock starts with a stale clock after power
loss and connects only once NTP has corrected it.

## Packages

Download the matching package, its `.sha256` file and `SHA256SUMS` from a tagged
[GitHub Release](https://github.com/RealisLux/NeoDSE/releases), or
[build natively](DEVELOPMENT.md#build-packages). The manifest covers packages and
their checksum files.

| Target | Package stem |
| --- | --- |
| Debian 13 client/server | `NeoDSE-{client,server}_<version>_debian13_{amd64,arm64}` |
| Ubuntu 26.04 client/server | `NeoDSE-{client,server}_<version>_ubuntu26.04_{amd64,arm64}` |
| EL9/EL10 server | `NeoDSE-server_<version>_el{9,10}_amd64` |

Example download; replace the version and package target:

```bash
gh release download v1.0.0 --repo RealisLux/NeoDSE \
  --pattern 'NeoDSE-server_1.0.0_ubuntu26.04_amd64.deb*' \
  --pattern SHA256SUMS --dir artifacts/server
cd artifacts/server
package=NeoDSE-server_1.0.0_ubuntu26.04_amd64.deb
for suffix in '' .sha256; do
  test -s "$package$suffix" || { echo "Missing $package$suffix" >&2; exit 1; }
done
sha256sum --check SHA256SUMS --ignore-missing
dpkg-deb --field NeoDSE-server_1.0.0_ubuntu26.04_amd64.deb Package Version Architecture
gh attestation verify NeoDSE-server_1.0.0_ubuntu26.04_amd64.deb --repo RealisLux/NeoDSE
```

Use a new download directory. The presence check prevents `--ignore-missing`
from hiding missing files when verifying one target from the full manifest.

Obtain checksums through a trusted release channel. Public GitHub releases also
provide build provenance attestations; private releases and local builds do not.
For RPM metadata, use `rpm -qp --queryformat
'%{NAME} %{VERSION}-%{RELEASE} %{ARCH}\n' PACKAGE.rpm`.

Local builds write packages and checksums to `dist/`. CI retains SBOMs and
vulnerability reports as artifacts.

## Install

Initial installation is supported only on clean controller and display hosts: a
freshly installed supported operating system, booted with systemd, with no
unrelated workloads and no earlier NeoDSE configuration or data. Packages install
the service manager, WireGuard routing tools and CA certificates, but do not
switch an existing host's init system.

Match the package to the distribution, major version and architecture. Before
installing, enable the distribution's security and updates repositories, apply
current updates and the required host and network security settings. Keep those
updates enabled: clients use the distribution's WebKitGTK runtime, which
installing NeoDSE alone may not update. After updates, restart the display
services (or reboot if required) and repeat the display/proxy checks.

On the controller, disable swap or ensure it is encrypted before bootstrap and
maintenance commands. Those commands handle database secrets outside the server
service's swap limit. Keep that host setting in place after reboot.

On Debian 13 or Ubuntu 26.04:

```bash
# Controller; substitute the verified package filename
sudo apt update
sudo apt install ./NeoDSE-server_1.0.0_debian13_amd64.deb
# Each display
sudo apt update
sudo apt install ./NeoDSE-client_1.0.0_debian13_amd64.deb
```

On an amd64 EL9/EL10 controller, use its matching server RPM:

```bash
sudo dnf install ./NeoDSE-server_1.0.0_el9_amd64.rpm
rpm -q neodse-server
sudo semodule -l | grep '^neodse'
getenforce
```

Installation creates service accounts and systemd units; RPMs also install the
SELinux policy, which erasing the RPM removes again. Server services stay
stopped until bootstrap. The agent starts only if `/etc/neodse/agent.yaml`
exists and connects after enrollment.

Weston and the renderer show a waiting screen when a display is connected. On a
headless host they stay stopped; the configured agent remains available. After
connecting a display, the packaged udev rule starts `neodse-weston.service` if it
is enabled; the renderer follows when Weston is ready. See
[DRM and VNC configuration](CONFIGURATION.md#weston-drm-and-vnc-outputs).

## Bootstrap

Bootstrap creates local configuration and keys. It does not enroll displays.

### Controller

Choose a nonoverlapping WireGuard subnet, a reachable endpoint and a consistent
instance name. Examples use `neodse`, `10.99.0.254/24` and
`vpn.example.net:51820`; replace them throughout.

NeoDSE uses IPv4 inside the tunnel; WireGuard's outer UDP transport can use IPv4
or IPv6. `--server-endpoint` takes an IPv4 literal or a DNS name, not an IPv6
literal. Every display must resolve that name and reach the resulting address
and UDP port.

The packaged services start after `wg-quick@neodse.service`. With another
instance name, set the matching `After=` ordering in a systemd drop-in on the
controller and each display.

```bash
sudo neodse-server bootstrap \
  --instance neodse \
  --server-address 10.99.0.254/24 \
  --server-endpoint vpn.example.net:51820 \
  --listen-port 51820
```

Bootstrap first asks twice for a new database passphrase of at least 16 bytes.
It encrypts `/var/lib/neodse/controller.db` with a random key and stores that key
only in wrapped form, sealed with the passphrase, in
`/var/lib/neodse/controller.db.keyslot`. The passphrase itself is never stored.
Keep it in a password manager or another secure place: without it, nobody can
recover the database. When standard input is not a terminal, bootstrap reads the
passphrase from its first line and asks only once.

Bootstrap generates server/transport/proxy YAML and TLS files under `/etc/neodse`,
`/etc/wireguard/neodse.conf`, the encrypted database and its keyslot. It starts
WireGuard, transport, server and proxy. Store the administrator token immediately;
it is printed once and only its hash is retained. Never copy it to a display.

The controller starts locked. Unlock it now and after every restart, as described
in [unlocking the controller](OPERATIONS.md#unlocking-the-controller):

```bash
sudo neodse-server unlock
```

Bootstrap never replaces controller state: it stops if the database, its keyslot
or any SQLite sidecar file exists, even an orphaned one. It also stops at
existing configuration, TLS or WireGuard files unless you pass `--force`, which
replaces those regular files but never symbolic links or other file types. To
start over completely, move the old state aside as described for a
[lost passphrase](OPERATIONS.md#unlocking-the-controller).

The API initially listens on `127.0.0.1:8443`, with a certificate covering
loopback. Use an [SSH tunnel](OPERATIONS.md#api-access) or follow the
[LAN access procedure](CONFIGURATION.md#lan-api-access) to change the
listener and TLS certificate. The certificate must cover the address operators
use. Changing the API port also requires updating `proxy.backend_url`.

The generated certificate is valid for three years. Plan its
[renewal](OPERATIONS.md#certificate-renewal): when it expires, displays can no
longer load web content.

Distribute the trust anchor securely, or use your organizational CA. See
[configuration](CONFIGURATION.md) for generated fields, ownership and modes.

### Controller firewall

After bootstrap creates the WireGuard interface, the administrator must apply
and verify the [firewall rules](FIREWALL.md): zone assignments, client isolation
and, if needed, restricted LAN API access. The examples use firewalld; adapt them
to the host's active firewall manager.

### Displays

Run this on each display, choosing a unique agent ID. The ID `broadcast` is
reserved for fleet API routes and cannot be enrolled:

```bash
sudo neodse-agent bootstrap --instance neodse --agent-id display-001 --friendly-name "Lobby display"
```

Use a unique ID of 1–32 letters, digits, `_` or `-`, starting with a letter or
digit. The optional friendly name is a trimmed UTF-8 label of at most 32 characters.

Set scale, rotation and appearance in `/etc/neodse/display.env`, independently
of bootstrap. See [Weston settings](CONFIGURATION.md#weston-drm-and-vnc-outputs)
and [display configuration](CONFIGURATION.md#display-configuration-file) for
values and restart commands.

Bootstrap creates agent/WireGuard configuration and enables the tunnel unit.
Continue with provisioning to obtain controller credentials and connect.

Agent bootstrap `--force` replaces its local configuration and private key.
Use it only to replace the display's identity, then enroll again. Bootstrap and
`remove-config` preserve `/etc/neodse/display.env` and do not restart Weston.

## Authorize content networks

The proxy initially denies all web-content destinations because
`proxy.authorized_networks` is empty. Before publishing a playlist, add the IPv4
networks for its pages and supporting services to `/etc/neodse/proxy.yaml` on the
controller. Keep the generated listener, backend, credentials and certificate fields.

For example, add this field inside the existing `proxy:` mapping:

```yaml
  authorized_networks:
    - 10.20.0.0/16
    - 192.168.50.0/24
```

Replace these example networks with your deployment's destination networks.
Preserve the file's `root:neodse-proxy` ownership and `0640` mode, then apply it:

```bash
sudo systemctl restart neodse-proxy
sudo systemctl status neodse-proxy --no-pager
```

Content needs both network and origin authorization: this list permits addresses;
playlist URLs and `proxy_allow` permit origins. DNS names must resolve to eligible
IPv4 addresses in an allowed network. See [proxy configuration](CONFIGURATION.md#proxy)
and [content access](ARCHITECTURE.md#content-access) for the full rules.

## Provision displays

Open a terminal on the display and one on the controller. Both must be bootstrapped
with the same instance name. Transfer the controller response through an
authenticated, confidential channel; the display keeps its private WireGuard key.

### 1. Generate the request on the display

```bash
sudo neodse-agent provision --instance neodse
```

The command prints a non-secret agent request and waits for a controller response.
Copy the request block and leave this terminal waiting.

### 2. Issue credentials on the controller

In the controller terminal, run:

```bash
sudo neodse-server provision-agent --instance neodse
```

Enter the database passphrase, then paste the generated agent request and finish
with an empty line. When piping input instead, put the passphrase on the first
line, followed by the request block. The controller allocates a tunnel address,
creates independent WireGuard/application PSKs, updates the live peer and SQLite
credential, and prints a secret response. The response points the display at
the ports of `server.transport_url` and `proxy.listen`; pass `--proxy-config` if
the proxy configuration is not at `/etc/neodse/proxy.yaml`.

Each display must have its own WireGuard key. Enrollment rejects a key belonging
to the controller or another peer.

Bootstrap, enrollment and removal commands take a per-host lock on the WireGuard
configuration; if another one is running, wait and retry. Manual edits do not
take this lock, so avoid them meanwhile. Ctrl+C cancels a command waiting for a
pasted block without applying anything.

### 3. Apply the response on the display

Paste the controller response into the waiting display terminal, then enter an
empty line. The command keeps the private key, saves peer/application configuration
and restarts WireGuard and the agent.

Paste blocks unchanged. Do not record provisioning sessions; clear scrollback,
clipboard and temporary copies of the secret response afterward. See the
[enrollment contract](ARCHITECTURE.md#enrollment) for block validation.

## Verify enrollment

```bash
# Controller
sudo wg show neodse
sudo systemctl status wg-quick@neodse neodse-transport neodse-server neodse-proxy
curl --fail --cacert /etc/neodse/server.crt https://127.0.0.1:8443/healthz
# Display
sudo wg show neodse
sudo systemctl status wg-quick@neodse neodse-agent neodse-weston neodse-ui
sudo journalctl -u neodse-agent --since '-10 minutes'
```

With the [authenticated API helper](OPERATIONS.md#api-access), request
`/api/v1/agents/display-001`. Confirm recent state and `is_authenticated: true`;
a WireGuard handshake alone does not establish readiness.

## Troubleshooting

Start with the symptom below and the affected host's journal.

| Symptom | First checks |
| --- | --- |
| API and dashboard are unreachable after a controller restart | `Controller database is locked` in the `neodse-server` journal. [Unlock](OPERATIONS.md#unlocking-the-controller) it with `sudo neodse-server unlock`. |
| No recent WireGuard handshake | Endpoint resolution, IPv4 routing, UDP port and firewall rules on both hosts. |
| Tunnel works, but the agent is unauthenticated | Clock synchronization on both hosts, transport listener, effective WireGuard route, matching enrollment credentials and controller/agent journals. |
| Dashboard opens, but web content does not load | Nonempty `proxy.authorized_networks`, playlist and supporting origins, eligible IPv4 resolution, trusted website certificates, pages accessible without signing in, controller certificate expiry, and capacity or `Proxy authorization unavailable` warnings in the proxy journal. |
| Weston or the UI is inactive | Connected DRM display, Weston journal and `/run/user/<neodse-ui UID>/wayland-0`. Connecting a display starts Weston unless `neodse-weston.service` is disabled. |
| Banner or sound is missing | Event result, agent connection, waiting-screen banner setting, configured sound file and ALSA output. |
| CEC or a serial action fails | Enabled hardware configuration, adapter/device access, CEC support or the peripheral's AT protocol, and the event result. |
| Live view is unavailable | Agent and Weston state, account scope and another active viewer. Only one viewer per display is supported. |

If provisioning reports a storage, write or synchronization failure, correct the
storage problem before retrying. Configuration may already have been published.
Inspect `/etc/wireguard/<instance>.conf`, the affected NeoDSE component
configuration and the controller's enrollment state. Restore consistent state
from backup or complete enrollment before restarting services. These files
contain secrets; never share their contents.

See [result tracking](OPERATIONS.md#monitoring) and
[content compatibility](CONFIGURATION.md#content-compatibility) for details.
Inspect controller and display journals:

```bash
sudo journalctl -b -u neodse-transport -u neodse-server -u neodse-proxy
sudo journalctl -b -u neodse-agent -u neodse-weston -u neodse-ui
systemctl cat neodse-weston.service neodse-ui.service
ui_uid=$(id -u neodse-ui)
sudo -u neodse-ui test -S "/run/user/${ui_uid}/wayland-0"
```

After changing display units, run `sudo systemctl daemon-reload`, restart
`neodse-weston.service`, then `neodse-ui.service`. See
[display configuration](CONFIGURATION.md#display-configuration-file) for appearance settings.

## Rotate or remove a display

To rotate credentials, repeat [provisioning](#provision-displays). Leave
`neodse-agent provision` waiting and add `--force` to the controller command:
`sudo neodse-server provision-agent --instance neodse --force`.
Complete both sides together: new credentials take effect immediately. Bootstrap
the agent again only when also replacing its private key.

To decommission it, run these commands. Removing the agent also deletes its proxy
policy. The controller command asks for the database passphrase:

```bash
# Controller
sudo neodse-server remove-agent --instance neodse display-001
# Display
sudo neodse-agent remove-config --instance neodse
```
