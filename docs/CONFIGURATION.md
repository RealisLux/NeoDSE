# NeoDSE configuration

Start with the files generated during [deployment](DEPLOYMENT.md). This reference
matches the current source version; update all components together when configuration
changes. YAML loaders reject unknown fields, multiple documents, symlinks, non-regular
files, unexpected ownership and excessive permissions.

[Agent](#agent) · [Display configuration](#display-configuration-file) ·
[Server and transport](#server-and-transport) · [LAN API access](#lan-api-access) ·
[Proxy](#proxy) · [Content compatibility](#content-compatibility) ·
[Logging](#logging-and-applying-changes)

| File | Owner/mode |
| --- | --- |
| `/etc/neodse/server.yaml` | `root:neodse-server` `0640` |
| `/etc/neodse/proxy.yaml` | `root:neodse-proxy` `0640` |
| `/etc/neodse/transport.yaml` | `root:neodse-transport` `0640` |
| `/etc/neodse/server.crt` | `root:root` `0644` |
| `/etc/neodse/server.key` | `root:neodse-server` `0640` |
| `/var/lib/neodse/controller.db`, its `.keyslot` and SQLite sidecars | `neodse-server:neodse-server` `0600` |
| `/etc/neodse/agent.yaml` | `neodse-agent:neodse-agent` `0600` |
| `/etc/neodse/display.env` | `root:root` `0600` |
| WireGuard configuration | `root:root` `0600` |

For a custom path, pass `--config` and override the packaged systemd unit's explicit
default path. Give the service the required filesystem permissions and access.

Edit each file on its service's host, preserve ownership and modes, then restart
the service and check its journal. Keep secrets out of issue reports and examples.

Application PSKs are exactly 64 hexadecimal characters. Paste generated keys
unchanged; surrounding whitespace is rejected even inside quotes.

## Agent

Field names include their YAML mapping prefix. Required fields must be present
after enrollment, which supplies the credentials and peer addresses missing from
the bootstrap configuration.

| Field | Value or behavior |
| --- | --- |
| `agent.id` | Required. 1–32 ASCII letters, digits, `_` or `-`, starting with a letter or digit. `broadcast` is reserved for fleet API routes. |
| `agent.friendly_name` | Optional trimmed UTF-8 label, at most 32 characters, with no NUL. Shown on the waiting screen and over playlist content unless hidden by the UI settings. |
| `agent.psk` | Required after enrollment. A 256-bit key encoded as 64 hexadecimal characters. |
| `agent.wireguard_interface` | Required WireGuard interface name. |
| `agent.ui_socket` | Defaults to `/run/neodse/ui.sock`. Absolute normalized path shorter than 108 bytes. The packaged renderer requires a filename directly below `/run/neodse`; set `NEODSE_UI_SOCKET` in `/etc/neodse/display.env` to the same path for a custom filename. |
| `agent.log_level` | `info` (default), `verbose` or `debug`. |
| `transport.url` | Required `ws://` URL with a literal private or loopback IPv4 address and an explicit port. No credentials, query or fragment; path is empty or `/`. Non-loopback traffic must use WireGuard. |
| `proxy.url` | Required `http://` URL with an explicit port and the same IPv4 address as `transport.url`. No credentials, query or fragment; path is empty or `/`. |
| `sound.info`, `sound.warning`, `sound.critical` | Absolute normalized paths to local audio files. An empty value disables that profile. |
| `serial.enabled` | Enables the serial adapter; disabled in bootstrap configuration. |
| `serial.port` | Absolute device path when enabled. Bootstrap uses `/dev/ttyUSB0` as an example. |
| `serial.baudrate` | 1–115200 when enabled; match the peripheral. Bootstrap uses 9600. Serial framing is raw 8N1 without flow control. |
| `serial.response_timeout_ms` | Required when enabled, from 100 to 60000 ms. Bounds the command write and response together; bootstrap supplies 5000 ms. Agent shutdown cancels pending I/O. |
| `cec.enabled` | Enables the Linux HDMI-CEC adapter. Bootstrap writes `false`; an omitted field means `true`. |
| `cec.device` | An explicit `/dev/cecN` path, even when CEC is disabled; defaults to `/dev/cec0`. |

### Sound and peripherals

Bootstrap uses the package's original notification sounds at
`/usr/share/neodse/{info,warning,critical}.wav`. Playback runs `/usr/bin/aplay`
through ALSA's default output, with a 30-second timeout. Custom files must be
readable by `neodse-agent`; configure the host's audio output for the speakers.

HDMI-CEC needs a compatible host adapter, screen and cable. Bootstrap leaves CEC
disabled: set `cec.enabled: true` and restart `neodse-agent` once the screen is
connected. Enable CEC on the screen and select the correct adapter. Power
commands target TV address `0`; audio commands prefer an Audio System at address
`5`, falling back to the TV. Screen power commands do not boot or shut down the
Linux host.

Serial peripherals must implement the [NeoDSE AT
protocol](ARCHITECTURE.md#serial-peripheral-protocol); a USB or serial connection
alone is insufficient. Match the baud rate and give `neodse-agent` device access.
The package adds the account to existing `audio`, `video` and `dialout` groups.

The agent opens the port for each command and keeps DTR asserted when closing
it. A board that restarts on a DTR change, such as many Arduino-compatible
controllers, therefore restarts only on the first command after it is connected
or the host boots. That command can time out while the board starts; send it
again.

Remote WebKit views always use the agent's content relay. For web destinations, see
[proxy](#proxy) and [content compatibility](#content-compatibility).

### Weston DRM and VNC outputs

Weston runs its stock DRM and VNC backends. At startup,
`/usr/lib/neodse/neodse-weston-config` selects the first connected DRM connector
and writes `/run/neodse/weston.ini`. VNC mirrors that output at its active
modeline through `mirror-of`; the mirror cannot be resized. `force-on=true`
keeps it available when a screen drops HDMI hotplug during standby. Connected
displays normally need no manual video mode; Weston selects its renderer normally.

`/run/neodse` is owned by `neodse-ui:neodse-ipc` with mode `0750`: the agent can
connect to the renderer's `0660` socket but cannot replace it or the compositor
configuration.

Weston and the UI do not start while no screen is connected; the agent stays
available. Connecting a screen later starts Weston through the packaged udev rule
`/usr/lib/udev/rules.d/71-neodse-display-hotplug.rules`, unless
`neodse-weston.service` is disabled. To start it manually and read its log:

```bash
sudo systemctl start neodse-weston.service
sudo journalctl -b -u neodse-weston.service
```

Set output scale and rotation in the shared
[`/etc/neodse/display.env`](#display-configuration-file), then restart
`neodse-weston.service`:

```ini
NEODSE_WESTON_SCALE=2
NEODSE_WESTON_TRANSFORM=normal
```

`NEODSE_WESTON_SCALE` must be a positive 32-bit integer (default `1`). Scale `2`
gives a 4K screen a 1080p logical size while retaining its physical video mode.
`NEODSE_WESTON_TRANSFORM` accepts `normal` (default), `rotate-90`, `rotate-180` or
`rotate-270`, using clockwise angles. Invalid settings prevent Weston startup
and leave the previous generated configuration intact.

Missing settings use scale `1` and no rotation. Weston regenerates
`/run/neodse/weston.ini` on every start. Restarting it also restarts the UI and
briefly interrupts the display.

VNC listens only on `127.0.0.1:5900`. The live-view stream is one-way; neither
the operator nor controller needs direct VNC access. See
[live display](ARCHITECTURE.md#live-display) for authentication, JPEG framing and
loopback encryption. The package configures Weston's PAM service to use
`/usr/lib/neodse/neodse-vnc-auth` through `pam_exec.so` and restores the distribution
PAM file on removal.

Installation creates a device-local TLS identity in `/var/lib/neodse-vnc`.
Both files are root-owned: `server.key` uses mode `0600`, `server.crt` mode `0644`.
The directory must be root-owned and not group/world writable. Systemd passes
the key to Weston with `LoadCredential`. The agent trusts only this certificate
for `127.0.0.1`; invalid or missing trust blocks capture. Keep the host clock correct.

The certificate lasts ten years. Manage its lifecycle as follows:

- **Renew:** package installation reuses the key and renews the certificate when
  fewer than 30 days remain. For manual renewal, run
  `sudo /usr/lib/neodse/neodse-vnc-tls`, then restart Weston. There is no renewal daemon.
- **Rotate after compromise:** stop Weston, remove both identity files as root,
  run the helper, then start Weston. The helper rejects unsafe permissions,
  mismatched keys and an existing certificate with a missing key.
- **Back up or remove:** encrypt private-key backups and never share identities
  between displays. Package removal keeps the identity; delete its directory
  when decommissioning the host.

The UI waits for Weston's `systemd-notify.so` / `Type=notify` readiness signal
and checks compositor activity, so a stale Wayland socket is insufficient.
After moving the cable to another output, restart Weston to change the mirror
source. Weston runs with `NoNewPrivileges` and core dumps disabled.

GTK and WebKit can use the GPU: the renderer service may open DRM devices,
through the `video` and `render` groups of `neodse-ui`, but no other hardware.
If the graphics driver misrenders, run `sudo systemctl edit neodse-ui.service`,
add `PrivateDevices=true` under `[Service]` and restart the service: the
renderer then draws on the CPU.

### Display configuration file

Weston and the UI read `/etc/neodse/display.env` through systemd's
`EnvironmentFile`. The client package supplies defaults. Edit it as root on the display:

```sh
sudoedit /etc/neodse/display.env
```

For example, increase banner and logo sizes on a 4K display and show device
information on the waiting screen:

```ini
NEODSE_BANNER_SCALE=2.0
NEODSE_WAITING_LOGO_SCALE=3.0
NEODSE_UI_DEVICE_INFO=show
```

Restart the UI to apply appearance changes; this briefly interrupts the display:

```sh
sudo systemctl restart neodse-ui.service
sudo systemctl status neodse-ui.service --no-pager
```

Output scale and rotation changes require `sudo systemctl restart neodse-weston.service`;
appearance changes need only the UI restart above. No `systemctl daemon-reload`
is needed. Remove an assignment and restart its service to restore the default.
Read startup messages with `journalctl -u neodse-ui.service -u neodse-weston.service`.

### UI appearance settings

Scaling values must be finite numbers from `0.5` to `3.0`; invalid values keep the
`1.0` default. Visibility settings accept `show` or `hide`; invalid values use
the defaults below.

| Environment variable | Default | Effect |
| --- | --- | --- |
| `NEODSE_WAITING_LOGO_SCALE` | `1.0` | Waiting-screen logo scale; `3.0` is its native 2048 × 682 size, reduced to fit smaller screens |
| `NEODSE_STATUS_LOGO_SCALE` | `1.0` | Bottom-right playlist status N scale; approximately 48 × 32 pixels at `1.0` |
| `NEODSE_FRIENDLY_NAME_SCALE` | `1.0` | Top-left display-name scale |
| `NEODSE_CLOCK_SCALE` | `1.0` | Top-right clock scale |
| `NEODSE_BANNER_SCALE` | `1.0` | Notification-banner scale |
| `NEODSE_UI_ZOOM` | `1.0` | WebKit content scale |
| `NEODSE_UI_LOGO_ANIMATION` | `show` | Animated N; `hide` leaves the completed N visible |
| `NEODSE_UI_STATUS_LOGO` | `show` | Static colored N indicating connection health during playlist playback |
| `NEODSE_UI_FRIENDLY_NAME` | `show` | Display-name overlay when `agent.friendly_name` is configured |
| `NEODSE_UI_CLOCK` | `show` | Current device-local time in 24-hour `HH:MM:SS` format |
| `NEODSE_UI_DEVICE_INFO` | `hide` | Agent name and LAN/VPN addresses on the waiting screen |
| `NEODSE_UI_STATUS_MESSAGE` | `hide` | Latest status message below the waiting-screen logo |
| `NEODSE_UI_WAITING_OVERLAYS` | `hide` | Allow banners, display name and clock on the waiting screen; individual visibility settings still apply. Playlist overlays are unaffected |

The waiting screen is native GTK on a black background. Its logo indicates the
latest severity: blue for information, green for success, amber for warning and
red for critical. GTK's disabled-animation preference also makes the N static.
Set these in the [display configuration file](#display-configuration-file).

During playlist playback, transport or proxy-relay failures make the status logo
red. Otherwise, it stays amber while any playlist page has a load or proxy
failure. A successful background page does not clear another page's warning;
failed pages must recover or be replaced.

## Server and transport

Listeners require a literal loopback or private IPv4 address and a numeric port
from 1 to 65535. Wildcards, DNS names, public addresses, IPv6 and port zero are
rejected. Non-loopback plaintext links must name a WireGuard interface; startup
checks its type, listener address and effective route. Transport and proxy
listeners stay bound to that interface. If it is removed or recreated, for
example by `systemctl restart wg-quick@neodse`, the affected service exits within
a few seconds and systemd restarts it on the new interface.

| Field | Value or behavior |
| --- | --- |
| `server.wireguard_interface` | WireGuard interface for the controller's plaintext transport link. |
| `server.listen` | Required HTTPS API listener. Bootstrap uses `127.0.0.1:8443`. A non-loopback address also retains a listener on `127.0.0.1` at the same port. |
| `server.tls_cert`, `server.tls_key` | Required absolute normalized certificate and private-key paths. |
| `server.database` | Absolute normalized path; defaults to `/var/lib/neodse/controller.db`. The file is always encrypted, and its keyslot is the same path with `.keyslot` appended. |
| `server.transport_url` | Required private or loopback `ws://` URL with an explicit port. Agent provisioning gives displays this port at the controller's tunnel address. |
| `server.transport_psk` | Required 64-character hexadecimal key, matching `transport.controller_psk`. |
| `server.proxy_internal_psk` | Required 64-character hexadecimal key, matching `proxy.internal_psk`. |
| `server.event_retention_days` | 1–3650 days; omitted or `0` selects the 30-day default. |
| `server.log_level` | `info` (default), `verbose` or `debug`. |
| `transport.wireguard_interface` | WireGuard interface for a non-loopback listener. |
| `transport.listen` | Required WebSocket listener; bootstrap uses the controller's tunnel IP on port 8081. |
| `transport.controller_psk` | Required key matching `server.transport_psk`. |
| `transport.log_level` | `info` (default), `verbose` or `debug`. |

The services also limit accepted TCP sockets before HTTP parsing or TLS
handshakes. The transport admits 8,224 sockets in total and four per non-loopback
source address. The HTTPS API has separate budgets: 512 management sockets,
at most 256 per source, and 2,048 loopback sockets for local callers such as the
proxy. Management clients cannot consume the loopback budget. Loopback skips
per-source limits because it carries multiple agents, but still counts toward
its total limit. These fixed API limits do not increase with proxy settings.

Idle connections and upgraded WebSocket or CONNECT connections remain counted
until their sockets close. Excess connections close before a protocol response;
the service logs `TCP connection rejected` at most every 30 seconds per budget,
with limits and a suppressed count, without client addresses or credentials.

Keep the proxy backend on loopback unless the port or deployment layout changes.

The encrypted database holds agent PSKs and service-account token hashes. The
controller opens it only after [unlocking](OPERATIONS.md#unlocking-the-controller).
Database paths must not contain symbolic links. Keep the state directory's
ancestors root-owned and not writable by service accounts or other users, as
with the packaged `/var/lib/neodse` directory under `/var/lib`.
Change shared internal PSKs on both services during a maintenance window.

### LAN API access

The API, dashboard and Swagger UI share `server.listen` in
`/etc/neodse/server.yaml`. Use a stable private IPv4 address already assigned to
the controller. Replace these example values throughout: `192.168.50.10:8443`
for the controller, `192.168.50.0/24` for management clients and `eth0` for the
LAN interface.

1. **Set the LAN listener.** Change only `listen` in the existing `server:`
   mapping; keep the other keys and paths:

   ```yaml
   server:
     listen: 192.168.50.10:8443
   ```

   Use a literal private IPv4 address and an explicit port. Wildcard addresses
   such as `0.0.0.0`, public IPs, DNS names and IPv6 are rejected. Preserve
   `root:neodse-server` ownership and `0640` mode.

2. **Prepare TLS.** The certificate must include the LAN IP in its Subject
   Alternative Names. Back up the certificate/key pair securely, then replace
   the bootstrap certificate with one covering the LAN IP and loopback. Start
   the services only after renewal succeeds:

   ```bash
   sudo systemctl stop neodse-proxy neodse-server &&
     sudo neodse-server renew-certificate --address 192.168.50.10 &&
     sudo systemctl start neodse-server neodse-proxy
   ```

   If installation fails, the command attempts to restore the previous files.
   Keep both services stopped until the pair is verified. If automatic restoration
   fails too, restore both files from the same backup before restarting.

   Distribute and trust the new public certificate before connecting. With an
   organizational CA, install the matching pair at `server.tls_cert` and
   `server.tls_key`, then restart both services. Include the LAN IP, `127.0.0.1`
   for the proxy and any user-facing DNS names; `proxy.tls_ca` or system trust
   must validate it. The renewal command adds an IP, not a DNS name.

   The controller starts locked after either procedure. Run
   `sudo neodse-server unlock` before verifying access; see
   [unlocking the controller](OPERATIONS.md#unlocking-the-controller).

3. **Allow access through the firewall.** An administrator must apply and verify
   the [source-restricted LAN rules](FIREWALL.md#lan-api-access). That guide covers
   zone selection, persistence and review using firewalld; adapt the rules to the
   host's active firewall manager.

4. **Verify both listeners.** On the controller:

   ```bash
   sudo systemctl status neodse-server neodse-proxy --no-pager
   sudo ss -ltnp 'sport = :8443'
   curl --fail --cacert /etc/neodse/server.crt https://127.0.0.1:8443/healthz
   ```

   From a LAN workstation with a securely obtained public certificate:

   ```bash
   curl --fail --cacert ./neodse-server.crt https://192.168.50.10:8443/healthz
   ```

   Open `https://192.168.50.10:8443/` for the dashboard or
   `https://192.168.50.10:8443/docs/` for Swagger. Authenticate with a scoped
   service-account token. `/healthz` confirms liveness; use authenticated
   `/api/v1/system/status` to confirm readiness.

The server retains its loopback listener on the same port. Leave
`proxy.backend_url: https://127.0.0.1:8443` unchanged when changing only the address.
If you change the port, update the proxy's loopback port, firewall rules and API URLs.

To remove LAN access, restore `server.listen: 127.0.0.1:8443`, restart the server,
run `sudo neodse-server unlock`, and follow
[Remove LAN API access](FIREWALL.md#remove-lan-api-access) to remove the
associated firewall rule.

## Proxy

| Field | Value or behavior |
| --- | --- |
| `proxy.wireguard_interface` | WireGuard interface for a non-loopback plaintext listener. |
| `proxy.listen` | Required private or loopback IPv4 listener; bootstrap uses the controller's tunnel IP on port 3128. Agent provisioning reads this port from `/etc/neodse/proxy.yaml` (`--proxy-config`). |
| `proxy.backend_url` | Required HTTPS controller URL. Port defaults to 443; an explicit port must be 1–65535. |
| `proxy.internal_psk` | Required 64-character hexadecimal key matching `server.proxy_internal_psk`. |
| `proxy.tls_ca` | Optional absolute normalized CA certificate path, added to system trust. Keep the generated value for the bootstrap certificate. |
| `proxy.authorized_networks` | Destination IPv4 CIDRs; an empty or omitted list denies every destination. Bootstrap leaves it empty. |
| `proxy.max_connections` | Concurrent proxied requests and tunnels for the whole fleet, 1–65536. Omitted or `0` selects 2048. |
| `proxy.max_agent_connections` | Concurrent proxied requests and tunnels per display, 1–1024 and at most `max_connections`. Omitted or `0` selects 32. Each display's local relay also accepts at most 64 connections, so higher values have no further effect. |
| `proxy.log_level` | `info` (default), `verbose` or `debug`. |

Omit `proxy.tls_ca` only when the controller certificate is already trusted by the
system.

A tunnel holds its slot for as long as the page keeps it open, for example a
WebSocket or a streaming connection. The defaults cover six pages with several
supporting origins each on 64 displays. When a limit is reached, the proxy
refuses the connection and logs `Proxy fleet connection capacity reached` or
`Proxy display connection capacity reached` at most every 30 seconds. Raise the
named setting and restart `neodse-proxy`. While the controller is locked or
unreachable, the proxy refuses requests and logs
`Proxy authorization unavailable` at most every 30 seconds, with a count of
suppressed repeats.

Before parsing HTTP, the proxy also limits open sockets, including idle clients
and incomplete headers: `max_connections` + min(`max_connections`, 128) in total
and `max_agent_connections` + min(`max_agent_connections`, 8) per non-loopback
source IP, which is 2,176 and 40 with the defaults. Loopback counts toward the
total only. These limits use the actual network source, never a forwarded header
or claimed agent ID; the per-display request limit applies only after the
controller authenticates the credentials.

`authorized_networks` accepts private or public IPv4 CIDRs and applies to both
resolved DNS names and numeric URLs. To permit all otherwise eligible IPv4
addresses, use `0.0.0.0/0`. Loopback, link-local, multicast and unspecified
destinations remain forbidden even when covered by an authorized network. Network
permission does not replace origin authorization: playlist URLs and `proxy_allow`
still determine which HTTP(S) origins an agent may request.

```yaml
proxy:
  authorized_networks:
    - 10.20.0.0/16
    - 192.168.50.0/24
```

### Content compatibility

Playlist URLs must use HTTP(S); `proxy_allow` lists supporting origins. Pages
must work without sign-in; NeoDSE does not automate authentication or restore
website sessions. Authorize supporting origins (APIs, redirects, fonts, scripts)
and their IPv4 destination networks separately.

The renderer dismisses JavaScript dialogs, leaves pages despite before-unload
prompts, and rejects login, file-selection and print dialogs. Content that needs
these interactions is unsupported.

Secure WebSocket (`wss://`) content uses HTTPS CONNECT. Authorize a separate
WebSocket endpoint as `https://host:port` in `proxy_allow`, never as a `wss://`
playlist or allowlist URL. Plain `ws://` content upgrades are unsupported; this
does not affect NeoDSE's agent/controller `ws://` transport over WireGuard.

Test each application on a display before rollout. It must reconnect after dropped
connections: the relay and proxy close a connection that has carried no data in
either direction for five minutes. Plain HTTP responses, including streams and
downloads, last at most five minutes and HTTPS tunnels at most four hours.
Authorization is checked every 30 seconds, with leases of at most 60 seconds.
Credentials belong to the authenticated agent transport session and do not
expire periodically. A disconnect, new session, revocation, or denied or
unavailable authorization closes the connection at the next check.

## Logging and applying changes

Logging goes to journald:

- `info`: lifecycle and actionable failures.
- `verbose`: one redacted completion summary per request or tunnel.
- `debug`: connection-stage details; the controller currently uses the same
  operation summaries as `verbose`.

For example, after changing agent configuration:

```bash
sudo systemctl restart neodse-agent
sudo journalctl -u neodse-agent --since '-5 minutes' --no-pager
```

Restarting the agent interrupts its connection and transient operations. UI appearance
changes instead require a `neodse-ui` restart.

## Enterprise Linux

The SELinux policy labels the packaged paths. Files copied into `/etc/neodse`,
such as a certificate from your CA, inherit the right label; after moving files
there with `mv`, run `sudo restorecon -RF /etc/neodse`. Files elsewhere need the
matching type:

| Custom file | SELinux type |
| --- | --- |
| Service configuration, `server.tls_cert` and `server.tls_key` | `neodse_etc_t` |
| `server.database` directory | `neodse_server_var_lib_t` |
| `proxy.tls_ca` | `neodse_etc_t` or the system `cert_t` |

Persist each mapping with `semanage fcontext`, then apply it with `restorecon`:

```bash
sudo semanage fcontext -a -t neodse_etc_t '/srv/neodse-tls(/.*)?'
sudo restorecon -RFv /srv/neodse-tls
```
