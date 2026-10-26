# Operations

After [deployment](DEPLOYMENT.md), use this guide for daily operation, monitoring
and upgrades. Configuration fields and display settings are in the
[configuration reference](CONFIGURATION.md).

[Dashboard](#dashboard) · [API access](#api-access) ·
[Content and schedules](#content-and-schedules) ·
[Automated alerts](#automated-alerts-and-peripherals) ·
[Monitoring](#monitoring) · [Unlocking](#unlocking-the-controller) ·
[Certificate renewal](#certificate-renewal) ·
[Upgrades and restoration](#upgrades)

## Dashboard

Open `https://127.0.0.1:8443/` on the controller, through an SSH tunnel or with
[direct LAN access](CONFIGURATION.md#lan-api-access). Sign in with a scoped
service-account token. Your roles and display assignments determine the controls
you see. The token stays in page memory; reloading requires signing in again.

Select an online display for live viewing. Click the image to expand it; use
Close or Escape to return.

Live viewing is read-only, with one viewer per display. See
[architecture](ARCHITECTURE.md#live-display) for capture and authentication details.

## API access

Swagger UI is at `https://127.0.0.1:8443/docs/`. Forward the loopback API over
SSH for remote access, or [configure LAN access](CONFIGURATION.md#lan-api-access):

```bash
ssh -L 8443:127.0.0.1:8443 administrator@server.example
```

The examples use Bash and default controller paths. Trust the deployment
certificate through your approved process, then define this helper on the
controller. It keeps the token out of shell history and process arguments:

```bash
curl --fail --cacert /etc/neodse/server.crt https://127.0.0.1:8443/healthz
read -rsp 'NeoDSE bearer token: ' NEODSE_TOKEN; printf '\n'
neodse_api() {
  printf 'Authorization: Bearer %s\n' "$NEODSE_TOKEN" |
    curl --fail --cacert /etc/neodse/server.crt --header @- "$@"
}
neodse_api https://127.0.0.1:8443/api/v1/agents
```

Do not export the token or enable shell tracing. When finished, run
`unset NEODSE_TOKEN; unset -f neodse_api`.

### Accounts and roles

Manage accounts at `/api/v1/service-accounts`. Store tokens when created or
rotated; they are shown only once. Set expiry dates appropriate to their use.

| Role | Permissions |
| --- | --- |
| `viewer` | Read state, events and schedules |
| `content_manager` | Playlists, reload, synchronization, banners and proxy revocation |
| `alert_io_operator` | Sound and serial actions |
| `cec_manager` | Display power and audio |
| `system_operator` | Restart, reboot and shutdown |
| `administrator` | All operations, schedule changes and global account management |

Combine roles as needed; `administrator` must be assigned alone. Scope accounts
to named agents or `all_agents`. Every role includes read access within that
scope, so operational accounts do not also need `viewer`.

Only administrators can change schedules or manage accounts. They can grant
access to any display, even beyond their own direct assignments. Use other roles
when delegating access to specific agents.

With an administrator token loaded in `neodse_api`, create a scoped operator:

```bash
neodse_api --request POST -H 'Content-Type: application/json' \
  --data '{"name":"Display operator","roles":["content_manager","alert_io_operator","cec_manager"],"all_agents":false,"agents":["display-001"]}' \
  https://127.0.0.1:8443/api/v1/service-accounts
```

Store the returned token securely without recording the session, and use it for
daily work. Add `expires_at` in RFC 3339 format and adjust roles and assignments
for the operator. Reserve the bootstrap administrator token for administration.

An administrator cannot disable, expire, demote or delete its own account;
another administrator makes those changes. If no administrator token works
anymore, because tokens were lost, expired or disabled, restore access on the
controller host:

```bash
sudo neodse-server recover-admin --name recovery-admin
```

The command asks for the database passphrase, then prints a new token for that
administrator account and creates the account if it does not exist. Earlier
tokens of the account stop working; other accounts and running services are
unaffected. Store the token without recording the session, then restore the
regular administrators and delete the recovery account.

## Content and schedules

First [authorize destination networks](DEPLOYMENT.md#authorize-content-networks),
then publish one to six HTTP(S) pages to a display:

```bash
neodse_api --request PUT -H 'Content-Type: application/json' \
  --data '{"urls":["https://signage.example/a","https://signage.example/b"],"interval":30,"proxy_allow":["https://assets.example"]}' \
  https://127.0.0.1:8443/api/v1/agents/display-001/playlist
```

Page origins are authorized automatically. Add API, redirect, font, script and
CDN origins with `proxy_allow`; grants cover whole origins, not individual paths.
Pages must work without sign-in because NeoDSE does not retain website sessions.

With several pages, `interval` is required: the time each page stays visible,
from 10 to 86400 seconds. A single page stays displayed and takes no `interval`.
`start_at` is the Unix time when rotation starts, and the waiting screen remains
until then; omit it or use `0` to start immediately. Displays rotate by
wall-clock time, so playlists with the same timing stay in step. Offline
displays receive saved changes when they reconnect.

Use **Reload web content** to refresh every page in the active playlist, including
hidden pages, without using cached data. This preserves the loaded views,
rotation timing and current position. The equivalent API request is:

```bash
neodse_api --request POST \
  https://127.0.0.1:8443/api/v1/agents/display-001/playlist/reload
```

To restore the waiting screen:

```bash
neodse_api --request DELETE \
  https://127.0.0.1:8443/api/v1/agents/display-001/playlist
```

To revoke web-content access while retaining the saved playlist:

```bash
neodse_api --request POST \
  https://127.0.0.1:8443/api/v1/agents/display-001/proxy/revoke
```

Revocation blocks new authorizations as soon as it is saved and closes existing
streams and tunnels within 60 seconds. It survives synchronization, reload and
reconnection. Publishing a playlist authorizes its destinations again.

Power schedules and playlist synchronization times use the controller's local
timezone. A delayed controller still runs power changes due in the previous two
minutes, once each, including across midnight. At daylight-saving changes, a
power change at a skipped local time does not run, and a synchronization time
that does not exist is rejected; a repeated local time is used once. Schedule
critical power changes outside those hours.

A display has at most one weekly power schedule. Only an administrator can
create, replace or delete it; all scoped roles can read it. For example:

```bash
neodse_api --request POST -H 'Content-Type: application/json' \
  --data '{"days":["monday","tuesday","wednesday","thursday","friday"],"power_on":"08:00","power_off":"18:00","enabled":true,"reminder_enabled":true}' \
  https://127.0.0.1:8443/api/v1/agents/display-001/schedules
```

This switches a compatible screen through HDMI-CEC and shows warning banners
before power-off. Keep the Linux host and agent running; the schedule does not
control host power. See the [API reference](../README.md#documentation) for
synchronization, broadcasts and other operations.

## Automated alerts and peripherals

Connect monitoring tools with an administrator-supplied script or webhook adapter
that calls the API. Store its token and controller certificate through your
secret-management process. The examples below use the [`neodse_api` helper](#api-access)
and an account scoped to `display-001`.

### Display a banner and play a notification

Assign `content_manager` for the banner and `alert_io_operator` for the sound:

```bash
neodse_api --request POST -H 'Content-Type: application/json' \
  --data '{"message":"Database latency above threshold","severity":"critical","duration_seconds":60}' \
  https://127.0.0.1:8443/api/v1/agents/display-001/banner
neodse_api --request POST \
  https://127.0.0.1:8443/api/v1/agents/display-001/sound/critical
```

Banners hold up to 256 Unicode characters on one line, truncated with an
ellipsis when too wide, and last 1–300 seconds at `info`, `warning` or
`critical` severity. A new custom banner replaces the previous one and appears
below the display name and clock. The waiting screen hides banners unless
`NEODSE_UI_WAITING_OVERLAYS=show` is set.

The bottom-right N shows connection health during playlist playback. Its
visibility and size, and waiting-screen status messages, are controlled by the
[UI appearance settings](CONFIGURATION.md#ui-appearance-settings). Sounds use the
same three severity names, with files selected in the
[agent configuration](CONFIGURATION.md#agent).

### Control screen power and a serial warning light

Assign `cec_manager`, enable HDMI-CEC in the agent configuration and on the
screen, and verify the configured `/dev/cecN` adapter. With the Linux host running,
turn the screen on:

```bash
neodse_api --request POST \
  https://127.0.0.1:8443/api/v1/agents/display-001/display/on
```

Serial actions require `alert_io_operator`, enabled serial configuration and a
device implementing NeoDSE's [AT command protocol](ARCHITECTURE.md#serial-peripheral-protocol).
The configured `serial.response_timeout_ms` bounds the command write and response
together. A stalled device reports a failed command; agent shutdown interrupts
pending serial I/O. For a supported beacon:

```bash
neodse_api --request POST -H 'Content-Type: application/json' \
  --data '{"command":"beacon","state":"blink","period_ms":500}' \
  https://127.0.0.1:8443/api/v1/agents/display-001/serial
```

The integration controls request ordering, routing and repeat notifications.
Check each returned `event_id` in [monitoring](#monitoring) before retrying.

## Monitoring

An agent is ready when its state is recent and `is_authenticated` is true.
Controller readiness requires `/api/v1/system/status` to report `status: ready`,
`database: true` and `transport: true`; `/healthz` alone is insufficient.

Content and hardware changes return an `event_id`. HTTP `202` confirms a command
was accepted; execution may still fail. Closing or timing out the API request
does not undo a committed operation, and broadcasts continue for their committed
target set. Check outcomes and physical state before retrying a lost response.

Look up the exact returned ID, or an agent's `last_event_id` (including scheduled
occurrences):

```bash
neodse_api "https://127.0.0.1:8443/api/v1/events/<event-id>"
```

States include `queued`, `uncertain`, `received`, `accepted` and `completed`;
some actions skip intermediate states. Other terminal outcomes are `rejected`,
`expired`, `failed` and `unsupported`. An `uncertain` action may have executed;
check physical state before retrying.

A display that reconnects receives only its latest content. When it applies that
content, earlier unresolved publications for it become `expired` with reason
`superseded by revision N`, and a publication of the same content becomes
`accepted` with reason `applied through event <id>`. A command that reaches a
display after its expiry is reported as `expired` and is not executed.

Content and schedules survive disconnections. Banners, CEC, sound, serial and host
actions need an authenticated online agent and are never replayed after an outage.
A single offline target returns `409 agent_offline`; broadcasts record a rejection
for each offline target.

Inspect services and journals on the corresponding host:

```bash
# Controller
sudo systemctl status wg-quick@neodse neodse-transport neodse-server neodse-proxy
sudo journalctl -b -u neodse-transport -u neodse-server -u neodse-proxy
# Display
sudo systemctl status wg-quick@neodse neodse-agent neodse-weston neodse-ui
sudo journalctl -b -u neodse-agent -u neodse-weston -u neodse-ui
```

If a WebKit child process crashes, the renderer logs `Playlist web process terminated`
and retries the affected page after about ten seconds while GTK stays running.

### Display session checks

Weston opens a graphical PAM session for `neodse-ui`, which provides its
`/run/user/<uid>` runtime directory, user manager, D-Bus socket and `wayland-0`.
Before the renderer starts, its `ExecStartPre` helper records that session in
`/run/neodse-ui/session.env`; the renderer opens no PAM session of its own. See
[state and delivery](ARCHITECTURE.md#state-and-delivery) for the runtime
directories.

If Weston runs with a display connected but the renderer does not start, check
the user manager, sockets and directory ownership:

```bash
ui_uid=$(id -u neodse-ui)
sudo systemctl status "user@${ui_uid}.service" "user-runtime-dir@${ui_uid}.service" --no-pager
sudo test -S "/run/user/${ui_uid}/bus"
sudo -u neodse-ui test -S "/run/user/${ui_uid}/wayland-0"
sudo stat -c '%U:%G %a %n' "/run/user/${ui_uid}" /run/neodse-ui /run/neodse
sudo journalctl -b -u "user@${ui_uid}.service" -u neodse-weston -u neodse-ui
sudo systemctl cat neodse-weston.service neodse-ui.service
```

`/run/user/<uid>` and `/run/neodse-ui` must belong to `neodse-ui` with mode
`700`; `/run/neodse` must be `neodse-ui:neodse-ipc` with mode `750`, so the agent
can reach the renderer's sockets without changing them. Do not point
`XDG_RUNTIME_DIR` at `/run/neodse`. A runtime directory can exist without a
running user manager: newer systemd versions may start a light session for
system accounts, so the packaged Weston unit sets the session type and class
explicitly. Compare local overrides with the packaged units.

## Restrict host power actions

The client grants only these privileged actions in `/etc/sudoers.d/neodse-agent`:

```sudoers
neodse-agent ALL=(root) NOPASSWD: /usr/bin/systemctl reboot
neodse-agent ALL=(root) NOPASSWD: /usr/bin/systemctl poweroff
neodse-agent ALL=(root) NOPASSWD: /usr/bin/systemctl restart neodse-ui.service
```

Remove unwanted rules with `sudo visudo -f /etc/sudoers.d/neodse-agent`. Keep the
file, even if only a comment remains: package installation validates it. If sudo
denies an API-authorized action, the agent reports failure.

`restart` restarts the renderer; the agent stays connected to report the outcome,
and the controller reapplies content afterward. HDMI-CEC screen power is separate
from host power. Preserve local restrictions during package-manager prompts and
review upstream rule changes.

## Unlocking the controller

The controller database, its WAL and its rollback journal are encrypted with
AES-256-XTS. The key exists unencrypted only in the controller's memory. After
every start, including a reboot, a crash, `systemctl restart` and a package
upgrade, the controller waits locked and logs `Controller database is locked`.
Unlock it as root on the controller:

```bash
sudo neodse-server unlock
```

The command asks for the database passphrase without echo and passes it to the
waiting controller over a socket that only root can use. After a wrong
passphrase the controller stays locked, so you can try again. With the correct
passphrase it opens the database and starts serving. If startup fails after
that, the controller exits, systemd starts it locked again and the journal
records the error. The socket appears a moment after systemd reports the service
as started; if `unlock` says the controller is not waiting, retry after a second.
Scripts should do the same.

While locked, the API, dashboard and proxy authorization are unavailable and
displays cannot authenticate. They keep their current content, but web pages
cannot load resources through the proxy. Schedules do not run: a power change due
more than two minutes before the unlock is skipped, not caught up, and missed
reminders are not shown. Monitor the controller so that a locked state is noticed
quickly: a locked controller refuses connections on its API port, including
`/healthz`, and `sudo test -S /run/neodse-server/unlock.sock` succeeds only while
it waits for the passphrase.

The root commands that open the database, `provision-agent`, `remove-agent` and
`recover-admin`, also ask for the passphrase. They work whether the service is
running or not. When standard input is not a terminal, every command reads the
passphrase from its first line, for example piped from a secret manager. Never
pass it as a command argument.

Root maintenance commands run outside the server service's swap limit. Keep
controller swap disabled or encrypted, including after reboot, so their
passphrases and database keys cannot be written to unencrypted swap.

To change the passphrase, run:

```bash
sudo neodse-server change-passphrase
```

It asks for the current passphrase, then twice for the new one. Without a
terminal, it reads the current passphrase from the first line of standard input
and the new one from the second. Only the keyslot changes; the database key and
a running controller are unaffected. A keyslot backup still opens with the
passphrase that was current when it was taken, so protect or retire older
backups accordingly.

If the passphrase is lost, the database cannot be recovered. Stop the controller
services, `wg-quick@neodse` and any manually launched database writers. Move the
old database, its keyslot and any matching `-wal`, `-shm` and `-journal` files
aside together, preserving their ownership and permissions. For the default
paths, these are `/var/lib/neodse/controller.db` and its sidecars. Run
`neodse-server bootstrap` again with `--force` and your original options, unlock
the new controller, and re-enroll every display. Bootstrap generates new secrets,
an administrator token and a certificate; redistribute certificate trust to API
clients and browsers.

## Certificate renewal

Bootstrap generates a self-signed HTTPS certificate valid for three years. The
proxy rejects an expired controller certificate, which stops web content on every
display, so renew it before it expires. The controller logs the expiry date at
startup and warns daily during the last 30 days:

```bash
sudo openssl x509 -in /etc/neodse/server.crt -noout -enddate
sudo journalctl -u neodse-server | grep 'HTTPS certificate'
```

Renew during a maintenance window. The new certificate keeps the addresses of
the current one; pass `--address` only to change the controller address:

```bash
sudo systemctl stop neodse-proxy neodse-server &&
  sudo neodse-server renew-certificate &&
  sudo systemctl start neodse-server neodse-proxy
```

The controller starts locked: [unlock it](#unlocking-the-controller) with
`sudo neodse-server unlock`. Then distribute the new public certificate to API
clients and browsers that trust it directly. Displays need no change. A
certificate issued by an organizational CA is renewed by that CA;
`renew-certificate` refuses to replace it unless `--address` is given.

## Upgrades

Rehearse on an isolated copy, then use a maintenance window. Release notes must
explicitly support upgrading from your installed release. Update all components
to the same release; mixed versions and protocols are unsupported. Reload the
dashboard afterward.

### Back up

1. Read release notes and [verify packages](DEPLOYMENT.md#packages). Keep the
   previous verified packages and record versions, checksums and host details.
2. Record configuration, systemd overrides, firewall/trust/SELinux settings,
   restricted sudoers rules, service-account UID/GID mappings and intentionally
   stopped/disabled services.
3. Stop `neodse-agent` on every display before changing the controller. Existing
   pages may lose proxy access during the window.
4. Stop controller services and any manually launched controller/provisioning
   processes. Confirm every database writer is stopped:

   ```bash
   sudo systemctl stop neodse-proxy neodse-server neodse-transport
   systemctl is-active neodse-proxy neodse-server neodse-transport
   ```

   A nonzero exit from `is-active` is expected for stopped units. Investigate any
   service still active.
5. Copy `/var/lib/neodse`, `/etc/neodse` and `/etc/wireguard` to encrypted,
   access-controlled storage. Include the database keyslot, SQLite WAL/SHM files,
   external certificates and custom paths. The database stays encrypted in the
   copy; restoring it needs the passphrase of the copied keyslot. Preserve
   numeric ownership, modes, ACLs and extended attributes. Back up each display's
   enrollment/tunnel configuration too; browser runtime state is not
   configuration.

### Install and resume

1. Install the verified server package on the controller with `apt install ./PACKAGE.deb`
   or `dnf install ./PACKAGE.rpm` as root. Configured server packages enable/restart
   transport, controller and proxy. The controller restarts locked: run
   `sudo neodse-server unlock`. SQLite migrations run once it is unlocked.
   Unconfigured installations remain stopped. RPM hooks refresh policy/labels.
   Review package-manager output and stop after a failed hook.
2. Check health and authenticated controller readiness using the API helper above.
3. Install the verified client package on one canary display. The hook restarts
   Weston/UI, clearing volatile state, and uses `try-restart` for the agent:
   a running agent adopts the new binary; one stopped for maintenance stays stopped.
   Packages enable services, so reapply intentional disabled states afterward.
   Retain local sudoers restrictions and review upstream changes.
4. Start the canary with `sudo systemctl start neodse-agent`. Check its version,
   authenticated heartbeat, content, proxy access and configured hardware. Restart
   the renderer to verify content recovery and ephemeral browser state.
5. Update remaining displays and start their agents. Review journals, schedules,
   readiness and proxy denials, restore intended disablement, and save validation
   results with the backup.

Do not bootstrap or re-enroll as a routine update. Re-enrollment is needed when
controller credentials are recreated or release instructions require it.

### Restore after failure

Stop the rollout and affected agents. Isolate the replacement controller and
install the previous package on a clean matching host, keeping it unconfigured
and its services stopped. Restore the matching database, keyslot and
configuration, including ownership, modes, trust, overrides and SELinux
contexts. Check the restored ownership and ACLs against the replacement host's
service accounts: package-created UID/GID numbers may differ from the backup.
Remap restored files to the same named accounts before starting services; follow
the [configuration ownership table](CONFIGURATION.md), and keep the database,
keyslot and sidecars owned by `neodse-server:neodse-server`. Keep failed state for
diagnosis; do not overlay old state onto a new database's WAL/SHM files. Start
`wg-quick@neodse`, then `neodse-transport`, `neodse-server` and `neodse-proxy`;
substitute your configured WireGuard instance when different. Unlock with the
passphrase of the restored keyslot and check authenticated controller readiness
before reconnecting displays.

Never run an old binary against a newer migrated database: restore both binaries
and matching state. Restore display packages/configuration to that same release,
validate a canary, then reconnect the fleet. Verify account scope, credentials,
desired content, schedules and proxy policy. Backups can restore revoked authority
and old action history; review schedules, rotate credentials when needed and check
physical state before retrying uncertain actions.
