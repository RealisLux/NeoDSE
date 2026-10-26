# Firewall

The administrator configures and verifies the controller firewall. NeoDSE
installation, bootstrap and upgrades leave it unchanged.

These examples use firewalld. Use the host's active firewall manager, with your
interface names, addresses and ports. For other managers, translate the access
rules, forwarding restrictions, rule order and persistence described below;
the distribution alone does not tell you which manager is active.

## Network isolation

Protect controllers and displays with host, network and physical measures suited
to the deployment's exposure, so that a compromised system cannot reach others.
For example, place controllers and displays in separate network segments, such
as separate physical networks or VLANs with enforced firewall or ACL rules, and
deny all traffic except the required flows: the controller's WireGuard UDP
endpoint, management access and infrastructure services such as DNS and NTP.
Limit the controller's own access to content networks and these dependencies.

A VLAN alone does not prevent lateral movement. Displays sharing a VLAN can
still communicate directly unless switch client isolation or equivalent access
controls block that traffic. Enforce isolation on the underlying LAN as well as
the [WireGuard client-to-client forwarding path](#client-isolation), and verify
that displays cannot reach one another or unrelated internal systems over either
path. Verify that controller access is also limited to the intended management,
display and dependency traffic. NeoDSE does not configure switches, VLANs or
upstream firewalls.

## Controller traffic

Configure the active firewall after bootstrap creates the WireGuard interface.

| Port | Service | Exposure |
| --- | --- | --- |
| `51820/udp` | WireGuard | Intended ingress network; public only if needed |
| `8081/tcp` | Transport | WireGuard interface only |
| `3128/tcp` | Proxy | WireGuard interface only |
| `8443/tcp` | HTTPS API | Loopback; optional restricted management LAN access |

Exposing the WireGuard listener to the Internet adds risk and requires protective
measures suited to the deployment.

NeoDSE uses IPv4 addresses and services inside the tunnel. WireGuard's outer
UDP transport is independent: it can carry that traffic over IPv4 or IPv6.
An IPv6 WireGuard endpoint does not expose NeoDSE TCP listeners over IPv6 or
bypass peer authentication. Apply the intended endpoint restrictions to both
address families where available. Disabling outer IPv6 is an optional deployment
policy, not a requirement for NeoDSE's IPv4 tunnel traffic. See the
[WireGuard overview](https://www.wireguard.com/#conceptual-overview) and
[endpoint configuration](https://git.zx2c4.com/wireguard-tools/tree/src/man/wg.8).

Displays use the transport and proxy over WireGuard, not the HTTPS API. The
controller proxy reaches the API at `https://127.0.0.1:8443`. Leave the API on
loopback unless enabling [restricted LAN access](#lan-api-access); do not open it
on WireGuard.

The rules below control network access, not service listeners. Apply both the
port rules and [client isolation](#client-isolation).

### Security requirements

Apply these requirements with whichever firewall manages the host:

- Deny unsolicited inbound traffic by default; allow only required services.
  Preserve SSH and other administrator access before changing policy.
- Permit the WireGuard UDP endpoint on its receiving interface and the transport
  and content proxy only through the WireGuard interface. Do not expose the API
  on WireGuard or expose NeoDSE TCP services on the public Internet.
- Block forwarding from the WireGuard interface back to itself for every
  protocol and port, while preserving access to controller services.
- If LAN API access is enabled, restrict it to the intended management sources,
  controller LAN address and API port. Account for every ingress interface
  matched by the host firewall's rules.
- Check existing host and cloud-provider rules for broader or earlier allowances
  that bypass these restrictions. A narrow allow rule does not cancel a broader
  one. Keep outbound access to content and other controller dependencies.
- Persist the rules and verify allowed and denied paths after applying them
  and after reboot. Input filtering and forwarding filtering must both enforce
  the intended policy; NeoDSE services do not require IP forwarding.

### firewalld example

With firewalld, first identify the endpoint interface and its effective zone
(replace `eth0` with the interface receiving WireGuard UDP traffic):

```bash
sudo firewall-cmd --state
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --get-default-zone
sudo firewall-cmd --get-zone-of-interface=eth0
sudo firewall-cmd --get-zone-of-interface=neodse
sudo firewall-cmd --list-all-zones
sudo firewall-cmd --permanent --list-all-zones
```

This example assumes the ingress interface already uses `external`. Set
`endpoint_zone` to the zone that handles incoming WireGuard traffic, checking
both interface and source bindings; unmatched traffic uses the default zone.
Keep existing assignments and management access. Zone names do not restrict
source addresses by themselves. See the
[zone definitions](https://firewalld.org/documentation/zone/predefined-zones.html).

Use a separate `neodse-vpn` zone for the `wg-quick` tunnel. If that zone already
exists, inspect it and skip `--new-zone`:

```bash
endpoint_zone=external
vpn_zone=neodse-vpn
sudo firewall-cmd --permanent --new-zone="$vpn_zone"
sudo firewall-cmd --permanent --zone="$vpn_zone" --change-interface=neodse
sudo firewall-cmd --permanent --zone="$endpoint_zone" --add-port=51820/udp
sudo firewall-cmd --permanent --zone="$vpn_zone" --add-port=8081/tcp
sudo firewall-cmd --permanent --zone="$vpn_zone" --add-port=3128/tcp
sudo firewall-cmd --check-config
sudo firewall-cmd --reload
sudo firewall-cmd --get-zone-of-interface=neodse
sudo firewall-cmd --zone="$vpn_zone" --list-all
sudo firewall-cmd --zone="$endpoint_zone" --list-all
sudo firewall-cmd --permanent --zone="$vpn_zone" --list-all
```

`--change-interface` creates or moves the interface binding. Check that the VPN
zone contains only `neodse`, no source bindings and the two TCP ports above.
Keep its default target: `trusted` or target `ACCEPT` would allow other inbound
services. A port opening covers every interface and source in its zone, so also
check source bindings and broad rules in other zones. Keep NeoDSE TCP ports out
of the endpoint zone. See
[firewalld zone bindings](https://firewalld.org/documentation/zone/connections-interfaces-and-sources.html)
and [zone options](https://firewalld.org/documentation/zone/options.html).

Before reloading, reconcile runtime and permanent rules, especially management
access. Reload applies `--permanent` changes and discards unsaved runtime rules.
After reboot, check that `neodse` still belongs to `neodse-vpn` and repeat the
enrollment checks. For NetworkManager-managed interfaces, also set the connection
profile's `connection.zone` to the intended zone. This example uses the
bootstrap-managed `wg-quick` tunnel. See the
[firewall-cmd reference](https://firewalld.org/documentation/man-pages/firewall-cmd.html).

## Client isolation

Apply these rules on the controller after setting up its tunnel firewall.
Provisioned displays have `AllowedIPs = <controller tunnel IP>/32`, but a client
can change its own routes and AllowedIPs. The controller must therefore block
forwarding from `neodse` back to `neodse`. Local transport and proxy access on
`8081` and `3128` remains available.

Keep IP forwarding disabled on a dedicated controller; NeoDSE does not need it.
If other workloads need forwarding, keep their settings and isolate displays
with the rules below.

### firewalld isolation

In the `neodse-vpn` zone, disable intra-zone forwarding and drop traffic from
the zone back to itself. If the policy already exists, inspect its runtime and
permanent settings and skip `--new-policy`:

```bash
vpn_zone=neodse-vpn
isolation_policy=neodse-isolation
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --list-all-policies
sudo firewall-cmd --permanent --list-all-policies
sudo firewall-cmd --permanent --zone="$vpn_zone" --remove-forward
sudo firewall-cmd --permanent --new-policy="$isolation_policy"
sudo firewall-cmd --permanent --policy="$isolation_policy" --add-ingress-zone="$vpn_zone"
sudo firewall-cmd --permanent --policy="$isolation_policy" --add-egress-zone="$vpn_zone"
sudo firewall-cmd --permanent --policy="$isolation_policy" --set-priority=-500
sudo firewall-cmd --permanent --policy="$isolation_policy" --set-target=DROP
sudo firewall-cmd --check-config
sudo firewall-cmd --reload
sudo firewall-cmd --zone="$vpn_zone" --query-forward
sudo firewall-cmd --info-policy="$isolation_policy"
sudo firewall-cmd --permanent --info-policy="$isolation_policy"
```

`--query-forward` must print `no` (exit status 1). Check that the policy is
active, has target `DROP` and priority `-500`, and lists only `neodse-vpn` for
both ingress and egress, with no service, port or rich-rule allowances. Negative
priority runs before zone rules; check for earlier accepting policies or custom
rules. Keep the VPN zone's default target and sole `neodse` interface binding.
These forwarding rules do not filter traffic to the controller itself. See
[firewalld policies](https://firewalld.org/documentation/man-pages/firewalld.policies.html)
and the [command reference](https://firewalld.org/documentation/man-pages/firewall-cmd.html).

### Verify isolation

Check forwarding state without changing it:

```bash
sysctl net.ipv4.ip_forward
```

With forwarding disabled, the kernel blocks client-to-client routing. The
firewall also protects against forwarding being enabled later. Confirm that
both displays still authenticate and load content.

To test the firewall rather than just the clients' AllowedIPs restriction, use
a test controller with forwarding enabled and two controlled clients. Temporarily
allow each client's tunnel address in the other's WireGuard AllowedIPs and
routes through the controller. New ICMP and TCP flows in both directions must
fail; controller transport and proxy access must still work. Use new connections
because stateful rules may retain existing flows. Restore the clients' original
settings, and repeat the checks after a controller reboot.

## LAN API access

Operators can optionally use the API, dashboard and Swagger UI over a management
LAN. First [configure the listener and TLS](CONFIGURATION.md#lan-api-access).
This example uses controller `192.168.50.10`, management network `192.168.50.0/24`
and interface `eth0` in the `internal` zone. Substitute your values.

[Inspect interface and source bindings](#controller-traffic) to find the zone
that handles the management traffic; unmatched traffic uses the default zone.
Confirm runtime and permanent bindings agree. Private addresses do not
automatically select `internal`; a rule in a zone that does not handle the
traffic has no effect. Do not move interfaces or change the default zone to
follow this example. Any reassignment needs a separate review by the
administrator to preserve SSH and other required services. See the
[predefined zone descriptions](https://firewalld.org/documentation/zone/predefined-zones.html).

Add an IPv4 rich rule restricted to the management source network and the API's
LAN address:

```bash
lan_zone=internal
lan_api_rule='rule family="ipv4" source address="192.168.50.0/24" destination address="192.168.50.10" port port="8443" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone="$lan_zone" --add-rich-rule="$lan_api_rule"
sudo firewall-cmd --check-config
sudo firewall-cmd --reload
sudo firewall-cmd --get-zone-of-interface=eth0
sudo firewall-cmd --zone="$lan_zone" --list-all
sudo firewall-cmd --permanent --zone="$lan_zone" --list-all
```

As above, reconcile runtime and permanent rules before reloading. This rich
rule applies to every interface in its zone when source and destination match.
For strict interface isolation, use a dedicated LAN zone and preserve management
services before moving the interface. Do not substitute `--add-source`: it
assigns the network to a zone for all services. See the
[rich-rule reference](https://firewalld.org/documentation/man-pages/firewalld.richlanguage.html).

Remove broader API allowances, including LAN-zone port openings, services and
rich rules. The rule above cannot override them or a zone target of `ACCEPT`.
Enforce the same restrictions with other firewall managers. Keep transport and
content-proxy ports on WireGuard; LAN dashboard access does not need them.

Run the [LAN verification steps](CONFIGURATION.md#lan-api-access) from an
allowed workstation. Direct LAN access to `8443` must fail from outside the
permitted network. Repeat the permitted-client check after a controller reboot.

## Remove LAN API access

First restore `server.listen: 127.0.0.1:8443`, restart `neodse-server` and run
`sudo neodse-server unlock`, as described in
[LAN API configuration](CONFIGURATION.md#lan-api-access).
Then remove the firewall rule, using the same zone and exact rule as when you
added it:

```bash
lan_zone=internal
lan_api_rule='rule family="ipv4" source address="192.168.50.0/24" destination address="192.168.50.10" port port="8443" protocol="tcp" accept'
sudo firewall-cmd --permanent --zone="$lan_zone" --remove-rich-rule="$lan_api_rule"
sudo firewall-cmd --check-config
sudo firewall-cmd --reload
sudo firewall-cmd --zone="$lan_zone" --list-all
```

## Verify firewall access

Inspect the effective rules with the active firewall manager, then test new
connections:

- Confirm administrator access still works and displays authenticate and load
  content through the controller's tunnel transport and proxy services.
- From a LAN/public-side test host, confirm controller transport and proxy ports
  cannot be reached through its LAN/public address. The API must remain local
  unless restricted management LAN access has been configured.
- For optional LAN API access, test both an allowed management workstation and
  a host outside the allowed sources, following [LAN verification](#lan-api-access).
- Verify client-to-client forwarding isolation using the controlled test
  described in [Verify isolation](#verify-isolation).

Repeat after a controller reboot. With firewalld, confirm the tunnel still
belongs to `neodse-vpn`, the isolation policy is active, and runtime and permanent
rules enforce the same restrictions.
