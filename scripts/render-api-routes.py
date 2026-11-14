#!/usr/bin/env python3
# File purpose: Rebuilds the API route map from the server's registered methods and capabilities.
# Copyright (c) 2026 RealisLux
# SPDX-License-Identifier: MIT
# Project: https://github.com/RealisLux/NeoDSE

"""Render neodse-api-routes.svg; fail if the route registry outgrows the map."""

from html import escape
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parent.parent
PREFIX = "/api/v1"
COLORS = {
    "View": "#2563eb", "Content": "#15803d", "Alert": "#7c3aed",
    "CEC": "#c2410c", "System": "#be123c", "Accounts": "#64748b",
}


ICONS = {
    'monitor': '<rect x="0" y="0" width="37" height="25" rx="2" fill="none" stroke="currentColor" stroke-width="4" /><path d="M18 25V33M10 34H27" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round" stroke-linecap="round" />',
    'content': '<path d="M4 0H26L38 12V38H4Z" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" /><path d="M26 0V12H38" fill="none" stroke="#ffffff" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" /><path d="M14 15L27 23L14 31Z" fill="#ffffff" stroke="#ffffff" stroke-width="1" stroke-linejoin="round" stroke-linecap="round" />',
    'calendar': '<rect x="1" y="3" width="36" height="31" rx="3" fill="none" stroke="currentColor" stroke-width="3" /><path d="M1 12H37M10 0V7M28 0V7" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" /><rect x="8" y="17" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" /><rect x="17" y="17" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" /><rect x="26" y="17" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" /><rect x="8" y="26" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" /><rect x="17" y="26" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" /><rect x="26" y="26" width="4" height="4" rx="0" fill="currentColor" stroke="none" stroke-width="2" />',
    'gear': '<polygon points="37.00,20.00 41.83,22.61 41.32,25.18 40.48,27.65 39.32,30.00 33.90,29.13 32.61,30.61 34.18,35.87 32.00,37.32 29.65,38.48 27.18,39.32 23.96,34.87 22.00,35.00 19.39,39.83 16.82,39.32 14.35,38.48 12.00,37.32 12.87,31.90 11.39,30.61 6.13,32.18 4.68,30.00 3.52,27.65 2.68,25.18 7.13,21.96 7.00,20.00 2.17,17.39 2.68,14.82 3.52,12.35 4.68,10.00 10.10,10.87 11.39,9.39 9.82,4.13 12.00,2.68 14.35,1.52 16.82,0.68 20.04,5.13 22.00,5.00 24.61,0.17 27.18,0.68 29.65,1.52 32.00,2.68 31.13,8.10 32.61,9.39 37.87,7.82 39.32,10.00 40.48,12.35 41.32,14.82 36.87,18.04" fill="currentColor" /><circle cx="22" cy="20" r="7" fill="white" />',
    'broadcast': '<circle cx="20" cy="20" r="5" fill="currentColor" /><path d="M11 8Q0 20 11 32M29 8Q40 20 29 32M5 2Q-12 20 5 38M35 2Q52 20 35 38" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" />',
    'accounts': '<circle cx="20" cy="8" r="7" fill="currentColor" /><rect x="13" y="18" width="14" height="17" rx="4" fill="currentColor" stroke="none" stroke-width="2" /><circle cx="3" cy="14" r="5" fill="currentColor" /><rect x="-2" y="22" width="10" height="17" rx="4" fill="currentColor" stroke="none" stroke-width="2" /><circle cx="37" cy="14" r="5" fill="currentColor" /><rect x="32" y="22" width="10" height="17" rx="4" fill="currentColor" stroke="none" stroke-width="2" />',
    'document': '<rect x="3" y="0" width="31" height="39" rx="3" fill="none" stroke="currentColor" stroke-width="3" /><path d="M11 10H26M11 18H26M11 26H26" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round" stroke-linecap="round" />',
    'shield': '<path d="M20 0L38 7V21Q34 34 20 40Q6 34 2 21V7Z" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round" stroke-linecap="round" /><path d="M11 19L18 26L29 13" fill="none" stroke="currentColor" stroke-width="4" stroke-linejoin="round" stroke-linecap="round" />',
    'dispatch': '<path d="M0 19L40 0L29 39L19 27L12 34L13 24Z" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" /><path d="M13 24L34 6" fill="none" stroke="#ffffff" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />',
    'results': '<rect x="0" y="24" width="8" height="14" rx="2" fill="currentColor" stroke="none" stroke-width="2" /><rect x="13" y="13" width="8" height="25" rx="2" fill="currentColor" stroke="none" stroke-width="2" /><rect x="26" y="1" width="8" height="37" rx="2" fill="currentColor" stroke="none" stroke-width="2" />',
    'alert': '<path d="M5 29h30l-4-6V14a11 11 0 0 0-22 0v9Zm10 6a5 5 0 0 0 10 0M20 0v3" fill="none" stroke="currentColor" stroke-width="3" stroke-linejoin="round" stroke-linecap="round"/>',
}


def registered_routes():
    """Read each method and its authorization capability from the Go registry."""
    source = (ROOT / "internal/server/routes.go").read_text()
    methods = {"Get": "GET", "Post": "POST", "Put": "PUT", "Delete": "DELETE"}
    routes = {}
    for path, block in re.findall(
        r's\.registerAPIPath\(\w+, "([^"]+)", map\[string\]apiRoute\{(.*?)\n\t\}\)',
        source, re.S,
    ):
        for method, capability in re.findall(
            r'http\.Method(\w+):\s*\{capability: cap(\w+)', block
        ):
            routes[methods[method], path.removeprefix(PREFIX)] = capability
    if not routes:
        raise ValueError("No API registrations found")
    return routes


def text(x, y, value, size=17, color="#0f172a", weight=400, mono=False, anchor="start"):
    """Build an escaped label with consistent typography."""
    family = "DejaVu Sans Mono, monospace" if mono else "DejaVu Sans, Arial, sans-serif"
    return (f'<text x="{x}" y="{y}" font-family="{family}" font-size="{size}" '
            f'fill="{color}" font-weight="{weight}" text-anchor="{anchor}">'
            f'{escape(value)}</text>')


def rect(x, y, width, height, fill, stroke="none", radius=14):
    """Build a rounded card or method pill."""
    return (f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
            f'rx="{radius}" fill="{fill}" stroke="{stroke}" stroke-width="2"/>')


def icon(name, x, y, color, scale=0.7):
    """Place one of the route map's original icons at a consistent size."""
    return (f'<use href="#icon-{name}" transform="translate({x} {y}) scale({scale})" '
            f'color="{color}" aria-hidden="true"/>')


def render():
    """Render all authenticated operations exactly once, plus public liveness."""
    routes = registered_routes()
    seen = set()
    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="2400" height="1550" '
        'viewBox="0 0 2400 1550" role="img" aria-labelledby="api-title api-desc">',
        '<title id="api-title">NeoDSE API routes and request flow</title>',
        '<desc id="api-desc">All control API methods grouped by capability, including '
        'screen borders, serial peripherals and supported broadcasts. The request flow '
        'shows bearer authentication, role and agent scope checks and asynchronous results. '
        'Public process liveness is separate from authenticated readiness.</desc>',
        '<defs>' + ''.join(f'<g id="icon-{name}">{markup}</g>'
                          for name, markup in ICONS.items()) + '</defs>',
        rect(0, 0, 2400, 1550, "#ffffff", radius=0),
        text(24, 65, "NeoDSE API routes and request flow", 52, weight=700),
        text(26, 103, "Methods and role capabilities from internal/server/routes.go · Endpoint contracts: internal/swagger/openapi.yaml", 19, "#475569"),
    ]

    def card(x, y, title, subtitle, capability, rows):
        color = COLORS[capability]
        height = 66 + 46 * len(rows)
        heading_icon = {
            "SESSION AND MONITORING": "monitor", "CONTENT CONTROL": "content",
            "SCHEDULING": "calendar", "ADMINISTRATION": "accounts",
            "DEVICE AND HOST CONTROL": "gear", "ALERTS AND PERIPHERALS": "alert",
            "BROADCAST": "broadcast",
        }[title]
        out.extend((rect(x, y, 880, height, "#f8fafc", color),
                    icon(heading_icon, x + 20, y + 11, color),
                    text(x + 62, y + 32, title, 24, color, 700),
                    text(x + 20, y + 54, subtitle, 15, "#475569")))
        for index, (method, path, description) in enumerate(rows):
            key = method, path
            if key in seen or key not in routes:
                raise ValueError(f"Duplicate or unregistered route: {key}")
            seen.add(key)
            row_y = y + 66 + 46 * index
            role_color = COLORS[routes[key]]
            out.extend((
                f'<g data-method="{method}" data-path="{escape(PREFIX + path, quote=True)}">',
                rect(x + 12, row_y, 856, 44, "#f1f5f9" if index % 2 == 0 else "#ffffff", radius=7),
                rect(x + 20, row_y + 4, 88, 31, role_color, radius=7),
                text(x + 64, row_y + 26, method, 16, "#ffffff", 700, anchor="middle"),
                text(x + 124, row_y + 17, path, 16, weight=600, mono=True),
                text(x + 124, row_y + 36, description, 14, "#475569"),
                '</g>',
            ))
        return y + height + 18

    agent = "/agents/{agentId}"
    broadcast = "/agents/broadcast"
    account = "/service-accounts"
    y = card(24, 130, "SESSION AND MONITORING", "Read access: any authenticated role; agent and event scope still apply", "View", [
        ("GET", "/session", "Service-account identity and assigned roles"),
        ("GET", "/agents", "List the agents accessible to this account"),
        ("GET", agent, "Last reported agent status and authentication state"),
        ("GET", agent + "/state", "Controller-authoritative desired content and revision"),
        ("GET", agent + "/display/status", "Last reported HDMI-CEC display status"),
        ("GET", agent + "/display/stream", "Read-only live stream; one viewer per display"),
        ("GET", "/system/status", "Authenticated database and transport readiness"),
        ("GET", "/events/{eventId}", "Durable delivery outcomes and receipts; requires scope over every target"),
    ])
    y = card(24, y, "CONTENT CONTROL", "Role: content_manager · Single agent within account scope", "Content", [
        ("PUT", agent + "/playlist", "Replace the saved playlist and authorize its web destinations"),
        ("DELETE", agent + "/playlist", "Clear the saved playlist and restore the waiting screen"),
        ("POST", agent + "/playlist/sync", "Update saved playlist timing"),
        ("POST", agent + "/playlist/reload", "Reload active pages without changing playback timing"),
        ("POST", agent + "/proxy/revoke", "Revoke content-proxy permissions"),
    ])
    y = card(24, y, "SCHEDULING", "Read: any authenticated role · Write: administrator · Scoped to one agent", "Accounts", [
        ("GET", agent + "/schedules", "Read the optional weekly screen-power schedule"),
        ("POST", agent + "/schedules", "Create or replace the weekly schedule"),
        ("DELETE", agent + "/schedules", "Delete the weekly schedule"),
    ])
    card(24, y, "ADMINISTRATION", "Role: administrator · Administrators can also use every other operation", "Accounts", [
        ("GET", account, "List service accounts"),
        ("POST", account, "Create an account and issue a bearer token"),
        ("GET", account + "/{accountId}", "Read one service account"),
        ("PUT", account + "/{accountId}", "Replace account metadata, roles and agent scope"),
        ("DELETE", account + "/{accountId}", "Delete the account and revoke its token"),
        ("POST", account + "/{accountId}/rotate-token", "Replace the account's bearer token"),
    ])
    y = card(1496, 130, "DEVICE AND HOST CONTROL", "Roles: cec_manager for display actions · system_operator for host actions", "System", [
        ("POST", agent + "/{operation}", "restart (renderer), reboot or shutdown (Linux host)"),
        ("POST", agent + "/display/{operation}", "on / off / active / mute / volup / voldown via HDMI-CEC"),
        ("POST", agent + "/display/volume", "Set the absolute HDMI-CEC audio volume"),
    ])
    y = card(1496, y, "ALERTS AND PERIPHERALS", "Role: alert_operator · Independent commands for an online, authenticated agent", "Alert", [
        ("POST", agent + "/banner", "Message, severity and duration; info / warning / critical"),
        ("POST", agent + "/border", "Screen border: severity and duration; independent of the banner"),
        ("POST", agent + "/sound/{profile}", "Notification audio: info / warning / critical"),
        ("POST", agent + "/serial", "Structured beacon, buzzer, relay, device-info or status action"),
    ])
    y = card(1496, y, "BROADCAST", "Same role as the matching single-agent action · Targets come from account scope", "Alert", [
        ("PUT", broadcast + "/playlist", "Replace playlists across permitted agents"),
        ("DELETE", broadcast + "/playlist", "Clear playlists across permitted agents"),
        ("POST", broadcast + "/playlist/sync", "Synchronize saved playlist timing"),
        ("POST", broadcast + "/playlist/reload", "Reload active playlist pages"),
        ("POST", broadcast + "/display/{operation}", "on / off / active / mute / volup / voldown via HDMI-CEC"),
        ("POST", broadcast + "/display/volume", "Set the absolute HDMI-CEC audio volume"),
        ("POST", broadcast + "/banner", "Send a message banner"),
        ("POST", broadcast + "/border", "Highlight scoped screens with a screen border"),
        ("POST", broadcast + "/sound/{profile}", "Play info / warning / critical notification audio"),
        ("POST", broadcast + "/serial", "Send a structured peripheral action"),
        ("POST", broadcast + "/{operation}", "restart / reboot / shutdown; per-target outcomes"),
    ])
    if seen != routes.keys():
        raise ValueError(f"Routes missing from diagram: {routes.keys() - seen}")

    out.extend((rect(932, 130, 536, 100, "#eff6ff"),
                text(1200, 174, PREFIX, 38, weight=700, mono=True, anchor="middle"),
                text(1200, 209, "All listed control routes use this prefix.", 18, anchor="middle")))
    steps = [
        ("HTTPS request", "Authorization: Bearer <token>"),
        ("Authenticate", "Resolve the service-account identity."),
        ("Authorize the operation", "Check the required role capability."),
        ("Check agent scope", "Verify single-agent targets exist.", "Derive broadcast targets from scope."),
        ("Validate and dispatch", "Save desired content or queue actions."),
        ("Deliver to displays", "Transient actions need online agents.", "Saved content can wait for reconnect."),
        ("Accepted asynchronous work", "202 + event_id", "Acceptance does not confirm execution."),
        ("Retrieve outcomes", "GET /events/{eventId}", "Check delivery state and agent receipts."),
    ]
    step_icons = ("monitor", "document", "shield", "accounts", "gear",
                  "dispatch", "document", "results")
    for index, lines in enumerate(steps):
        top = 254 + index * 112
        out.extend((rect(932, top, 536, 96, "#eff6ff" if index % 2 == 0 else "#f5f3ff"),
                    f'<circle cx="968" cy="{top+45}" r="23" fill="#0f172a"/>',
                    text(968, top + 53, str(index + 1), 24, "#ffffff", 700, anchor="middle"),
                    icon(step_icons[index], 1001, top + 33, "#0f172a", 0.65),
                    text(1040, top + 29, lines[0], 20, weight=700)))
        for line_index, line in enumerate(lines[1:]):
            out.append(text(1040, top + 54 + line_index * 23, line, 17))
        if index < len(steps) - 1:
            out.append(f'<path d="M1199 {top+99}v9m-6-5 6 6 6-6" '
                       'fill="none" stroke="#2563eb" stroke-width="3"/>')

    out.extend((rect(932, 1174, 536, 122, "#f1f5f9"),
                text(952, 1206, "PUBLIC PROCESS LIVENESS", 21, "#475569", 700),
                '<g data-method="GET" data-path="/healthz">',
                text(952, 1240, "GET /healthz", 22, weight=600, mono=True), '</g>',
                text(952, 1275, "No bearer token; separate from readiness.", 17),
                rect(932, 1314, 536, 146, "#f8fafc", "#cbd5e1"),
                text(952, 1348, "SCOPE AND ROLES", 21, "#475569", 700),
                text(952, 1380, "Method colors identify the required capability.", 17),
                text(952, 1410, "Administrator grants every capability and scope.", 17),
                text(952, 1440, "Events require access to all their target agents.", 17),
                rect(1496, y, 880, 1460 - y, "#eff6ff"),
                icon("document", 1516, y + 11, "#2563eb"),
                text(1558, y + 34, "DELIVERY AND RESULTS", 23, "#2563eb", 700),
                text(1516, y + 68, "Playlist updates persist while agents are offline; only the latest content is applied.", 17),
                text(1516, y + 98, "Banners, borders, audio, hardware and host actions require an online agent.", 17),
                text(1516, y + 128, "Broadcasts report results per target; failures can differ between displays.", 17),
                text(1516, y + 158, "A 202 response accepts work. Poll the event to inspect delivery and execution.", 17),
                text(1516, y + 188, "Uncertain delivery may have executed; it is never automatically retried.", 17)))
    out.append(rect(24, 1482, 2352, 48, "#eff6ff"))
    legend = [("View", "read / view"), ("Content", "content_manager"), ("CEC", "cec_manager"),
              ("Alert", "alert_operator"), ("System", "system_operator"), ("Accounts", "administrator")]
    for index, (capability, label) in enumerate(legend):
        x = 66 + index * 392
        out.extend((f'<circle cx="{x}" cy="1506" r="12" fill="{COLORS[capability]}"/>',
                    text(x + 24, 1512, label, 19)))
    out.append('</svg>')
    (ROOT / "neodse-api-routes.svg").write_text("\n".join(out) + "\n")
    print(f"Rendered neodse-api-routes.svg: {len(seen)} authenticated methods + public /healthz.")


if __name__ == "__main__":
    render()
