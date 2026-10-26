// File purpose: Labels dashboard operations, checks their roles and reports durable controller outcomes.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// eventOutcomes returns the controller's authoritative per-target outcomes,
// which take precedence over incomplete receipt histories.
export function eventOutcomes(event) {
  return event.deliveries ?? [];
}

// terminalOutcome reports whether an event target has reached a final state.
export const terminalOutcome = (outcome) =>
  [
    "accepted",
    "completed",
    "failed",
    "expired",
    "unsupported",
    "rejected",
  ].includes(outcome.status);

// operationLabel maps an API operation to its user-facing activity description.
export const operationLabel = (path, method = "POST") =>
  ({
    "display/on": "Power on",
    "display/off": "Power off",
    "display/active": "Select active HDMI source",
    playlist: method === "DELETE" ? "Restore waiting screen" : "Publish content",
    "playlist/reload": "Reload web content",
    "playlist/sync": "Synchronize playback",
    "sound/info": "Info sound",
    "sound/warning": "Warning sound",
    "sound/critical": "Critical sound",
    "display/mute": "Mute audio",
    "display/volup": "Increase volume",
    "display/voldown": "Decrease volume",
    banner: "Visual banner",
    serial: "Peripheral command",
    restart: "Restart display UI",
    reboot: "Reboot agent",
    shutdown: "Shut down agent",
  })[path];

// canOperate checks whether the active roles authorize a dashboard operation.
export function canOperate(roles, path) {
  if (roles.has("administrator")) return true;
  if (/^(restart|reboot|shutdown)$/.test(path))
    return roles.has("system_operator");
  if (/^display\//.test(path)) return roles.has("cec_manager");
  if (/^(sound\/|serial$)/.test(path)) return roles.has("alert_io_operator");
  return roles.has("content_manager");
}
