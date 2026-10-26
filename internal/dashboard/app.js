// File purpose: Coordinates dashboard controls and cancellable API operations.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

import { createAPI, isCancelled } from "./api.js";
import { displayFrames } from "./display.js";
import {
  eventOutcomes,
  terminalOutcome,
  canOperate,
  operationLabel,
} from "./events.js";
const apiClient = createAPI(undefined, () => {
  logout();
  notify("Authentication failed. Connect again.", true);
});
const visibleRefreshInterval = 30000;
// Playlists with several pages mirror the controller's page-time bounds; a
// single page has no interval.
const minPlaylistInterval = 10;
const maxPlaylistInterval = 86400;
// playlistSummary describes rotation only when there is more than one page.
function playlistSummary(content) {
  const count = (content.urls || []).length;
  if (count === 1) return "1 page, shown continuously";
  return `${count} pages · each shown ${content.interval}s`;
}
let roles = new Set();
let token = "",
  agents = [],
  selected = null,
  broadcast = false,
  schedule = null,
  scheduleReady = false,
  scheduleDirty = false,
  scheduleMutation = null,
  refreshTimer,
  toastTimer;
let displayRequest = null;
let displayStopPromise = Promise.resolve();
let displayGeneration = 0;
let pendingSelection = null;
// Each panel applies only its newest read, including reloads after operator edits.
let stateLoadRevision = 0,
  cecLoadRevision = 0,
  scheduleLoadRevision = 0;

// $ resolves a dashboard element by its unique identifier.
const $ = (id) => document.getElementById(id);
const api = apiClient.request;

// time formats a controller timestamp for the user's locale.
const time = (value) =>
  value
    ? new Intl.DateTimeFormat(undefined, {
        hour: "2-digit",
        minute: "2-digit",
        month: "short",
        day: "numeric",
      }).format(new Date(value))
    : "Unknown";

// uptime converts a duration in seconds into a compact two-part label.
const uptime = (seconds) => {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "uptime unknown";
  const units = [
    [86400, "d"],
    [3600, "h"],
    [60, "m"],
  ];
  let remaining = Math.floor(value),
    parts = [];
  for (const [size, label] of units) {
    if (remaining >= size) {
      parts.push(`${Math.floor(remaining / size)}${label}`);
      remaining %= size;
    }
    if (parts.length === 2) break;
  }
  return `uptime ${parts.length ? parts.join(" ") : `${remaining}s`}`;
};

// online requires both controller presence and an authenticated agent session.
const online = (agent) => agent?.status === "online" && agent.is_authenticated;

// renderSelectedAgent synchronizes the selected display header with fleet state.
function renderSelectedAgent() {
  if (!selected) return;
  $("selected-title").textContent = selected.agent_id;
  $("selected-subtitle").textContent =
    `${selected.friendly_name ? `${selected.friendly_name} · ` : ""}${selected.hostname || "Hostname unknown"} · ${uptime(selected.uptime_seconds)} · last seen ${time(selected.last_seen)}`;
  $("selected-status").className =
    `status ${online(selected) ? "online" : "offline"}`;
  $("selected-status").innerHTML =
    `<span class="dot"></span>${online(selected) ? "Online" : "Offline"}`;
}

// targetPath resolves an operation against the selected display or broadcast scope.
const targetPath = (path) =>
  broadcast
    ? `/api/v1/agents/broadcast/${path}`
    : selected
      ? `/api/v1/agents/${encodeURIComponent(selected.agent_id)}/${path}`
      : null;

// safe escapes untrusted controller values before inserting them into HTML.
const safe = (value) =>
  String(value || "").replace(
    /[&<>"']/g,
    (c) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#039;",
      })[c],
  );

// sentence normalizes a message for notifications and status text.
const sentence = (value) => {
  const text = String(value || "").trim();
  return text ? text[0].toUpperCase() + text.slice(1) : "";
};

// notify displays one temporary dashboard notification.
function notify(message, error = false) {
  const el = $("toast");
  el.textContent = sentence(message);
  el.className = `toast show${error ? " error" : ""}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (el.className = "toast"), 6200);
}

// activity prepends one bounded entry to the browser-session activity list.
function activity(text) {
  const box = $("activity");
  const empty = box.querySelector(".empty");
  if (empty) empty.remove();
  const item = document.createElement("div");
  item.className = "activity-item";
  item.innerHTML = `<span class="dot"></span><div><p>${safe(sentence(text))}</p><time>${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</time></div>`;
  box.prepend(item);
  while (box.children.length > 50) box.lastElementChild.remove();
  return item;
}

// trackEvent polls a controller event until every target reaches a final outcome.
async function trackEvent(eventID, target, operation) {
  const item = activity(`${operation} accepted by controller for ${target}`);
  for (let attempt = 0; attempt < 30; attempt += 1) {
    await apiClient.delay(2000);
    try {
      const event = await (
        await api(`/api/v1/events/${encodeURIComponent(eventID)}`)
      ).json();
      const receipts = eventOutcomes(event);
      if (!receipts.length) continue;
      const summary = receipts
        .map(
          (receipt) =>
            `${receipt.agent_id}: ${sentence(receipt.status)}${receipt.error || receipt.reason ? ` — ${sentence(receipt.error || receipt.reason)}` : ""}`,
        )
        .join(" · ");
      item.querySelector("p").textContent = `${operation} · ${summary}`;
      item.querySelector("time").textContent = time(event.updated_at);
      if (receipts.every(terminalOutcome)) return;
    } catch (_) {
      return;
    }
  }
}

// renderAgents rebuilds the selector from the authorized fleet snapshot.
function renderAgents() {
  const box = $("agents");
  $("agent-count").textContent =
    `${agents.length} display${agents.length === 1 ? "" : "s"} available`;
  if (!agents.length) {
    box.innerHTML =
      '<div class="empty">No displays are available to this token.</div>';
    return;
  }
  box.innerHTML = agents
    .map(
      (a) =>
        `<button class="agent ${selected && selected.agent_id === a.agent_id ? "selected" : ""}" data-id="${safe(a.agent_id)}" type="button"><span class="agent-avatar">${safe(a.agent_id.slice(0, 2).toUpperCase())}</span><span class="agent-info"><span class="agent-name">${safe(a.agent_id)}</span><span class="agent-meta">${safe(a.hostname || "Hostname unknown")} · ${safe(a.version || "version unknown")}</span></span><span class="agent-state"><span class="status ${online(a) ? "online" : "offline"}"><span class="dot"></span>${online(a) ? "Online" : "Offline"}</span><span class="agent-meta">${time(a.last_seen)}</span></span></button>`,
    )
    .join("");
  box
    .querySelectorAll("[data-id]")
    .forEach((el) =>
      el.addEventListener("click", () =>
        select(agents.find((a) => a.agent_id === el.dataset.id)),
      ),
    );
}

// renderMetrics summarizes online and attention counts for the current fleet.
function renderMetrics() {
  const up = agents.filter(online).length;
  $("total").textContent = agents.length;
  $("online").textContent = up;
  $("attention").textContent = agents.length - up;
}

// renderCECStatus keeps the compact power indicator synchronized in both previews.
function renderCECStatus(state, summary, detail) {
  document.querySelectorAll("[data-cec-badge]").forEach((badge) => {
    badge.dataset.state = state;
    badge.querySelector("[data-cec-summary]").textContent = summary;
    badge.querySelector("[data-cec-detail]").textContent = detail;
    badge.setAttribute("aria-label", `HDMI-CEC: ${summary}. ${detail}`);
  });
}

// resetSchedule restores the schedule form to its unloaded defaults.
function resetSchedule() {
  schedule = null;
  scheduleReady = false;
  scheduleDirty = false;
  scheduleMutation = null;
  for (const id of ["power-on", "power-off"]) $(id).value = $(id).defaultValue;
  $("schedule-enabled").checked = $("schedule-enabled").defaultChecked;
  $("schedule-reminder").checked = $("schedule-reminder").defaultChecked;
  document.querySelectorAll("#schedule-days input").forEach((input) => {
    input.checked = input.defaultChecked;
  });
}

// clearSelectedView removes all state belonging to the previous display.
function clearSelectedView() {
  stopDisplay();
  resetSchedule();
  $("selected-title").textContent = "Select a display";
  $("selected-subtitle").textContent = "Choose a display from the fleet list";
  $("selected-status").className = "status offline";
  $("selected-status").innerHTML = '<span class="dot"></span>—';
  $("content-title").textContent = "Content state";
  $("content-detail").textContent =
    "Choose a display to inspect its desired content.";
  renderCECStatus("unknown", "CEC · —", "Select a display to view its CEC status.");
  $("schedule-note").textContent =
    "Select a display to edit its weekly schedule";
  setTargetControls();
}

// select switches target scope and loads all display-specific panels together.
async function select(agent) {
  apiClient.resetTarget();
  const stopped = stopDisplay();
  const transition = displayGeneration;
  pendingSelection = transition;
  await stopped;
  if (pendingSelection === transition) pendingSelection = null;
  if (transition !== displayGeneration || !token) return;
  // A refresh may have changed fleet state or loaded the old target during cleanup.
  apiClient.resetTarget();
  selected = agents.find((current) => current.agent_id === agent.agent_id) || null;
  if (!selected) {
    clearSelectedView();
    renderAgents();
    return;
  }
  resetSchedule();
  renderAgents();
  renderSelectedAgent();
  setTargetControls();
  $("content-title").textContent = "Loading content state…";
  $("content-detail").textContent =
    "Retrieving controller-authoritative configuration.";
  renderCECStatus("unknown", "CEC · Loading…", "Retrieving display status.");
  await Promise.all([
    loadState(),
    loadSchedule(),
    loadCECStatus(agent.agent_id),
  ]);
  if (selected?.agent_id === agent.agent_id && online(selected) && !displayRequest) startDisplay(agent.agent_id);
}

// stopDisplay cancels capture and removes the canvas belonging to the current view.
function stopDisplay() {
  displayGeneration += 1;
  collapseDisplay();
  const request = displayRequest;
  displayRequest = null;
  request?.controller.abort();
  const screen = $("screen-content");
  if (screen) screen.innerHTML = '<div class="screen-empty"><strong>No live view</strong><span>Select an online display to connect.</span></div>';
  if (request) displayStopPromise = request.finished;
  return displayStopPromise;
}

// startDisplay reads JPEG frames for the lifetime of one authenticated GET request.
async function startDisplay(agentID) {
  if (displayRequest) return;
  const generation = ++displayGeneration;
  await displayStopPromise;
  if (generation !== displayGeneration || selected?.agent_id !== agentID || broadcast || !token || !online(selected)) return;
  const screen = $("screen-content");
  screen.innerHTML = '<div class="screen-empty"><strong>Connecting…</strong><span>Opening the read-only display stream.</span></div>';
  let finish;
  const request = { controller: new AbortController(), finished: new Promise(resolve => { finish = resolve; }) };
  displayRequest = request;
  let reason = "The display stream ended.";
  try {
    const response = await api(`/api/v1/agents/${encodeURIComponent(agentID)}/display/stream`, { signal: request.controller.signal });
    if (response.headers.get("Content-Type") !== "application/octet-stream" || !response.body)
      throw new Error("Invalid display stream response.");
    const canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img");
    canvas.setAttribute("aria-label", `Read-only live display for ${agentID}`);
    const context = canvas.getContext("2d", { alpha: false });
    if (!context) throw new Error("Canvas display rendering is unavailable.");
    let receivedFrame = 0;
    let displayedFrame = 0;
    const pending = new Set();

    // drawFrame releases every decoded bitmap and ignores stale or reordered frames.
    async function drawFrame(frame, frameNumber) {
      const bitmap = await createImageBitmap(new Blob([frame], { type: "image/jpeg" }));
      try {
        response.check();
        if (displayRequest !== request || generation !== displayGeneration || frameNumber <= displayedFrame) return;
        if (canvas.width !== bitmap.width || canvas.height !== bitmap.height) {
          canvas.width = bitmap.width;
          canvas.height = bitmap.height;
        }
        context.drawImage(bitmap, 0, 0);
        displayedFrame = frameNumber;
        if (!canvas.isConnected) screen.replaceChildren(canvas);
      } finally {
        bitmap.close();
      }
    }

    try {
      for await (const frame of displayFrames(response.body)) {
        response.check();
        if (displayRequest !== request || generation !== displayGeneration) break;
        if (pending.size >= 2) continue;
        const decoding = drawFrame(frame, ++receivedFrame).catch(error => {
          if (!isCancelled(error)) {
            reason = error.message;
            request.controller.abort();
          }
        }).finally(() => pending.delete(decoding));
        pending.add(decoding);
      }
    } finally {
      request.controller.abort();
      await Promise.allSettled(pending);
    }
  } catch (error) {
    if (!isCancelled(error)) reason = error.message;
  } finally {
    request.controller.abort();
    if (displayRequest === request) {
      displayRequest = null;
      screen.innerHTML = `<div class="screen-empty"><strong>Live view disconnected</strong><span>${safe(reason)}</span></div>`;
    }
    finish();
  }
}

// expandDisplay restores the former large preview behavior for the live view.
function expandDisplay() {
  $("screen").classList.add("expanded");
  $("screen").setAttribute("aria-expanded", "true");
  document.body.classList.add("display-expanded");
  $("close-display").focus();
}

// collapseDisplay restores the live view to its dashboard card.
function collapseDisplay() {
  $("screen")?.classList.remove("expanded");
  $("screen")?.setAttribute("aria-expanded", "false");
  document.body.classList.remove("display-expanded");
}

$("screen-content").addEventListener("click", expandDisplay, { capture: true });
$("close-display").addEventListener("click", collapseDisplay);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") collapseDisplay();
});

// loadState renders the controller-authoritative content configuration.
async function loadState(options = {}) {
  if (!selected) return;
  const revision = ++stateLoadRevision;
  try {
    const state = await (
      await api(`/api/v1/agents/${encodeURIComponent(selected.agent_id)}/state`, options)
    ).json();
    if (revision !== stateLoadRevision) return;
    const c = state.content || {};
    $("content-title").textContent =
      c.mode === "playlist"
        ? `Playlist · revision ${state.revision}`
        : `Status page · revision ${state.revision}`;
    $("content-detail").innerHTML =
      c.mode === "playlist"
        ? `${playlistSummary(c)}<br>${(c.urls || []).map((url) => safe(url)).join("<br>")}`
        : "The built-in local status page is active.";
  } catch (e) {
    if (isCancelled(e) || revision !== stateLoadRevision) return;
    $("content-title").textContent = "Content state unavailable";
    $("content-detail").textContent = e.message;
  }
}

// loadCECStatus renders the latest HDMI-CEC capability and power state.
async function loadCECStatus(agentID = selected?.agent_id, options = {}) {
  if (!agentID) return;
  const revision = ++cecLoadRevision;
  try {
    const status = await (
      await api(`/api/v1/agents/${encodeURIComponent(agentID)}/display/status`, options)
    ).json();
    if (revision !== cecLoadRevision || selected?.agent_id !== agentID) return;
    if (!status.enabled) {
      renderCECStatus(
        "disabled",
        "CEC · Disabled",
        "CEC is disabled in this agent configuration.",
      );
      return;
    }
    const power = sentence(status.power_status || "unknown");
    const normalizedPower = String(status.power_status || "unknown").toLowerCase();
    const state = normalizedPower === "on"
      ? "on"
      : ["standby", "off"].includes(normalizedPower)
        ? "standby"
        : "unknown";
    renderCECStatus(
      state,
      `CEC · ${power}`,
      `Last checked ${status.checked_at ? time(status.checked_at) : "never"}`,
    );
  } catch (e) {
    if (isCancelled(e) || revision !== cecLoadRevision) return;
    if (selected?.agent_id === agentID) {
      renderCECStatus("error", "CEC · Unavailable", sentence(e.message));
    }
  }
}

// command submits one target operation and starts durable outcome tracking.
async function command(path, options = {}) {
  const endpoint = targetPath(path);
  if (!endpoint) return null;
  const { recordActivity = true, ...requestOptions } = options;
  const operation =
    operationLabel(path, requestOptions.method) || sentence(path.replaceAll("/", " "));
  const target = broadcast ? "all authorized displays" : selected.agent_id;
  try {
    const res = await api(endpoint, requestOptions);
    const data = res.status === 204 ? {} : await res.json();
    notify(
      data.event_id
        ? `${operation} accepted by controller`
        : `${operation} completed`,
    );
    if (data.event_id && recordActivity)
      trackEvent(data.event_id, target, operation).catch((error) => {
        if (!isCancelled(error)) notify(error.message, true);
      });
    else if (!data.event_id && recordActivity)
      activity(`${operation} completed for ${target}`);
    return data;
  } catch (e) {
    if (isCancelled(e)) return;
    notify(`${operation} failed: ${e.message}`, true);
    return null;
  }
}

// setTargetControls applies scope, role, readiness, and connectivity constraints.
function setTargetControls() {
  const ready = Boolean(selected) || broadcast;
  document
    .querySelectorAll(
      "[data-action], [data-alert], [data-operation], [data-serial-command], #publish, #reload-content, #sync-playback, #send-banner",
    )
    .forEach((el) => {
      const action =
        el.dataset.action ||
        el.dataset.alert ||
        el.dataset.operation ||
        (el.dataset.serialCommand ? "serial" : undefined) ||
        (el.id === "publish" || el.id === "reload-content" || el.id === "sync-playback"
          ? "playlist"
          : "banner");
      const requiresOnline =
        /^(display\/|sound\/|serial$|banner$|restart$|reboot$|shutdown$)/.test(
          action,
        );
      el.disabled =
        !ready ||
        !canOperate(roles, action) ||
        (requiresOnline && !broadcast && !online(selected));
    });
  const scheduleDisabled =
    !selected || broadcast || !scheduleReady || Boolean(scheduleMutation) || !roles.has("administrator");
  $("save-schedule").disabled = scheduleDisabled;
  $("delete-schedule").disabled = scheduleDisabled || !schedule;
  document
    .querySelectorAll("#schedule-panel .schedule-config input")
    .forEach((input) => (input.disabled = scheduleDisabled));
  $("target-single").classList.toggle("active", !broadcast);
  $("target-broadcast").classList.toggle("active", broadcast);
  $("publish-target").textContent = broadcast
    ? "To all authorized displays"
    : "To the selected display";
  $("sync-playback-at").disabled = $("sync-playback").disabled;
  $("agent-detail").classList.toggle("hidden", broadcast);
  $("broadcast-detail").classList.toggle("hidden", !broadcast);
  $("schedule-panel").classList.remove("hidden");
  document
    .querySelectorAll("#schedule-panel .schedule-config")
    .forEach((element) => element.classList.toggle("hidden", broadcast));
  $("schedule-broadcast-note").classList.toggle("hidden", !broadcast);
}

// loadSchedule loads the selected display's optional weekly power schedule.
async function loadSchedule(options = {}) {
  if (!selected) return;
  const revision = ++scheduleLoadRevision;
  resetSchedule();
  setTargetControls();
  $("schedule-note").textContent = "Loading weekly schedule…";
  try {
    const response = await (
      await api(
        `/api/v1/agents/${encodeURIComponent(selected.agent_id)}/schedules`,
        options,
      )
    ).json();
    if (revision !== scheduleLoadRevision) return;
    const values = Array.isArray(response) ? response : [];
    schedule = values[0] || null;
    scheduleReady = true;
    if (schedule) {
      $("power-on").value = schedule.power_on;
      $("power-off").value = schedule.power_off;
      $("schedule-enabled").checked = schedule.enabled;
      $("schedule-reminder").checked = schedule.reminder_enabled !== false;
      document
        .querySelectorAll("#schedule-days input")
        .forEach(
          (input) => (input.checked = schedule.days.includes(input.value)),
        );
      $("schedule-note").textContent = "Weekly schedule loaded";
    } else {
      $("schedule-note").textContent = "No weekly schedule configured";
    }
  } catch (e) {
    if (isCancelled(e) || revision !== scheduleLoadRevision) return;
    $("schedule-note").textContent = sentence(e.message);
  }
  setTargetControls();
}

// saveSchedule validates and persists the weekly schedule form.
async function saveSchedule() {
  if (!selected || broadcast || !scheduleReady || scheduleMutation) return;
  const days = [
    ...document.querySelectorAll("#schedule-days input:checked"),
  ].map((input) => input.value);
  const body = {
    days,
    power_on: $("power-on").value,
    power_off: $("power-off").value,
    enabled: $("schedule-enabled").checked,
    reminder_enabled: $("schedule-reminder").checked,
  };
  if (!days.length) return notify("Select at least one day.", true);
  const path = `/api/v1/agents/${encodeURIComponent(selected.agent_id)}/schedules`;
  const mutation = {};
  scheduleMutation = mutation;
  setTargetControls();
  try {
    await api(path, { method: "POST", body: JSON.stringify(body) });
    notify("Power schedule saved");
    activity(
      `Power schedule saved for ${selected.agent_id || selected.hostname}`,
    );
    await loadSchedule();
  } catch (e) {
    if (isCancelled(e)) return;
    notify(e.message, true);
  } finally {
    if (scheduleMutation === mutation) {
      scheduleMutation = null;
      setTargetControls();
    }
  }
}

// deleteSchedule removes the selected display's weekly power schedule.
async function deleteSchedule() {
  if (
    !selected ||
    !schedule ||
    broadcast ||
    !scheduleReady ||
    scheduleMutation ||
    !confirm("Remove this weekly power schedule?")
  )
    return;
  const mutation = {};
  scheduleMutation = mutation;
  setTargetControls();
  try {
    await api(
      `/api/v1/agents/${encodeURIComponent(selected.agent_id)}/schedules`,
      { method: "DELETE" },
    );
    notify("Power schedule removed");
    activity(
      `Power schedule removed for ${selected.agent_id || selected.hostname}`,
    );
    await loadSchedule();
  } catch (e) {
    if (isCancelled(e)) return;
    notify(e.message, true);
  } finally {
    if (scheduleMutation === mutation) {
      scheduleMutation = null;
      setTargetControls();
    }
  }
}

let refreshRevision = 0;
let refreshController;

// refreshVisibleDetails reloads read-only data for the currently visible target.
async function refreshVisibleDetails(agentID, options) {
  if (!agentID || broadcast || selected?.agent_id !== agentID) return;
  const scheduleIsBeingEdited = scheduleDirty || scheduleMutation || $("schedule-panel").contains(
    document.activeElement,
  );
  await Promise.all([
    loadState(options),
    loadCECStatus(agentID, options),
    scheduleIsBeingEdited ? Promise.resolve() : loadSchedule(options),
  ]);
}

// refresh atomically replaces session, readiness, and fleet state.
async function refresh() {
  if (!token) return;
  refreshController?.abort();
  refreshController = new AbortController();
  const options = { signal: refreshController.signal };
  const revision = ++refreshRevision;
  try {
    const [agentRes, systemRes, sessionRes] = await Promise.all([
      api("/api/v1/agents", options),
      api("/api/v1/system/status", options).catch(() => null),
      api("/api/v1/session", options),
    ]);
    const [nextAgents, session, system] = await Promise.all([
      agentRes.json(),
      sessionRes.json(),
      systemRes ? systemRes.json() : null,
    ]);
    sessionRes.check();
    if (revision !== refreshRevision) return;
    agents = nextAgents;
    roles = new Set(session.roles || []);
    $("connection-role").textContent =
      "Role: " +
      ((session.roles || [])
        .map((role) => sentence(role.replaceAll("_", " ")))
        .join(", ") || "Unknown");
    $("connection-dot").className = "dot online";
    $("connection-label").textContent = "Connected securely";
    $("server").textContent = system?.status === "ready" ? "Ready" : "Degraded";
    $("server-note").textContent = system
      ? `Database: ${system.database ? "ready" : "unavailable"} · Transport: ${system.transport ? "connected" : "disconnected"}`
      : "status unavailable";
    setTargetControls();
    renderMetrics();
    renderAgents();
    if (selected) {
      const replacement = agents.find((a) => a.agent_id === selected.agent_id);
      if (replacement) {
        selected = replacement;
        renderSelectedAgent();
      } else {
        apiClient.resetTarget();
        selected = null;
        clearSelectedView();
      }
      setTargetControls();
      renderAgents();
    }
    if (selected && !broadcast) {
      const agentID = selected.agent_id;
      await refreshVisibleDetails(agentID, options);
      if (options.signal.aborted || revision !== refreshRevision) return;
      if (selected?.agent_id === agentID && !broadcast) {
        if (!online(selected)) {
          if (displayRequest) stopDisplay();
        } else if (!displayRequest && pendingSelection === null) {
          startDisplay(agentID);
        }
      }
    }
  } catch (e) {
    if (isCancelled(e) || revision !== refreshRevision) return;
    $("connection-dot").className = "dot";
    $("connection-label").textContent = "Connection failed";
    $("server").textContent = "Degraded";
    $("server-note").textContent = "Controller readiness unavailable";
    notify(e.message, true);
  }
}
$("connect").addEventListener("click", async () => {
  token = $("token").value.trim();
  apiClient.setToken(token);
  if (!token) return notify("Enter a bearer token to connect.", true);
  $("connect").textContent = "Connecting…";
  $("connect").disabled = true;
  await refresh();
  if ($("connection-label").textContent === "Connected securely") {
    $("setup").classList.add("hidden");
    $("dashboard").classList.remove("hidden");
    clearInterval(refreshTimer);
    refreshTimer = setInterval(refresh, visibleRefreshInterval);
  }
  $("connect").textContent = "Connect";
  $("connect").disabled = false;
});
$("token").addEventListener("keydown", (e) => {
  if (e.key === "Enter") $("connect").click();
});
$("refresh").addEventListener("click", refresh);

// logout invalidates authenticated work and clears account-owned UI state.
function logout() {
  refreshController?.abort();
  refreshController = undefined;
  apiClient.setToken("");
  roles = new Set();
  token = "";
  agents = [];
  selected = null;
  schedule = null;
  broadcast = false;
  clearInterval(refreshTimer);
  clearSelectedView();
  renderAgents();
  renderMetrics();
  for (const id of ["urls", "interval", "banner-message", "banner-duration"])
    $(id).value = $(id).defaultValue;
  $("banner-severity").selectedIndex = 0;
  clearTimeout(toastTimer);
  $("toast").textContent = "";
  $("toast").className = "toast";
  $("server").textContent = "Unknown";
  $("server-note").textContent = "Connect to inspect controller readiness";
  $("token").value = "";
  $("setup").classList.remove("hidden");
  $("dashboard").classList.add("hidden");
  $("connection-dot").className = "dot";
  $("connection-label").textContent = "Not connected";
  $("connection-role").textContent = "Role: —";
  $("activity").innerHTML =
    '<div class="empty">Commands will appear here.</div>';
}
$("logout").addEventListener("click", logout);
document
  .querySelectorAll("[data-docs]")
  .forEach((el) =>
    el.addEventListener("click", () => (window.location.href = "/docs/")),
  );
$("target-single").addEventListener("click", async () => {
  if (!broadcast) return;
  apiClient.resetTarget();
  broadcast = false;
  setTargetControls();
  const stopped = stopDisplay();
  const transition = displayGeneration;
  await stopped;
  if (transition === displayGeneration && !broadcast && selected && online(selected)) {
    startDisplay(selected.agent_id);
  }
});
$("target-broadcast").addEventListener("click", async () => {
  if (broadcast) return;
  apiClient.resetTarget();
  broadcast = true;
  setTargetControls();
  await stopDisplay();
});
// maxPlaylistURLs mirrors the controller's playlist page limit.
const maxPlaylistURLs = 6;
$("publish").addEventListener("click", () => {
  const urls = $("urls")
    .value.split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  if (!urls.length) return notify("Add at least one HTTP(S) playlist URL.", true);
  if (urls.length > maxPlaylistURLs)
    return notify(`A playlist can contain at most ${maxPlaylistURLs} URLs.`, true);
  // A single page does not rotate, so only several pages send an interval.
  const playlist = { urls };
  if (urls.length > 1) {
    playlist.interval = Number($("interval").value);
    if (
      !Number.isInteger(playlist.interval) ||
      playlist.interval < minPlaylistInterval ||
      playlist.interval > maxPlaylistInterval
    )
      return notify(
        `Interval must be between ${minPlaylistInterval} and ${maxPlaylistInterval} seconds.`,
        true,
      );
  }
  command("playlist", {
    method: "PUT",
    body: JSON.stringify(playlist),
  }).then((data) => data && !broadcast && loadState());
});
$("reload-content").addEventListener("click", () =>
  command("playlist/reload", { method: "POST" }),
);
$("sync-playback").addEventListener("click", () => {
  const selectedTime = $("sync-playback-at").value;
  if (!selectedTime)
    return notify("Choose a synchronization time.", true);
  command("playlist/sync", {
    method: "POST",
    body: JSON.stringify({ start_at: selectedTime }),
  }).then((data) => data && !broadcast && loadState());
});
document.querySelectorAll("[data-action]").forEach((el) =>
  el.addEventListener("click", () => {
    const action = el.dataset.action;
    if (
      action === "display/off" &&
      !confirm(
        `Power off ${broadcast ? "all authorized displays" : selected?.hostname || selected?.agent_id}?`,
      )
    )
      return;
    command(action, { method: el.dataset.method || "POST" }).then(
      (data) => data && action === "playlist" && !broadcast && loadState(),
    );
  }),
);
document
  .querySelectorAll("[data-alert]")
  .forEach((el) =>
    el.addEventListener("click", () =>
      command(el.dataset.alert, { method: "POST" }),
    ),
  );
document.querySelectorAll("[data-operation]").forEach((el) =>
  el.addEventListener("click", () => {
    const operation = el.dataset.operation;
    if (
      !confirm(
        `${operation[0].toUpperCase() + operation.slice(1)} ${broadcast ? "all authorized displays" : selected?.hostname || selected?.agent_id}?`,
      )
    )
      return;
    command(operation, { method: "POST" });
  }),
);
// limitBannerMessage counts Unicode characters instead of UTF-16 code units.
function limitBannerMessage(event) {
  if (event.isComposing) return;
  const input = $("banner-message");
  const characters = Array.from(input.value);
  if (characters.length > 256) input.value = characters.slice(0, 256).join("");
}
$("banner-message").addEventListener("input", limitBannerMessage);
$("banner-message").addEventListener("compositionend", limitBannerMessage);
$("send-banner").addEventListener("click", () => {
  const message = $("banner-message").value.trim(),
    duration_seconds = Number($("banner-duration").value);
  if (!message) return notify("Enter a banner message.", true);
  if (Array.from(message).length > 256)
    return notify("Banner messages must be at most 256 characters.", true);
  if (
    !Number.isInteger(duration_seconds) ||
    duration_seconds < 1 ||
    duration_seconds > 300
  )
    return notify("Banner duration must be 1–300 seconds.", true);
  command("banner", {
    method: "POST",
    body: JSON.stringify({
      message,
      severity: $("banner-severity").value,
      duration_seconds,
    }),
  });
});
// sendSerialAction constructs the only permitted dashboard serial payload.
function sendSerialAction(operation, state) {
  const body = { command: operation };
  if (state) body.state = state;
  if (operation === "beacon" && state === "blink") {
    const period = Number($("beacon-period").value);
    if (!Number.isInteger(period) || period < 100 || period > 60000)
      return notify("Blink period must be 100–60000 milliseconds.", true);
    body.period_ms = period;
  }
  if (operation === "relay") {
    const relayID = Number($("relay-id").value);
    if (!Number.isInteger(relayID) || relayID < 1 || relayID > 32)
      return notify("Relay ID must be 1–32.", true);
    body.relay_id = relayID;
  }
  command("serial", { method: "POST", body: JSON.stringify(body) });
}
document.querySelectorAll("[data-serial-command]").forEach((el) =>
  el.addEventListener("click", () =>
    sendSerialAction(el.dataset.serialCommand, el.dataset.serialState),
  ),
);
$("save-schedule").addEventListener("click", saveSchedule);
$("delete-schedule").addEventListener("click", deleteSchedule);
document.querySelectorAll("#schedule-panel .schedule-config input").forEach((input) =>
  input.addEventListener("input", () => { scheduleDirty = true; }),
);
