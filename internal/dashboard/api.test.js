// File purpose: Exercises request cancellation and durable outcome presentation.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

import { test } from "node:test";
import assert from "node:assert/strict";
import { createAPI } from "./api.js";
import {
  eventOutcomes,
  terminalOutcome,
  canOperate,
  operationLabel,
} from "./events.js";

test("changing target aborts pending reads and polling, preserving session reads", async () => {
  const requests = [];
  const api = createAPI(async (path, options) => {
    requests.push({ path, ...options });
    return new Response('{"ok":true}', {
      headers: { "Content-Type": "application/json" },
    });
  });
  api.setToken("session-secret");
  const selected = await api.request("/api/v1/agents/display/state");
  const session = await api.request("/api/v1/session");
  const delay = api.delay(60000);
  const cancelled = assert.rejects(delay, { name: "AbortError" });
  api.resetTarget();
  await cancelled;
  assert.equal(requests[0].signal.aborted, true);
  assert.equal(requests[1].signal.aborted, false);
  await assert.rejects(selected.json(), { name: "AbortError" });
  assert.deepEqual(await session.json(), { ok: true });
});

test("logout and credential replacement invalidate response bodies already in flight", async () => {
  let finishBody;
  const api = createAPI(async () => ({
    ok: true,
    status: 200,
    json: () =>
      new Promise((resolve) => {
        finishBody = resolve;
      }),
  }));
  api.setToken("old");
  const response = await api.request("/api/v1/session");
  const body = response.json();
  api.setToken("new");
  finishBody({ roles: ["administrator"] });
  await assert.rejects(body, { name: "AbortError" });
  assert.throws(response.check, { name: "AbortError" });
});

test("HTTP failures expose structured messages without dropping authentication", async () => {
  const api = createAPI(async (_, options) => {
    assert.equal(options.headers.Authorization, "Bearer secret");
    assert.equal(options.headers["Content-Type"], "application/json");
    return new Response('{"message":"agent offline"}', { status: 409 });
  });
  api.setToken("secret");
  await assert.rejects(
    api.request("/api/v1/agents/display/reboot", {
      method: "POST",
      body: "{}",
    }),
    /agent offline/,
  );
});

test("delivery uncertainty remains visible alongside historical receipts", () => {
  const event = {
    deliveries: [{ agent_id: "display", status: "uncertain" }],
    receipts: [{ agent_id: "display", status: "received" }],
  };
  assert.deepEqual(eventOutcomes(event), event.deliveries);
  assert.equal(terminalOutcome(eventOutcomes(event)[0]), false);
  for (const status of [
    "completed",
    "failed",
    "expired",
    "rejected",
    "unsupported",
    "accepted",
  ])
    assert.equal(terminalOutcome({ status }), true);
});

test("role controls follow controller capabilities", () => {
  const roles = new Set(["content_manager"]);
  assert.equal(canOperate(roles, "playlist"), true);
  for (const operation of [
    "reboot",
    "shutdown",
    "restart",
    "display/mute",
    "display/off",
    "sound/info",
    "serial",
  ])
    assert.equal(canOperate(roles, operation), false);
  assert.equal(canOperate(new Set(["administrator"]), "reboot"), true);
  assert.equal(canOperate(new Set(["system_operator"]), "restart"), true);
});

test("empty deliveries never infer success from historical receipts", () => {
  assert.deepEqual(eventOutcomes({
    deliveries: [],
    receipts: [{ agent_id: "display", status: "completed" }],
  }), []);
  assert.deepEqual(eventOutcomes({}), []);
});

test("audio controls use the current display API routes", () => {
  for (const operation of ["mute", "volup", "voldown"]) {
    const path = `display/${operation}`;
    assert.ok(operationLabel(path));
    assert.equal(canOperate(new Set(["cec_manager"]), path), true);
    assert.equal(canOperate(new Set(["viewer"]), path), false);
  }
});

test("playlist activity distinguishes publication from status-page restore", () => {
  assert.equal(operationLabel("playlist", "PUT"), "Publish content");
  assert.equal(operationLabel("playlist", "DELETE"), "Restore waiting screen");
  assert.equal(operationLabel("serial"), "Peripheral command");
});

test("current authorization failure closes the session; stale failures do not", async () => {
  let complete;
  let closed = 0;
  const api = createAPI(
    () =>
      new Promise((resolve) => {
        complete = resolve;
      }),
    () => {
      closed++;
      api.setToken("");
    },
  );
  api.setToken("old");
  const stale = api.request("/api/v1/session");
  const rejectedStale = assert.rejects(stale, { name: "AbortError" });
  api.setToken("new");
  complete(new Response("{}", { status: 401 }));
  await rejectedStale;
  assert.equal(closed, 0);
  const current = api.request("/api/v1/session");
  const rejectedCurrent = assert.rejects(current, { name: "AbortError" });
  complete(new Response("{}", { status: 401 }));
  await rejectedCurrent;
  assert.equal(closed, 1);
});

test("refresh cancellation does not cancel independent target requests", async () => {
  const requests = [];
  const api = createAPI(async (_path, options) => {
    requests.push(options.signal);
    return new Response("{}");
  });
  const refresh = new AbortController();
  const previous = await api.request("/api/v1/session", {
    signal: refresh.signal,
  });
  const selected = await api.request("/api/v1/agents/display/state");
  refresh.abort();
  assert.equal(requests[0].aborted, true);
  assert.equal(requests[1].aborted, false);
  await assert.rejects(previous.json(), { name: "AbortError" });
  assert.deepEqual(await selected.json(), {});
});

// Stale stream responses must close capture even if fetch resolves after cancellation.
test("a late display stream response is cancelled after target selection changes", async () => {
  let complete;
  let cancelled = false;
  const api = createAPI(() => new Promise(resolve => { complete = resolve; }));
  api.setToken("viewer");
  const pending = api.request("/api/v1/agents/alpha/display/stream");
  const rejected = assert.rejects(pending, { name: "AbortError" });
  api.resetTarget();
  complete(new Response(new ReadableStream({ cancel() { cancelled = true; } })));
  await rejected;
  assert.equal(cancelled, true);
});
