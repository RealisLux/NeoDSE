// File purpose: Exercises real dashboard DOM transitions against controlled API replies.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

(() => {
  const originalFetch = window.fetch;
  const requests = [];
  const serialBodies = [];
  const holds = new Map();
  let degraded = false;
  let offline = false;
  let unauthorized = false;
  let agentsUnavailable = false;
  let hideAlpha = false;
  let outcome = "completed";
  let nextEvent = 0;
  const events = new Map();

  // json creates a JSON response for the controlled browser API.
  const json = (value, status = 200) =>
    new Response(JSON.stringify(value), {
      status,
      headers: { "Content-Type": "application/json" },
    });

  // Browser checks accept destructive-operation confirmations deterministically.
  window.confirm = () => true;

  // The fetch stub models authorization, fleet state, and command outcomes.
  window.fetch = async (path, options = {}) => {
    if (!path.startsWith("/api/")) return originalFetch(path, options);
    const key = `${options.method || "GET"} ${path}`;
    requests.push(key);
    if (path.endsWith("/serial") && options.body)
      serialBodies.push(JSON.parse(options.body));
    if (unauthorized) return json({ message: "unauthorized" }, 401);
    if (holds.has(key)) {
      const hold = holds.get(key);
      holds.delete(key);
      hold.called = true;
      hold.signal = options.signal;
      return hold.promise; // Deliberately ignore abort to test response invalidation.
    }
    const token = options.headers.Authorization;
    const role =
      token === "Bearer content"
        ? "content_manager"
        : token === "Bearer admin" || token === "Bearer empty"
          ? "administrator"
          : token.slice(7);
    if (path === "/api/v1/session") return json({ roles: [role] });
    if (path === "/api/v1/system/status") {
      return degraded
        ? json({ message: "unavailable" }, 503)
        : json({ status: "ready", database: true, transport: true });
    }
    if (path === "/api/v1/agents" && agentsUnavailable)
      return json({ message: "unavailable" }, 503);
    if (path === "/api/v1/agents")
      return json(
        token === "Bearer empty"
          ? []
          : (hideAlpha ? ["beta"] : ["alpha", "beta"]).map((agent_id) => ({
              agent_id,
              friendly_name: agent_id === "alpha" ? "Left lobby" : "",
              hostname: agent_id,
              status: offline ? "offline" : "online",
              is_authenticated: !offline,
              last_seen: new Date().toISOString(),
              uptime_seconds: 60,
            })),
      );
    if (path.startsWith("/api/v1/events/"))
      return json(events.get(path.split("/").at(-1)));
    const target = path.split("/")[4];
    if (path.endsWith("/state"))
      return json({
        revision: target === "alpha" ? 11 : 22,
        content: {
          mode: "playlist",
          urls: [`https://${target}-private.example/`],
        },
      });
    if (path.endsWith("/schedules"))
      return json(
        target === "alpha"
          ? [
              {
                days: ["sunday"],
                power_on: "05:00",
                power_off: "23:00",
                enabled: false,
                reminder_enabled: true,
              },
            ]
          : [],
      );
    if (path.endsWith("/display/stream"))
      return originalFetch("/browser-test/display", options);
    if (path.endsWith("/display/status"))
      return json({ enabled: true, power_status: "on" });
    const event_id = `event-${++nextEvent}`;
    events.set(event_id, {
      deliveries: [{ agent_id: target, status: outcome }],
      updated_at: new Date().toISOString(),
    });
    return json({ event_id }, 202);
  };

  // $ resolves a fixture element by identifier.
  const $ = (id) => document.getElementById(id);

  // pause yields while asynchronous dashboard work progresses.
  const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // assert fails the current check with a focused diagnostic.
  const assert = (condition, message) => {
    if (!condition) throw new Error(message);
  };

  // until waits for an observable condition with a fixed deadline.
  const until = async (condition, description) => {
    const deadline = Date.now() + 5000;
    while (!condition()) {
      if (Date.now() > deadline) throw new Error(`Timed out: ${description}`);
      await pause(10);
    }
  };

  // hold suspends one API response to exercise cancellation and stale replies.
  const hold = (key) => {
    let resolve;
    const entry = {
      called: false,
      promise: new Promise((r) => {
        resolve = r;
      }),
    };

    // release completes the suspended response with a controlled body.
    entry.release = (body, status = 200) => {
      holds.delete(key);
      resolve(json(body, status));
    };
    holds.set(key, entry);
    return entry;
  };

  // login establishes a fresh dashboard session for a requested role token.
  const login = async (token = "admin") => {
    $("logout").click();
    $("token").value = token;
    $("connect").click();
    await until(() => !$("dashboard").classList.contains("hidden"), "login");
  };

  // select chooses a display and waits until its private state is rendered.
  const select = async (id) => {
    const path = `GET /api/v1/agents/${encodeURIComponent(id)}/state`;
    const previous = requests.filter(request => request === path).length;
    document.querySelector(`[data-id="${id}"]`).click();
    await until(
      () => requests.filter(request => request === path).length > previous
        && $("content-detail").textContent.includes(`${id}-private`),
      `select ${id}`,
    );
  };

  // The load handler runs the complete browser regression scenario.
  window.addEventListener("load", async () => {
    const passed = [],
      failures = [];

    // test records one scenario outcome without stopping subsequent checks.
    const test = async (name, run) => {
      try {
        await run();
        passed.push(name);
      } catch (error) {
        failures.push(`${name}: ${error.message}`);
      }
    };
    try {
      await test("readiness and administrator controls", async () => {
        await login();
        await select("alpha");
        assert($("selected-title").textContent === "alpha", "agent ID was replaced");
        assert(
          $("selected-subtitle").textContent.includes("Left lobby"),
          "friendly name was not shown as selection detail",
        );
        assert($("server").textContent === "Ready", "readiness was not shown");
        assert(
          !document.querySelector('[data-operation="reboot"]').disabled,
          "administrator reboot disabled",
        );
      });
      await test("refresh reloads every visible display component", async () => {
        const paths = [
          "GET /api/v1/agents/alpha/state",
          "GET /api/v1/agents/alpha/schedules",
          "GET /api/v1/agents/alpha/display/status",
        ];
        const before = new Map(
          paths.map((path) => [
            path,
            requests.filter((request) => request === path).length,
          ]),
        );
        $("refresh").click();
        await until(
          () =>
            paths.every(
              (path) =>
                requests.filter((request) => request === path).length >
                before.get(path),
            ),
          "visible component refresh",
        );
      });
      await test("refresh preserves an unsaved schedule after focus moves away", async () => {
        await login();
        await select("alpha");
        await until(() => !$("save-schedule").disabled, "loaded schedule");
        $("power-on").value = "06:30";
        $("power-on").dispatchEvent(new Event("input", { bubbles: true }));
        $("schedule-reminder").click();
        const monday = document.querySelector('#schedule-days input[value="monday"]');
        monday.click();
        $("refresh").focus();
        const path = "GET /api/v1/agents/alpha/schedules";
        const count = requests.filter(request => request === path).length;
        const stateCount = requests.filter(request => request === "GET /api/v1/agents/alpha/state").length;
        $("refresh").click();
        await until(() => requests.filter(request => request === "GET /api/v1/agents/alpha/state").length > stateCount,
          "refresh while a schedule draft exists");
        await pause(100);
        assert($("power-on").value === "06:30", "refresh discarded an unsaved power-on time");
        assert(!$("schedule-reminder").checked && monday.checked,
          "refresh discarded unsaved reminder or weekday settings");
        assert(requests.filter(request => request === path).length === count,
          "refresh reloaded the schedule over an unsaved draft");
        $("save-schedule").click();
        await until(() => requests.filter(request => request === path).length > count
          && $("schedule-note").textContent === "Weekly schedule loaded", "saved schedule reconciliation");
        const savedCount = requests.filter(request => request === path).length;
        $("refresh").focus();
        $("refresh").click();
        await until(() => requests.filter(request => request === path).length > savedCount,
          "schedule refresh after saving a draft");
      });
      await test("schedule requests disable edits and failed mutations preserve drafts", async () => {
        await login();
        await select("alpha");
        await until(() => !$("save-schedule").disabled, "loaded schedule");
        const loaded = hold("GET /api/v1/agents/alpha/schedules");
        try {
          $("refresh").focus();
          $("refresh").click();
          await until(() => loaded.called, "pending schedule read");
          assert($("power-on").disabled && $("save-schedule").disabled,
            "schedule remained editable during an outstanding read");
        } finally {
          loaded.release([{ days: ["sunday"], power_on: "05:00", power_off: "23:00", enabled: false, reminder_enabled: true }]);
        }
        await until(() => !$("save-schedule").disabled, "schedule read completed");
        $("power-on").value = "06:45";
        $("power-on").dispatchEvent(new Event("input", { bubbles: true }));
        for (const [method, button] of [["POST", "save-schedule"], ["DELETE", "delete-schedule"]]) {
          const pending = hold(`${method} /api/v1/agents/alpha/schedules`);
          try {
            $(button).click();
            await until(() => pending.called, `pending schedule ${method}`);
            assert($("power-on").disabled && $("schedule-reminder").disabled
              && $("save-schedule").disabled && $("delete-schedule").disabled,
              `schedule remained editable during ${method}`);
            const path = "GET /api/v1/agents/alpha/schedules";
            const count = requests.filter(request => request === path).length;
            const stateCount = requests.filter(request => request === "GET /api/v1/agents/alpha/state").length;
            $("refresh").focus();
            $("refresh").click();
            await until(() => requests.filter(request => request === "GET /api/v1/agents/alpha/state").length > stateCount,
              `refresh during schedule ${method}`);
            assert(requests.filter(request => request === path).length === count,
              `refresh reloaded a pending schedule ${method}`);
          } finally {
            pending.release({ message: `${method} rejected` }, 500);
          }
          await until(() => !$("save-schedule").disabled && $("toast").textContent.includes(`${method} rejected`),
            `failed schedule ${method}`);
          assert($("power-on").value === "06:45", `failed ${method} discarded the draft`);
        }
      });
      await test("live JPEG renders on canvas, expands and clears on logout", async () => {
        await login();
        await select("alpha");
        await until(() => {
          const canvas = $("screen-content").querySelector("canvas");
          return canvas?.width === 8 && canvas.height === 6 &&
            canvas.getContext("2d").getImageData(0, 0, 1, 1).data[3] === 255;
        }, "decoded JPEG from a real HTTP stream");
        const canvas = $("screen-content").querySelector("canvas");
        await until(() => canvas.getContext("2d").getImageData(0, 0, 1, 1).data[0] > 240,
          "next JPEG drawn into the same canvas");
        assert($("screen-content").querySelector("canvas") === canvas, "frame replaced the canvas");
        assert(canvas.getAttribute("role") === "img" && canvas.getAttribute("aria-label").includes("alpha"),
          "live canvas lacks an accessible label");
        $("screen-content").click();
        assert($("screen").classList.contains("expanded"), "display did not expand");
        $("close-display").click();
        assert(!$("screen").classList.contains("expanded"), "display did not close");
        await select("beta");
        await until(() => $("screen-content").querySelector("canvas")?.getAttribute("aria-label").includes("beta"), "replacement display frame");
        document.querySelector('[data-id="alpha"]').click();
        $("logout").click();
        await pause(100);
        assert($("selected-title").textContent === "Select a display", "pending selection survived logout");
        assert(!$("screen-content").querySelector("canvas"), "logout retained a private frame");
        await login();
      });
      await test("logout discards and releases a bitmap decoded late", async () => {
        const originalDecode = window.createImageBitmap;
        let bitmap;
        let release;
        let held = false;
        window.createImageBitmap = async (...args) => {
          if (held) return originalDecode(...args);
          held = true;
          bitmap = await originalDecode(...args);
          await new Promise(resolve => { release = resolve; });
          return bitmap;
        };
        try {
          await login();
          await select("alpha");
          await until(() => release, "pending bitmap decode");
          $("logout").click();
          release();
          await until(() => bitmap.width === 0, "decoded bitmap release");
          assert(!$("screen-content").querySelector("canvas"), "late bitmap restored a private canvas");
        } finally {
          release?.();
          window.createImageBitmap = originalDecode;
        }
        await login();
      });
      await test("schedule belongs to the new target", async () => {
        const pending = hold("GET /api/v1/agents/beta/schedules");
        try {
          await select("beta");
          await until(() => pending.called, "schedule request");
          assert(
            $("save-schedule").disabled,
            "schedule can be saved before target loads",
          );
          assert(
            $("power-on").value === "08:00",
            "previous target's schedule remained in form",
          );
        } finally {
          pending.release([]);
        }
        await until(
          () => $("schedule-note").textContent.includes("No weekly"),
          "empty schedule",
        );
      });
      await test("logout clears previous account data and drafts", async () => {
        await select("alpha");
        $("urls").value = "https://private-draft.example/";
        $("banner-message").value = "private banner";
        await login("empty");
        assert(
          !$("dashboard").textContent.includes("alpha-private"),
          "previous account content remains visible",
        );
        assert(
          $("selected-title").textContent === "Select a display",
          "previous target remains selected visually",
        );
        assert(
          !$("urls").value && !$("banner-message").value,
          "previous account draft retained",
        );
      });
      await test("late target response cannot replace current content", async () => {
        await login();
        const pending = hold("GET /api/v1/agents/alpha/state");
        document.querySelector('[data-id="alpha"]').click();
        await until(() => pending.called, "old state request");
        await select("beta");
        pending.release({
          revision: 999,
          content: { mode: "playlist", urls: ["https://stale.example/"] },
        });
        await pause(100);
        assert(
          $("content-title").textContent.includes("22"),
          "stale target overwrote current revision",
        );
      });
      await test("cancelled publication starts no new target request", async () => {
        await select("alpha");
        const pending = hold("PUT /api/v1/agents/alpha/playlist");
        $("urls").value = "https://new.example/";
        $("publish").click();
        await until(() => pending.called, "publish request");
        await select("beta");
        const count = requests.filter(
          (path) => path === "GET /api/v1/agents/beta/state",
        ).length;
        pending.release({ event_id: "cancelled" });
        await pause(100);
        assert(
          requests.filter((path) => path === "GET /api/v1/agents/beta/state")
            .length === count,
          "old operation started a request under the new target",
        );
      });
      await test("degraded readiness", async () => {
        degraded = true;
        $("refresh").click();
        await until(
          () => $("server").textContent === "Degraded",
          "degraded readiness",
        );
        degraded = false;
      });
      await test("failed fleet refresh cannot retain ready status", async () => {
        await login();
        agentsUnavailable = true;
        $("refresh").click();
        await until(
          () => $("connection-label").textContent === "Connection failed",
          "failed fleet refresh",
        );
        assert(
          $("server").textContent === "Degraded",
          "stale ready status survived API failure",
        );
        agentsUnavailable = false;
      });
      await test("superseded refresh cannot overwrite current target details", async () => {
        await login();
        await select("alpha");
        const paths = [
          "GET /api/v1/agents/alpha/state",
          "GET /api/v1/agents/alpha/schedules",
          "GET /api/v1/agents/alpha/display/status",
        ];
        const pending = paths.map(hold);
        try {
          $("refresh").click();
          await until(() => pending.every(entry => entry.called), "old detail requests");
          const counts = paths.map(path => requests.filter(request => request === path).length);
          $("refresh").click();
          await until(() => paths.every((path, index) =>
            requests.filter(request => request === path).length > counts[index])
            && $("schedule-note").textContent === "Weekly schedule loaded", "new detail responses");
          pending[0].release({ revision: 1, content: { mode: "playlist", urls: ["https://stale.example/"] } });
          pending[1].release([{ days: ["monday"], power_on: "00:01", power_off: "00:02", enabled: true }]);
          pending[2].release({ enabled: true, power_status: "standby" });
          await pause(100);
          assert($("content-title").textContent.includes("11"), "old refresh overwrote current content revision");
          assert($("power-on").value === "05:00", "old refresh overwrote current schedule");
          assert(document.querySelector("[data-cec-badge]").dataset.state === "on", "old refresh overwrote current CEC status");
          assert(pending.every(entry => entry.signal.aborted), "old detail requests remained active");
        } finally {
          pending.forEach(entry => entry.release({}));
        }
      });
      await test("publication reconciliation supersedes an older refresh read", async () => {
        await login();
        await select("alpha");
        const pending = hold("GET /api/v1/agents/alpha/state");
        try {
          $("refresh").click();
          await until(() => pending.called, "pending refresh content");
          const count = requests.filter(path => path === "GET /api/v1/agents/alpha/state").length;
          $("urls").value = "https://new.example/";
          $("publish").click();
          await until(() => requests.filter(path => path === "GET /api/v1/agents/alpha/state").length > count,
            "publication content reconciliation");
          await pause(100);
          pending.release({ revision: 1, content: { mode: "playlist", urls: ["https://stale.example/"] } });
          await pause(100);
          assert($("content-title").textContent.includes("11"), "older refresh overwrote publication reconciliation");
        } finally {
          pending.release({});
        }
      });
      await test("refresh replacement preserves pending operator commands", async () => {
        await login();
        await select("alpha");
        const publication = hold("PUT /api/v1/agents/alpha/playlist");
        const snapshot = hold("GET /api/v1/session");
        try {
          $("urls").value = "https://new.example/";
          $("publish").click();
          await until(() => publication.called, "pending publication");
          $("refresh").click();
          await until(() => snapshot.called, "old refresh snapshot");
          $("refresh").click();
          await until(() => snapshot.signal.aborted
            && $("schedule-note").textContent === "Weekly schedule loaded", "replacement refresh");
          assert(!publication.signal.aborted, "refresh replacement cancelled an operator command");
          const count = requests.filter(path => path === "GET /api/v1/agents/alpha/state").length;
          publication.release({});
          await until(() => requests.filter(path => path === "GET /api/v1/agents/alpha/state").length > count,
            "publication content reconciliation");
        } finally {
          publication.release({});
          snapshot.release({ roles: ["viewer"] });
        }
      });
      await test("superseded refresh is cancelled", async () => {
        await login();
        const pending = hold("GET /api/v1/session");
        $("refresh").click();
        await until(() => pending.called, "superseded refresh");
        $("refresh").click();
        await until(() => pending.signal.aborted, "refresh cancellation");
        pending.release({ roles: ["viewer"] });
        await pause(100);
        assert(
          $("connection-role").textContent.includes("Administrator"),
          "old refresh changed current roles",
        );
      });
      await test("all role controls", async () => {
        const controls = [
          "#publish",
          "#send-banner",
          "#save-schedule",
          '[data-action="display/on"]',
          '[data-alert="sound/info"]',
          '[data-serial-command="beacon"]',
          '[data-operation="reboot"]',
        ];
        const expected = {
          administrator: [0, 1, 2, 3, 4, 5, 6],
          viewer: [],
          content_manager: [0, 1],
          cec_manager: [3],
          alert_io_operator: [4, 5],
          system_operator: [6],
        };
        for (const [role, enabled] of Object.entries(expected)) {
          await login(role);
          await select("beta");
          await until(
            () => $("schedule-note").textContent.includes("No weekly"),
            "role schedule",
          );
          for (const [i, selector] of controls.entries()) {
            assert(
              document.querySelector(selector).disabled ===
                !enabled.includes(i),
              `${role}: wrong control ${selector}`,
            );
          }
        }
      });
      await test("structured peripheral controls", async () => {
        await login("alert_io_operator");
        await select("beta");
        $("beacon-period").value = "500";
        document
          .querySelector('[data-serial-command="beacon"][data-serial-state="blink"]')
          .click();
        await until(() => serialBodies.length > 0, "serial command");
        assert(
          JSON.stringify(serialBodies.at(-1)) ===
            JSON.stringify({
              command: "beacon",
              state: "blink",
              period_ms: 500,
            }),
          "dashboard did not send the structured blink action",
        );
      });
      await test("scope removal clears selected data", async () => {
        await login();
        await select("alpha");
        hideAlpha = true;
        $("refresh").click();
        await until(
          () => $("selected-title").textContent === "Select a display",
          "removed scope",
        );
        assert(
          !$("content-detail").textContent.includes("alpha-private"),
          "removed scope retained content",
        );
        assert(
          $("save-schedule").disabled,
          "removed scope retained schedule controls",
        );
        hideAlpha = false;
      });
      await test("offline hardware controls", async () => {
        offline = true;
        await login();
        await select("alpha");
        assert(
          document.querySelector('[data-operation="reboot"]').disabled,
          "offline reboot enabled",
        );
        assert($("send-banner").disabled, "offline banner enabled");
        offline = false;
      });
      await test("live viewing follows the selected display's connectivity", async () => {
        try {
          offline = true;
          await login();
          await select("alpha");
          assert(!$("screen-content").querySelector("canvas"), "offline selection opened a live view");
          offline = false;
          $("refresh").click();
          await until(() => $("screen-content").querySelector("canvas"), "reconnected display live view");
          offline = true;
          $("refresh").click();
          await until(() => !$("screen-content").querySelector("canvas"), "offline live view cleanup");
        } finally {
          offline = false;
        }
      });
      await test("refresh during capture cleanup preserves a pending selection", async () => {
        await login();
        const original = window.createImageBitmap;
        const releases = [];
        let holdBitmaps = true;
        window.createImageBitmap = async (...args) => {
          const bitmap = await original(...args);
          if (holdBitmaps) await new Promise(resolve => releases.push(resolve));
          return bitmap;
        };
        try {
          await select("alpha");
          await until(() => releases.length, "pending bitmap");
          document.querySelector('[data-id="beta"]').click();
          $("refresh").click();
          await pause(100);
          holdBitmaps = false;
          releases.forEach(release => release());
          await until(() => $("content-detail").textContent.includes("beta-private"), "selection after cleanup");
          assert($("selected-title").textContent === "beta", "refresh superseded the selected display");
        } finally {
          holdBitmaps = false;
          releases.forEach(release => release());
          window.createImageBitmap = original;
        }
      });
      await test("pending selection uses refreshed display connectivity", async () => {
        await login();
        const original = window.createImageBitmap;
        const releases = [];
        let holdBitmaps = true;
        window.createImageBitmap = async (...args) => {
          const bitmap = await original(...args);
          if (holdBitmaps) await new Promise(resolve => releases.push(resolve));
          return bitmap;
        };
        try {
          await select("alpha");
          await until(() => releases.length, "pending bitmap");
          document.querySelector('[data-id="beta"]').click();
          offline = true;
          $("refresh").click();
          await until(() => $("selected-status").classList.contains("offline"), "offline fleet refresh");
          const streamCount = requests.filter(path => path.endsWith("/display/stream")).length;
          holdBitmaps = false;
          releases.forEach(release => release());
          await until(() => $("content-detail").textContent.includes("beta-private"), "pending offline selection");
          await pause(100);
          assert($("selected-title").textContent === "beta", "pending selection changed target");
          assert($("selected-status").classList.contains("offline"), "pending selection restored stale connectivity");
          assert(requests.filter(path => path.endsWith("/display/stream")).length === streamCount, "pending selection opened an offline display stream");
        } finally {
          offline = false;
          holdBitmaps = false;
          releases.forEach(release => release());
          window.createImageBitmap = original;
        }
      });
      await test("pending selection cancels previous-target refresh replies", async () => {
        await login();
        const original = window.createImageBitmap;
        const releases = [];
        let holdBitmaps = true;
        let delayedState;
        window.createImageBitmap = async (...args) => {
          const bitmap = await original(...args);
          if (holdBitmaps) await new Promise(resolve => releases.push(resolve));
          return bitmap;
        };
        try {
          await select("alpha");
          await until(() => releases.length, "pending bitmap");
          document.querySelector('[data-id="beta"]').click();
          delayedState = hold("GET /api/v1/agents/alpha/state");
          $("refresh").click();
          await until(() => delayedState.called, "previous-target refresh response");
          holdBitmaps = false;
          releases.forEach(release => release());
          await until(() => $("content-detail").textContent.includes("beta-private"), "replacement selection state");
          delayedState.release({ revision: 99, content: { mode: "playlist", urls: ["https://stale-alpha.example/"] } });
          await pause(100);
          assert(delayedState.signal.aborted, "previous-target refresh request remained current");
          assert($("content-detail").textContent.includes("beta-private"), "previous-target refresh overwrote replacement state");
        } finally {
          delayedState?.release({});
          holdBitmaps = false;
          releases.forEach(release => release());
          window.createImageBitmap = original;
        }
      });
      await test("pending selection cannot restore a display removed from scope", async () => {
        await login();
        const original = window.createImageBitmap;
        const releases = [];
        let holdBitmaps = true;
        window.createImageBitmap = async (...args) => {
          const bitmap = await original(...args);
          if (holdBitmaps) await new Promise(resolve => releases.push(resolve));
          return bitmap;
        };
        try {
          await select("beta");
          await until(() => releases.length, "pending bitmap");
          document.querySelector('[data-id="alpha"]').click();
          hideAlpha = true;
          $("refresh").click();
          await until(() => !document.querySelector('[data-id="alpha"]'), "removed display scope");
          const streamCount = requests.filter(path => path.endsWith("/display/stream")).length;
          holdBitmaps = false;
          releases.forEach(release => release());
          await until(() => $("selected-title").textContent === "Select a display", "removed pending selection cleanup");
          assert(!$("content-detail").textContent.includes("alpha-private"), "removed display restored its private state");
          assert(requests.filter(path => path.endsWith("/display/stream")).length === streamCount, "removed pending selection opened a display stream");
        } finally {
          hideAlpha = false;
          holdBitmaps = false;
          releases.forEach(release => release());
          window.createImageBitmap = original;
        }
      });
      await test("pending capture cannot start after an offline refresh", async () => {
        await login();
        const original = window.createImageBitmap;
        const releases = [];
        let holdBitmaps = true;
        window.createImageBitmap = async (...args) => {
          const bitmap = await original(...args);
          if (holdBitmaps) await new Promise(resolve => releases.push(resolve));
          return bitmap;
        };
        try {
          await select("alpha");
          await until(() => releases.length, "pending bitmap");
          $("target-broadcast").click();
          $("target-single").click();
          $("refresh").click();
          await pause(100);
          offline = true;
          $("refresh").click();
          await until(() => $("selected-status").classList.contains("offline"), "offline refresh");
          const streamCount = requests.filter(path => path.endsWith("/display/stream")).length;
          holdBitmaps = false;
          releases.forEach(release => release());
          await pause(100);
          assert(requests.filter(path => path.endsWith("/display/stream")).length === streamCount, "capture started for an offline display");
        } finally {
          offline = false;
          holdBitmaps = false;
          releases.forEach(release => release());
          window.createImageBitmap = original;
        }
      });
      await test("banner messages are limited to 256 Unicode characters", async () => {
        await login();
        await select("beta");
        const input = $("banner-message");
        const countBanners = () => requests.filter(path => path.endsWith("/banner")).length;
        for (const character of ["a", "é", "界", "😀"]) {
          input.value = character.repeat(257);
          input.dispatchEvent(new Event("input"));
          assert(input.value === character.repeat(256), "banner input character limit");
          const before = countBanners();
          const activityBefore = $("activity").querySelectorAll(".activity-item").length;
          $("send-banner").click();
          await until(() => countBanners() === before + 1, "256-character banner sent");
          await until(() => $("activity").querySelectorAll(".activity-item").length > activityBefore,
            "banner response processed");
        }
        const before = countBanners();
        input.value = "😀".repeat(257);
        $("send-banner").click();
        await pause(100);
        assert(countBanners() === before, "oversized banner submitted");
        assert($("toast").textContent.includes("256 characters"), "missing banner length error");
      });
      await test("durable command outcomes", async () => {
        await login();
        for (const state of [
          "accepted",
          "completed",
          "rejected",
          "expired",
          "uncertain",
        ]) {
          await select("beta");
          outcome = state;
          $("banner-message").value = "test";
          $("send-banner").click();
          await until(
            () =>
              $("activity")
                .firstElementChild?.textContent.toLowerCase()
                .includes(`beta: ${state}`),
            state,
          );
        }
      });
      await test("logout invalidates a pending session refresh", async () => {
        const pending = hold("GET /api/v1/session");
        $("refresh").click();
        await until(() => pending.called, "session refresh");
        $("logout").click();
        pending.release({ roles: ["administrator"] });
        await pause(100);
        assert(
          $("dashboard").classList.contains("hidden"),
          "old session reopened dashboard",
        );
        assert(
          $("connection-role").textContent === "Role: —",
          "old roles restored after logout",
        );
      });
      await test("expired authorization clears the session", async () => {
        await login();
        await select("alpha");
        unauthorized = true;
        $("refresh").click();
        await until(
          () => $("dashboard").classList.contains("hidden"),
          "authorization expiry",
        );
        assert(!$("token").value, "expired token retained in login form");
        assert(
          $("selected-title").textContent === "Select a display",
          "expired account retained selection",
        );
        unauthorized = false;
      });
    } catch (error) {
      failures.push(`harness: ${error.message}`);
    }
    window.webkit.messageHandlers.test_result.postMessage(
      JSON.stringify({ completed: true, passed, failures }),
    );
  });
})();
