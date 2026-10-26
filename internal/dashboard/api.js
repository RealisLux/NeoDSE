// File purpose: Sends authenticated API requests whose session and target lifetimes own every request and polling delay.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

// createAPI builds an authenticated client whose requests follow those lifetimes.
export function createAPI(fetcher = fetch, onUnauthorized = () => {}) {
  let token = "";
  let session = new AbortController();
  let target = new AbortController();

  // resetTarget cancels work associated with the previously selected display.
  function resetTarget() {
    target.abort();
    target = new AbortController();
  }

  // setToken replaces the authenticated session and invalidates all prior work.
  function setToken(value) {
    session.abort();
    session = new AbortController();
    resetTarget();
    token = value;
  }

  // signalFor selects the cancellation lifetime that owns an API path.
  function signalFor(path) {
    const targetScoped = /^\/api\/v1\/(agents\/|events\/)/.test(path);
    return targetScoped
      ? AbortSignal.any([session.signal, target.signal])
      : session.signal;
  }

  // request sends one authenticated request and rejects stale response bodies.
  async function request(path, options = {}) {
    const signal = options.signal
      ? AbortSignal.any([signalFor(path), options.signal])
      : signalFor(path);
    signal.throwIfAborted();
    const response = await fetcher(path, {
      ...options,
      signal,
      headers: {
        Authorization: `Bearer ${token}`,
        ...(options.body ? { "Content-Type": "application/json" } : {}),
        ...options.headers,
      },
    });
    if (signal.aborted) {
      await response.body?.cancel();
      signal.throwIfAborted();
    }
    if (!response.ok) {
      if (response.status === 401) {
        onUnauthorized();
        signal.throwIfAborted();
      }
      let message = `Request failed (${response.status})`;

      // Prefer a structured API error, retaining the HTTP status as fallback.
      try {
        message = (await response.json()).message || message;
      } catch (_) {}
      signal.throwIfAborted();
      throw Object.assign(new Error(message), { status: response.status });
    }

    // consume reads a response body only while its request remains current.
    const consume = async (method) => {
      const value = await response[method]();
      signal.throwIfAborted();
      return value;
    };
    return {
      check: () => signal.throwIfAborted(),
      body: response.body,
      status: response.status,
      headers: response.headers,
      json: () => consume("json"),
      blob: () => consume("blob"),
    };
  }

  // delay waits within the current target and session cancellation scopes.
  function delay(milliseconds) {
    const signal = AbortSignal.any([session.signal, target.signal]);
    return new Promise((resolve, reject) => {
      signal.throwIfAborted();
      const timer = setTimeout(() => {
        signal.removeEventListener("abort", aborted);
        resolve();
      }, milliseconds);

      // aborted rejects the delay immediately when either owning scope ends.
      function aborted() {
        clearTimeout(timer);
        reject(signal.reason);
      }
      signal.addEventListener("abort", aborted, { once: true });
    });
  }

  return { request, setToken, resetTarget, delay };
}

// isCancelled identifies expected AbortController cancellation failures.
export const isCancelled = (error) => error?.name === "AbortError";
