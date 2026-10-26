// File purpose: Verifies HTTP JPEG framing across chunk boundaries and bounded failure cleanup.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

import assert from "node:assert/strict";
import test from "node:test";
import { displayFrames } from "./display.js";

// framed prefixes a fixture with its network-order byte length.
function framed(bytes) {
  const frame = new Uint8Array(4 + bytes.length);
  new DataView(frame.buffer).setUint32(0, bytes.length);
  frame.set(bytes, 4);
  return frame;
}

// collect consumes a fixture stream using the same decoder as the dashboard.
async function collect(chunks) {
  const body = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(chunk);
      controller.close();
    },
  });
  const frames = [];
  for await (const frame of displayFrames(body)) frames.push([...frame]);
  assert.equal(body.locked, false);
  return frames;
}

test("fragmented headers, fragmented JPEGs and coalesced frames decode identically", async () => {
  const first = framed(new Uint8Array([1, 2, 3]));
  const second = framed(new Uint8Array([4, 5]));
  const joined = new Uint8Array([...first, ...second]);
  assert.deepEqual(await collect([joined]), [[1, 2, 3], [4, 5]]);
  assert.deepEqual(await collect([...joined].map(byte => new Uint8Array([byte]))), [[1, 2, 3], [4, 5]]);
  assert.deepEqual(await collect([]), []);
});

test("zero, oversized and truncated records fail and cancel their readers", async () => {
  for (const size of [0, 2097153, 0xffffffff]) {
    const header = new Uint8Array(4);
    new DataView(header.buffer).setUint32(0, size);
    await assert.rejects(collect([header]), /Invalid display frame size/);
  }
  await assert.rejects(collect([new Uint8Array([0, 0])]), /ended during a frame/);
  await assert.rejects(collect([framed(new Uint8Array([1, 2])).subarray(0, 5)]), /ended during a frame/);
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(4)); },
    cancel() { cancelled = true; },
  });
  await assert.rejects(async () => {
    for await (const frame of displayFrames(body)) assert.fail(`unexpected frame ${frame}`);
  }, /Invalid display frame size/);
  assert.equal(cancelled, true);
  assert.equal(body.locked, false);
});

test("leaving the frame loop cancels an open response and releases its reader", async () => {
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) { controller.enqueue(framed(new Uint8Array([1]))); },
    cancel() { cancelled = true; },
  });
  for await (const frame of displayFrames(body)) {
    assert.deepEqual([...frame], [1]);
    break;
  }
  assert.equal(cancelled, true);
  assert.equal(body.locked, false);
});
