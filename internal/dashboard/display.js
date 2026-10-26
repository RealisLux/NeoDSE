// File purpose: Decodes bounded JPEG frames from the authenticated HTTP display stream.
// Copyright (c) 2026 RealisLux
// SPDX-License-Identifier: MIT
// Project: https://github.com/RealisLux/NeoDSE

const maxFrameBytes = 2 * 1024 * 1024;

// displayFrames handles arbitrary HTTP chunk boundaries without buffering a whole stream.
export async function* displayFrames(body) {
  const reader = body.getReader();
  let chunk = new Uint8Array(0);
  let offset = 0;

  // readExactly fills one bounded record, distinguishing clean EOF from truncation.
  async function readExactly(size, allowEOF = false) {
    const bytes = new Uint8Array(size);
    let filled = 0;
    while (filled < size) {
      if (offset === chunk.length) {
        const result = await reader.read();
        if (result.done) {
          if (allowEOF && filled === 0) return null;
          throw new Error("The display stream ended during a frame.");
        }
        chunk = result.value;
        offset = 0;
        if (!chunk.length) continue;
      }
      const count = Math.min(size - filled, chunk.length - offset);
      bytes.set(chunk.subarray(offset, offset + count), filled);
      offset += count;
      filled += count;
    }
    return bytes;
  }

  try {
    while (true) {
      const header = await readExactly(4, true);
      if (!header) return;
      const size = new DataView(header.buffer).getUint32(0);
      if (size === 0 || size > maxFrameBytes)
        throw new Error("Invalid display frame size.");
      yield await readExactly(size);
    }
  } finally {
    try { await reader.cancel(); } finally { reader.releaseLock(); }
  }
}
