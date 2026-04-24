// Smoke test — compiles, imports, runs.
//
// The point of this test in alpha.0 is to exercise the end-to-end pipeline:
// TypeScript → tsc → dist/ → node --test picks it up → assertions run.
// No protocol logic is covered yet.

import { test } from "node:test";
import assert from "node:assert/strict";
import { VERSION } from "../src/index.js";

test("package exposes a VERSION string", () => {
  assert.ok(typeof VERSION === "string");
  assert.ok(VERSION.length > 0);
});

test("WebCrypto is available in the test environment", async () => {
  // The protocol implementation relies on globalThis.crypto.subtle being
  // available. Node 20+ provides it globally; fail loudly if that ever
  // regresses so we catch it here instead of deep in a handler.
  assert.ok(globalThis.crypto, "globalThis.crypto missing");
  assert.ok(globalThis.crypto.subtle, "crypto.subtle missing");

  // Trivial round-trip to prove it actually works.
  const data = new TextEncoder().encode("hello aithos");
  const hash = await globalThis.crypto.subtle.digest("SHA-256", data);
  assert.equal(hash.byteLength, 32);
});
