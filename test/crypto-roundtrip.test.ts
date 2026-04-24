// Crypto round-trip sanity tests.
//
// The whole package is a cryptographic client — if these don't pass,
// nothing downstream is safe. These tests are intentionally narrow:
// they exercise the primitives actually used by the higher-level editor
// and envelope modules, not every combination of every function.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  generateKeyPair,
  sign,
  verify,
  base64url,
  base64urlDecode,
  bytesToHex,
  canonicalize,
} from "../src/index.js";

test("ed25519 sign/verify round-trip with a fresh keypair", () => {
  const kp = generateKeyPair();
  assert.equal(kp.seed.length, 32, "seed must be 32 bytes");
  assert.equal(kp.publicKey.length, 32, "public key must be 32 bytes");

  const message = new TextEncoder().encode("hello aithos");
  const signature = sign(message, kp.seed);
  assert.equal(signature.length, 64, "ed25519 signature must be 64 bytes");

  assert.equal(verify(signature, message, kp.publicKey), true);
});

test("ed25519 verify rejects a tampered message", () => {
  const kp = generateKeyPair();
  const message = new TextEncoder().encode("authentic");
  const signature = sign(message, kp.seed);

  const tampered = new TextEncoder().encode("authentiq"); // one char changed
  assert.equal(verify(signature, tampered, kp.publicKey), false);
});

test("ed25519 verify rejects a signature from a different key", () => {
  const kp1 = generateKeyPair();
  const kp2 = generateKeyPair();
  const message = new TextEncoder().encode("hello");

  const sig = sign(message, kp1.seed);
  assert.equal(verify(sig, message, kp2.publicKey), false);
});

test("base64url encodes and decodes round-trip", () => {
  const bytes = new Uint8Array([0, 1, 2, 255, 128, 64, 32]);
  const encoded = base64url(bytes);
  const decoded = base64urlDecode(encoded);
  assert.deepEqual([...decoded], [...bytes]);
});

test("base64url output never contains padding or standard chars", () => {
  // Encoding random bytes that would include '/', '+', '=' in base64 standard.
  const bytes = new Uint8Array([0xff, 0xff, 0xff, 0xff]);
  const encoded = base64url(bytes);
  assert.ok(!encoded.includes("="), "no padding");
  assert.ok(!encoded.includes("/"), "no /");
  assert.ok(!encoded.includes("+"), "no +");
});

test("bytesToHex produces lowercase hex of correct length", () => {
  const bytes = new Uint8Array([0, 15, 16, 255]);
  assert.equal(bytesToHex(bytes), "000f10ff");
});

test("canonicalize produces stable output regardless of key order", () => {
  const a = canonicalize({ b: 1, a: 2, c: [3, 2, 1] });
  const b = canonicalize({ c: [3, 2, 1], a: 2, b: 1 });
  assert.equal(a, b, "same object, different order → same canonical form");
});

test("canonicalize is recursive on nested objects", () => {
  const a = canonicalize({ outer: { b: 1, a: 2 } });
  const b = canonicalize({ outer: { a: 2, b: 1 } });
  assert.equal(a, b);
});
