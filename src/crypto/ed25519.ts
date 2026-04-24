// Ed25519 primitives, browser-side.
//
// We use `@noble/ed25519` directly (pure JS, ~4KB gzipped) instead of the
// WebCrypto API because:
//   - WebCrypto Ed25519 is only widely available on Safari 18+, Firefox 135+
//     (spring 2025) — we want broader compat
//   - noble gives us sync `sign`/`verify` once sha512 is wired, which keeps
//     the signing flow linear and easy to reason about
//
// The protocol-core reference library also uses noble with the same
// sha512 wiring, so signatures produced here and there are byte-identical.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

// Sync sha512 is required for `ed.sign` / `ed.verify` (the async variants
// use WebCrypto). Wire it once at module load.
if (!ed.etc.sha512Sync) {
  ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
}

export interface KeyPair {
  readonly seed: Uint8Array; // 32 bytes, private
  readonly publicKey: Uint8Array; // 32 bytes, public
}

/** Generate a fresh Ed25519 keypair using crypto.getRandomValues. */
export function generateKeyPair(): KeyPair {
  const seed = new Uint8Array(32);
  crypto.getRandomValues(seed);
  const publicKey = ed.getPublicKey(seed);
  return { seed, publicKey };
}

/** Sign `bytes` with `seed`, returning a 64-byte Ed25519 signature. */
export function sign(bytes: Uint8Array, seed: Uint8Array): Uint8Array {
  return ed.sign(bytes, seed);
}

/** Verify a 64-byte Ed25519 signature against `bytes` and a 32-byte pubkey. */
export function verify(
  sig: Uint8Array,
  bytes: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  return ed.verify(sig, bytes, publicKey);
}
