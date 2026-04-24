// Key-agreement (X25519) derivation + HKDF helper.
//
// Given an Ed25519 seed we can derive an X25519 secret usable for
// scalar-multiplication against other parties' X25519 public keys.
// libsodium's `crypto_sign_ed25519_sk_to_curve25519` does exactly this:
// it SHA-512 hashes the 32-byte seed, takes the first 32 bytes, and
// applies the standard Curve25519 "clamp" bit-twiddling.
//
// Matches @aithos/protocol-core's `edSeedToX25519Secret`.

import { sha512 } from "@noble/hashes/sha2";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { edwardsToMontgomeryPub } from "@noble/curves/ed25519";

/**
 * Derive an X25519 secret from a 32-byte Ed25519 seed. Applies the
 * standard Curve25519 clamp.
 */
export function edSeedToX25519Secret(seed: Uint8Array): Uint8Array {
  if (seed.length !== 32) {
    throw new Error(`edSeedToX25519Secret: expected 32-byte seed, got ${seed.length}`);
  }
  const h = sha512(seed);
  const sk = h.slice(0, 32);
  sk[0]! &= 248;
  sk[31]! &= 127;
  sk[31]! |= 64;
  return sk;
}

/**
 * Derive the X25519 public key corresponding to an Ed25519 public key
 * via the standard Edwards → Montgomery isogeny:  u = (1 + y) / (1 - y).
 *
 * Used on the owner side when sealing a zone for a delegate — the mandate
 * only stores the delegate's Ed25519 pubkey (multibase `z…`), so we need
 * to project it onto Curve25519 before we can HKDF a wrap key for them.
 *
 * Mirrors libsodium's `crypto_sign_ed25519_pk_to_curve25519`. Do NOT swap
 * this for a raw multibase copy of the Ed25519 pubkey — a wrap encrypted
 * with the wrong curve point would be silently unopenable.
 */
export function edPubToX25519Pub(edPub: Uint8Array): Uint8Array {
  if (edPub.length !== 32) {
    throw new Error(`edPubToX25519Pub: expected 32-byte key, got ${edPub.length}`);
  }
  return edwardsToMontgomeryPub(edPub);
}

/**
 * HKDF-SHA256 expand to `length` bytes, matching protocol-core's helper.
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return hkdf(sha256, ikm, salt, info, length);
}
