// Zone decryption — browser side.
//
// Implements the reader half of the §5 envelope format used by
// @aithos/protocol-core's `decryptZone` function. Every constant (AAD
// prefix, HKDF salt, HKDF info derivation) is kept identical so a
// zone sealed by the CLI can be opened here byte-for-byte.
//
// Flow:
//   1. Pick the wrap whose `recipient` matches a key we hold.
//   2. X25519(our_sk, ephemeral_pubkey) → shared secret.
//   3. HKDF-SHA256(shared, salt="aithos-wrap-v1", info=recipient) → wrap key (32B).
//   4. XChaCha20-Poly1305 unwrap the symmetric DEK (AAD = recipient).
//   5. XChaCha20-Poly1305 decrypt the zone ciphertext (AAD = "aithos-zone-v1\0" + subject_did).
//
// Intentionally close to the reference impl; if the spec changes these
// constants, both sides must move in lockstep.

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";

import { base64urlDecode, multibaseToX25519PublicKey } from "./encoding.js";
import { edSeedToX25519Secret, hkdfSha256 } from "./kex.js";

const ZONE_AAD_PREFIX_TEXT = "aithos-zone-v1\0";
const WRAP_SALT_TEXT = "aithos-wrap-v1";

export interface ZoneCipher {
  readonly alg: "xchacha20poly1305-ietf";
  readonly nonce: string; // base64url
  readonly wraps: readonly WrapEntry[];
}

export interface WrapEntry {
  readonly recipient: string;
  readonly alg: "x25519-hkdf-sha256-aead";
  readonly ephemeral_public: string; // multibase X25519 pubkey
  readonly wrap_nonce: string; // base64url
  readonly wrapped_key: string; // base64url
}

export interface DecryptOwnerArgs {
  /** Raw ciphertext bytes as stored in S3. */
  readonly ciphertext: Uint8Array;
  /** The `cipher` block from the manifest's ZoneManifest entry. */
  readonly cipher: ZoneCipher;
  /** Subject DID — the bare `did:aithos:z…`, NOT a DID URL. */
  readonly subjectDid: string;
  /** DID URL we claim to be (e.g. `did:aithos:z…#circle-kex`). */
  readonly myDidUrl: string;
  /** Our X25519 secret (32 bytes, already clamped). Use edSeedToX25519Secret. */
  readonly myX25519Secret: Uint8Array;
}

export function decryptZone(args: DecryptOwnerArgs): string {
  const wrap = args.cipher.wraps.find((w) => w.recipient === args.myDidUrl);
  if (!wrap) {
    throw new Error(`no wrap entry matching ${args.myDidUrl}`);
  }
  const dek = unwrapDek(wrap, args.myX25519Secret);
  try {
    const aad = concatBytes(
      new TextEncoder().encode(ZONE_AAD_PREFIX_TEXT),
      new TextEncoder().encode(args.subjectDid),
    );
    const aead = xchacha20poly1305(dek, base64urlDecode(args.cipher.nonce), aad);
    const plain = aead.decrypt(args.ciphertext);
    return new TextDecoder().decode(plain);
  } finally {
    dek.fill(0);
  }
}

function unwrapDek(wrap: WrapEntry, mySk: Uint8Array): Uint8Array {
  if (wrap.alg !== "x25519-hkdf-sha256-aead") {
    throw new Error(`unsupported wrap alg: ${wrap.alg}`);
  }
  const epk = multibaseToX25519PublicKey(wrap.ephemeral_public);
  const shared = x25519.getSharedSecret(mySk, epk);
  const wrapKey = hkdfSha256(
    shared,
    new TextEncoder().encode(WRAP_SALT_TEXT),
    new TextEncoder().encode(wrap.recipient),
    32,
  );
  const nonce = base64urlDecode(wrap.wrap_nonce);
  const aead = xchacha20poly1305(
    wrapKey,
    nonce,
    new TextEncoder().encode(wrap.recipient),
  );
  const out = aead.decrypt(base64urlDecode(wrap.wrapped_key));
  // Best-effort zeroize.
  if (typeof (shared as Uint8Array).fill === "function") (shared as Uint8Array).fill(0);
  wrapKey.fill(0);
  return out;
}

/**
 * Thin convenience wrapper for the owner path: given an Ed25519 seed +
 * sphere name + subject DID + cipher block, attempt to decrypt. Returns
 * `null` if no wrap matches (caller interprets as "no access").
 */
export interface DecryptOwnerInput {
  readonly ciphertext: Uint8Array;
  readonly cipher: ZoneCipher;
  readonly subjectDid: string;
  readonly sphere: "circle" | "self";
  readonly sphereSeed: Uint8Array;
}

export function tryDecryptAsOwner(input: DecryptOwnerInput): string | null {
  const mySk = edSeedToX25519Secret(input.sphereSeed);
  const myDidUrl = `${input.subjectDid}#${input.sphere}-kex`;
  try {
    return decryptZone({
      ciphertext: input.ciphertext,
      cipher: input.cipher,
      subjectDid: input.subjectDid,
      myDidUrl,
      myX25519Secret: mySk,
    });
  } catch {
    return null;
  } finally {
    mySk.fill(0);
  }
}

/**
 * Convenience wrapper for the delegate path: the wrap recipient id is
 * `<granteeId>#<pubkeyMultibase>` (see protocol-core `delegateWrapDid`),
 * and the X25519 secret comes from the grantee's Ed25519 seed via the
 * standard libsodium derivation.
 */
export interface DecryptDelegateInput {
  readonly ciphertext: Uint8Array;
  readonly cipher: ZoneCipher;
  readonly subjectDid: string;
  readonly granteeId: string;
  readonly granteePubkeyMultibase: string;
  readonly delegateSeed: Uint8Array;
}

export function tryDecryptAsDelegate(input: DecryptDelegateInput): string | null {
  const mySk = edSeedToX25519Secret(input.delegateSeed);
  const myDidUrl = `${input.granteeId}#${input.granteePubkeyMultibase}`;
  try {
    return decryptZone({
      ciphertext: input.ciphertext,
      cipher: input.cipher,
      subjectDid: input.subjectDid,
      myDidUrl,
      myX25519Secret: mySk,
    });
  } catch {
    return null;
  } finally {
    mySk.fill(0);
  }
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

function concatBytes(...arrs: Uint8Array[]): Uint8Array {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}
