// Zone encryption — the writer half of §5 envelope format.
//
// Mirrors @aithos/protocol-core's `encryptZone` + `wrapDek`. Every
// constant (AAD prefix, HKDF salt + info, AEAD key length) must match
// the decrypter's expectations — if they drift, ciphertexts sealed
// here cannot be opened by CLI readers (or vice versa).

import { xchacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";

import { base64url, x25519PublicKeyToMultibase } from "./encoding.js";
import { hkdfSha256 } from "./kex.js";

export interface EncryptRecipient {
  /** DID URL identifying who can open the wrap (e.g. `did:aithos:z…#circle-kex`). */
  readonly didUrl: string;
  /** Recipient's X25519 public key (32 bytes, raw). */
  readonly x25519PublicKey: Uint8Array;
}

export interface SealedZone {
  readonly ciphertext: Uint8Array;
  readonly cipher: {
    readonly alg: "xchacha20poly1305-ietf";
    readonly nonce: string;
    readonly wraps: readonly SealedWrap[];
  };
}

export interface SealedWrap {
  readonly recipient: string;
  readonly alg: "x25519-hkdf-sha256-aead";
  readonly ephemeral_public: string;
  readonly wrap_nonce: string;
  readonly wrapped_key: string;
}

const ZONE_AAD_PREFIX_TEXT = "aithos-zone-v1\0";
const WRAP_SALT_TEXT = "aithos-wrap-v1";

/**
 * Seal a plaintext zone for a set of recipients. Generates a fresh DEK
 * (symmetric key) per call, encrypts the plaintext with XChaCha20-Poly1305
 * (AAD = "aithos-zone-v1\0" + subject_did), then wraps the DEK once per
 * recipient via X25519+HKDF+AEAD.
 */
export function encryptZone(args: {
  readonly plaintext: string;
  readonly subjectDid: string;
  readonly recipients: readonly EncryptRecipient[];
}): SealedZone {
  const dek = new Uint8Array(32);
  crypto.getRandomValues(dek);
  const nonce = new Uint8Array(24);
  crypto.getRandomValues(nonce);

  const aad = concatBytes(
    new TextEncoder().encode(ZONE_AAD_PREFIX_TEXT),
    new TextEncoder().encode(args.subjectDid),
  );
  const aead = xchacha20poly1305(dek, nonce, aad);
  const ciphertext = aead.encrypt(new TextEncoder().encode(args.plaintext));

  const wraps: SealedWrap[] = args.recipients.map((r) =>
    wrapDek(dek, r.didUrl, r.x25519PublicKey),
  );

  dek.fill(0);

  return {
    ciphertext,
    cipher: {
      alg: "xchacha20poly1305-ietf",
      nonce: base64url(nonce),
      wraps,
    },
  };
}

function wrapDek(
  dek: Uint8Array,
  recipientDidUrl: string,
  recipientPk: Uint8Array,
): SealedWrap {
  // Ephemeral X25519 keypair — single-use, generated per recipient per
  // edition. Gives forward secrecy for the ephemeral leg.
  const esk = new Uint8Array(32);
  crypto.getRandomValues(esk);
  const epk = x25519.getPublicKey(esk);

  const shared = x25519.getSharedSecret(esk, recipientPk);
  const wrapKey = hkdfSha256(
    shared,
    new TextEncoder().encode(WRAP_SALT_TEXT),
    new TextEncoder().encode(recipientDidUrl),
    32,
  );

  const wrapNonce = new Uint8Array(24);
  crypto.getRandomValues(wrapNonce);
  const aead = xchacha20poly1305(
    wrapKey,
    wrapNonce,
    new TextEncoder().encode(recipientDidUrl),
  );
  const wrapped = aead.encrypt(dek);

  // Zeroize
  esk.fill(0);
  if (typeof (shared as Uint8Array).fill === "function") (shared as Uint8Array).fill(0);
  wrapKey.fill(0);

  return {
    recipient: recipientDidUrl,
    alg: "x25519-hkdf-sha256-aead",
    ephemeral_public: x25519PublicKeyToMultibase(epk),
    wrap_nonce: base64url(wrapNonce),
    wrapped_key: base64url(wrapped),
  };
}

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
