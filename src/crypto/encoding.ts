// Small encoding helpers for Aithos crypto. Pure JS, browser-safe.
//
//   - base64url      — used for proof values and signatures in JSON
//   - base58btc      — Bitcoin alphabet, used inside multibase `z…` strings
//   - multibase z    — the public-key-as-string format the Aithos protocol
//                      pins to, per did:key (z prefix = base58btc)
//   - hex            — used for sha256 anchors in the manifest
//
// Implementation mirrors @aithos/protocol-core's `did.js` + `identity.js`
// byte-for-byte so signatures computed client-side verify server-side.

/* ---------- base64url ---------------------------------------------------- */

/** Encode bytes → base64url (no padding, URL-safe alphabet). */
export function base64url(bytes: Uint8Array): string {
  // btoa works on binary strings, so encode bytes as a latin-1 string first.
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(s: string): Uint8Array {
  const pad = s.length % 4;
  const b64 =
    s.replace(/-/g, "+").replace(/_/g, "/") +
    (pad ? "====".slice(pad) : "");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

/* ---------- base58btc ---------------------------------------------------- */

// Bitcoin alphabet (no 0, O, I, l to avoid confusion).
const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** Decode a base58btc string → bytes. Inverse of {@link base58btcEncode}. */
export function base58btcDecode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array(0);
  // Count leading '1's — they represent leading zero bytes in the original.
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  const size = Math.ceil(s.length * 0.7335) + 1; // ~log(58)/log(256)
  const b256 = new Uint8Array(size);
  let length = 0;
  for (let i = zeros; i < s.length; i++) {
    const ch = s[i]!;
    const idx = B58_ALPHABET.indexOf(ch);
    if (idx < 0) throw new Error(`base58btcDecode: invalid character '${ch}' at ${i}`);
    let carry = idx;
    let j = 0;
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 58 * b256[k]!;
      b256[k] = carry & 0xff;
      carry = carry >> 8;
    }
    length = j;
  }
  let start = size - length;
  while (start < size && b256[start] === 0) start++;
  const out = new Uint8Array(zeros + (size - start));
  for (let i = 0; i < zeros; i++) out[i] = 0;
  let pos = zeros;
  for (let i = start; i < size; i++) out[pos++] = b256[i]!;
  return out;
}

/** Encode bytes → base58btc string. */
export function base58btcEncode(bytes: Uint8Array): string {
  if (bytes.length === 0) return "";
  // Count leading zeros → preserved as leading '1's.
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  // Allocate a digits buffer, process big-endian, repeated divmod 58.
  const size = Math.ceil((bytes.length - zeros) * 1.365) + 1; // ~log(256)/log(58)
  const b58 = new Uint8Array(size);
  let length = 0;
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    let j = 0;
    for (let k = size - 1; (carry !== 0 || j < length) && k >= 0; k--, j++) {
      carry += 256 * b58[k]!;
      b58[k] = carry % 58;
      carry = (carry / 58) | 0;
    }
    length = j;
  }
  // Skip leading zeros inside the accumulator, then prepend one '1' per input zero.
  let start = size - length;
  while (start < size && b58[start] === 0) start++;
  let out = "1".repeat(zeros);
  for (let i = start; i < size; i++) out += B58_ALPHABET[b58[i]!];
  return out;
}

/* ---------- multibase (did:key-style) ------------------------------------ */

// Multicodec prefix bytes for ed25519-pub = 0xED varint = `0xed 0x01`.
// (Multicodec table: https://github.com/multiformats/multicodec)
const ED25519_PUB_MULTICODEC = new Uint8Array([0xed, 0x01]);

// x25519-pub multicodec = `0xec 0x01`.
const X25519_PUB_MULTICODEC = new Uint8Array([0xec, 0x01]);

/**
 * Encode a raw 32-byte X25519 public key as multibase `z…`. Matches
 * `x25519PublicKeyToMultibase` in @aithos/protocol-core.
 */
export function x25519PublicKeyToMultibase(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) {
    throw new Error(`x25519PublicKeyToMultibase: expected 32-byte key, got ${pubkey.length}`);
  }
  const buf = new Uint8Array(X25519_PUB_MULTICODEC.length + 32);
  buf.set(X25519_PUB_MULTICODEC, 0);
  buf.set(pubkey, X25519_PUB_MULTICODEC.length);
  return "z" + base58btcEncode(buf);
}

/**
 * Decode a multibase `z...` string that carries an x25519 public key back
 * into raw 32 bytes. Errors if the multicodec prefix isn't x25519-pub.
 */
export function multibaseToX25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) throw new Error("multibaseToX25519PublicKey: expected 'z' prefix");
  const raw = base58btcDecode(mb.slice(1));
  if (raw.length !== 2 + 32) {
    throw new Error(
      `multibaseToX25519PublicKey: expected 34 bytes payload, got ${raw.length}`,
    );
  }
  if (raw[0] !== X25519_PUB_MULTICODEC[0] || raw[1] !== X25519_PUB_MULTICODEC[1]) {
    throw new Error("multibaseToX25519PublicKey: unexpected multicodec prefix");
  }
  return raw.slice(2);
}

/**
 * Decode a multibase `z…` string carrying an Ed25519 public key back to
 * the raw 32 bytes. Mirror of `ed25519PublicKeyToMultibase`. Used when
 * reading `mandate.grantee.pubkey` so we can convert it to an X25519
 * kex public key for the zone-seal path.
 */
export function multibaseToEd25519PublicKey(mb: string): Uint8Array {
  if (!mb.startsWith("z")) {
    throw new Error("multibaseToEd25519PublicKey: expected 'z' prefix");
  }
  const raw = base58btcDecode(mb.slice(1));
  if (raw.length !== 2 + 32) {
    throw new Error(
      `multibaseToEd25519PublicKey: expected 34 bytes payload, got ${raw.length}`,
    );
  }
  if (raw[0] !== ED25519_PUB_MULTICODEC[0] || raw[1] !== ED25519_PUB_MULTICODEC[1]) {
    throw new Error(
      "multibaseToEd25519PublicKey: unexpected multicodec prefix (not ed25519-pub)",
    );
  }
  return raw.slice(2);
}

/**
 * Encode an Ed25519 public key (raw 32 bytes) as a multibase string:
 * `z` (base58btc tag) + base58btc(0xed 0x01 || pubkey).
 *
 * Matches `ed25519PublicKeyToMultibase` in @aithos/protocol-core/did.js.
 */
export function ed25519PublicKeyToMultibase(pubkey: Uint8Array): string {
  if (pubkey.length !== 32) {
    throw new Error(
      `ed25519PublicKeyToMultibase: expected 32-byte key, got ${pubkey.length}`,
    );
  }
  const buf = new Uint8Array(ED25519_PUB_MULTICODEC.length + 32);
  buf.set(ED25519_PUB_MULTICODEC, 0);
  buf.set(pubkey, ED25519_PUB_MULTICODEC.length);
  return "z" + base58btcEncode(buf);
}

/* ---------- hex ---------------------------------------------------------- */

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += bytes[i]!.toString(16).padStart(2, "0");
  return out;
}
