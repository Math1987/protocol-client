// Client-side mandate signing.
//
// Mirrors protocol-core's `createMandate` in a browser-safe form: no
// node:crypto, no node:fs, no `ulid` dep. A signed mandate produced here
// is byte-identical to one produced by the reference CLI as far as the
// server-side `verifyMandate` is concerned (same canonicalization, same
// Ed25519 signature scheme, same verification method URL convention).
//
// Spec: §4.2 "Mandate envelope".

import { canonicalize } from "./canonical.js";
import { sign } from "./ed25519.js";
import { base64url } from "./encoding.js";
import type { BrowserIdentity, Sphere } from "./identity.js";
import { sphereDidUrl } from "./identity.js";

export const MANDATE_VERSION_CURRENT = "0.3.0" as const;

/**
 * Scopes a mandate may NEVER carry. Mirrors protocol-core's
 * `FORBIDDEN_SCOPES`. Surfaced here so the mint UI can block the user
 * BEFORE we call signMandate, which would otherwise reject them server
 * side.
 */
export const FORBIDDEN_SCOPES: ReadonlySet<string> = new Set([
  "mandate.issue",
  "mandate.revoke",
  "identity.rotate-keys",
  "identity.destroy",
]);

/**
 * Scopes implying a write operation. A mandate carrying any of these
 * MUST bind to a specific delegate key (grantee.pubkey), per §4.5.4.
 */
const WRITE_SCOPE_PREFIX = "ethos.write.";
function hasWriteScope(scopes: readonly string[]): boolean {
  return scopes.some((s) => s.startsWith(WRITE_SCOPE_PREFIX));
}

export interface Grantee {
  readonly id: string;
  readonly label?: string;
  /** Ed25519 pubkey multibase (z…) — required for sealed-zone delegates. */
  readonly pubkey?: string;
}

export interface MandateConstraints {
  readonly domains?: readonly string[];
  readonly rate_limit?: Readonly<Record<string, number>>;
  readonly require_counter_sign?: readonly string[];
}

export interface SignedMandate {
  readonly "aithos-mandate": typeof MANDATE_VERSION_CURRENT;
  readonly id: string;
  readonly issuer: string;
  readonly issued_by_key: string;
  readonly grantee: Grantee;
  readonly actor_sphere: Sphere;
  readonly scopes: readonly string[];
  readonly constraints?: MandateConstraints;
  readonly not_before: string;
  readonly not_after: string;
  readonly issued_at: string;
  readonly nonce: string;
  readonly signature: {
    readonly alg: "ed25519";
    readonly key: string;
    readonly value: string;
  };
}

export interface SignMandateArgs {
  readonly issuer: BrowserIdentity;
  readonly actorSphere: Sphere;
  readonly grantee: Grantee;
  readonly scopes: readonly string[];
  readonly ttlSeconds: number;
  readonly constraints?: MandateConstraints;
  readonly notBefore?: Date;
}

/**
 * Build + sign a mandate in one pass. Throws if the caller passes
 * forbidden scopes or a write scope without grantee.pubkey.
 */
export function signMandate(args: SignMandateArgs): SignedMandate {
  for (const scope of args.scopes) {
    if (FORBIDDEN_SCOPES.has(scope)) {
      throw new Error(
        `scope "${scope}" can never be delegated (forbidden by §11.7)`,
      );
    }
  }
  if (hasWriteScope(args.scopes) && !args.grantee.pubkey) {
    throw new Error(
      `write mandate requires grantee.pubkey so the delegate signer can be bound (§4.5.4)`,
    );
  }
  validateScopesAgainstSphere(args.scopes, args.actorSphere);

  const now = args.notBefore ?? new Date();
  const notAfter = new Date(now.getTime() + args.ttlSeconds * 1000);
  const nonceBytes = new Uint8Array(9); // 72 bits of entropy
  crypto.getRandomValues(nonceBytes);
  const nonce = base64url(nonceBytes);

  const keyUrl = sphereDidUrl(args.issuer, args.actorSphere);
  const unsigned = {
    "aithos-mandate": MANDATE_VERSION_CURRENT,
    id: `mandate_${generateUlid()}`,
    issuer: args.issuer.did,
    issued_by_key: keyUrl,
    grantee: args.grantee,
    actor_sphere: args.actorSphere,
    scopes: [...args.scopes],
    ...(args.constraints ? { constraints: args.constraints } : {}),
    not_before: now.toISOString(),
    not_after: notAfter.toISOString(),
    issued_at: new Date().toISOString(),
    nonce,
    signature: {
      alg: "ed25519" as const,
      key: keyUrl,
      value: "",
    },
  };

  const sigBytes = sign(
    new TextEncoder().encode(canonicalize(unsigned)),
    args.issuer[args.actorSphere].seed,
  );
  return {
    ...unsigned,
    signature: { ...unsigned.signature, value: base64url(sigBytes) },
  } as SignedMandate;
}

/**
 * Validate the scope → actor_sphere relationship. Mirrors protocol-core's
 * `validateScopesAgainstSphere` byte-for-byte so we fail client-side with
 * the same errors the server would emit. If we get any of this wrong,
 * `publish_mandate` will still reject the envelope — this is for UX.
 *
 * Rules:
 *   - Each `ethos.write.X` scope requires `actor_sphere === X` exactly
 *     (a self-sphere mandate cannot bundle a circle write, because the
 *     signing key must match the target zone).
 *   - The `public` sphere is heavily restricted: only
 *     `ethos.read.public`, `ethos.read.all`, `ethos.write.public`, and
 *     `gamma.read`. Any other scope is rejected.
 *   - For circle/self sphere, read scopes and gamma.read are unconstrained.
 */
function validateScopesAgainstSphere(
  scopes: readonly string[],
  sphere: Sphere,
): void {
  for (const s of scopes) {
    if (s === "ethos.write.public" && sphere !== "public") {
      throw new Error(
        `scope ${s} requires actor_sphere=public (got ${sphere})`,
      );
    }
    if (s === "ethos.write.circle" && sphere !== "circle") {
      throw new Error(
        `scope ${s} requires actor_sphere=circle (got ${sphere})`,
      );
    }
    if (s === "ethos.write.self" && sphere !== "self") {
      throw new Error(
        `scope ${s} requires actor_sphere=self (got ${sphere})`,
      );
    }
  }
  if (sphere === "public") {
    for (const s of scopes) {
      const ok =
        s === "ethos.read.public" ||
        s === "ethos.read.all" ||
        s === "ethos.write.public" ||
        s === "gamma.read";
      if (!ok) {
        throw new Error(
          `scope ${s} is not permitted for the public sphere`,
        );
      }
    }
  }
}

/* -------------------------------------------------------------------------- */
/*  ULID (monotonic-ish, browser-safe)                                        */
/* -------------------------------------------------------------------------- */

// Crockford base32 alphabet — matches the ULID spec.
const ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Generate a 26-char ULID.
 *
 * 48-bit timestamp (10 chars) + 80-bit randomness (16 chars). We don't
 * bother with per-process monotonic guarantees — mandate ids have enough
 * randomness to never collide across a browser session.
 */
export function generateUlid(): string {
  const ts = Date.now();
  const timeChars = new Array<string>(10);
  let t = ts;
  for (let i = 9; i >= 0; i--) {
    timeChars[i] = ULID_ALPHABET[t & 0x1f]!;
    t = Math.floor(t / 32);
  }
  const rnd = new Uint8Array(10);
  crypto.getRandomValues(rnd);
  const rndChars = new Array<string>(16);
  // 10 bytes = 80 bits. Encode as 16 base32 chars (5 bits each).
  let bitBuf = 0;
  let bitLen = 0;
  let outIdx = 0;
  for (let i = 0; i < rnd.length; i++) {
    bitBuf = (bitBuf << 8) | rnd[i]!;
    bitLen += 8;
    while (bitLen >= 5) {
      bitLen -= 5;
      const v = (bitBuf >> bitLen) & 0x1f;
      rndChars[outIdx++] = ULID_ALPHABET[v]!;
    }
  }
  return timeChars.join("") + rndChars.join("");
}
