// Signed envelope §11.2 — browser side.
//
// A POST to `/mcp/primitives/write` carries `params._envelope` alongside
// the rest of `params`. The server recomputes params_hash over the
// canonicalized params minus `_envelope` and verifies the Ed25519
// signature over canonicalized(envelope minus proof).
//
// Two signing paths supported:
//
//   - Owner path: `verificationMethod = "{iss}#{sphere}"`; `mandate`
//     omitted. The server resolves the sphere key via the subject's
//     did.json.
//   - Delegate path: `verificationMethod = <multibase Ed25519 pubkey>`;
//     `mandate` REQUIRED (carries the full §4.2 Mandate). The server
//     refuses any multibase-keyed envelope without an attached mandate.

import { sha256 } from "@noble/hashes/sha2";

import { sign, type KeyPair } from "./ed25519.js";
import { base64url, bytesToHex } from "./encoding.js";
import { canonicalize } from "./canonical.js";
import type { SignedMandate } from "./mandate.js";

export interface EnvelopeProof {
  readonly type: "Ed25519Signature2020";
  readonly verificationMethod: string;
  readonly created: string;
  readonly proofValue: string;
}

export interface SignedEnvelope {
  readonly "aithos-envelope": "0.1.0";
  readonly iss: string;
  readonly aud: string;
  readonly method: string;
  readonly iat: number;
  readonly exp: number;
  readonly nonce: string;
  readonly params_hash: string;
  /**
   * Full signed mandate — ONLY present when the caller is a delegate
   * signing under that mandate. Server rejects a multibase-keyed
   * envelope without this field.
   */
  readonly mandate?: SignedMandate;
  readonly proof: EnvelopeProof;
}

export interface BuildEnvelopeArgs {
  /** Issuer DID — root DID of the subject, not the delegate's ID. */
  readonly iss: string;
  /** Full URL of the write endpoint, matches what CloudFront routes to the Lambda. */
  readonly aud: string;
  /** Fully-qualified JSON-RPC method, e.g. `aithos.publish_identity`. */
  readonly method: string;
  /**
   * Verification method the server should resolve to a pubkey. Two shapes:
   *   - `{iss}#{sphere}` (DID URL) — owner direct signing.
   *   - a bare multibase Ed25519 pubkey — delegate signing. MUST be paired
   *     with `mandate`.
   */
  readonly verificationMethod: string;
  /** Params object EXCLUDING `_envelope` (that's what params_hash commits to). */
  readonly params: unknown;
  /** Signing keypair (matches `verificationMethod`). */
  readonly signer: KeyPair;
  /** Lifetime in seconds; default 120. The server caps at 300. */
  readonly ttlSeconds?: number;
  /**
   * Full signed mandate; REQUIRED when `verificationMethod` is a bare
   * multibase key. Omit for owner-path envelopes.
   */
  readonly mandate?: SignedMandate;
}

export function buildSignedEnvelope(args: BuildEnvelopeArgs): SignedEnvelope {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + (args.ttlSeconds ?? 120);
  const nonce = generateNonce();
  const paramsHash = "sha256-" + bytesToHex(
    sha256(new TextEncoder().encode(canonicalize(args.params))),
  );

  // Canonicalize the payload that gets signed. Mandate is included when
  // present so the signature commits to the delegation context — the
  // server can't swap the mandate out from under the caller.
  const unsigned = {
    "aithos-envelope": "0.1.0" as const,
    iss: args.iss,
    aud: args.aud,
    method: args.method,
    iat,
    exp,
    nonce,
    params_hash: paramsHash,
    ...(args.mandate ? { mandate: args.mandate } : {}),
  };

  const sigBytes = sign(
    new TextEncoder().encode(canonicalize(unsigned)),
    args.signer.seed,
  );

  return {
    ...unsigned,
    proof: {
      type: "Ed25519Signature2020",
      verificationMethod: args.verificationMethod,
      created: new Date(iat * 1000).toISOString(),
      proofValue: base64url(sigBytes),
    },
  };
}

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}
