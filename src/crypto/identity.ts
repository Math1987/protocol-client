// In-browser identity creation.
//
// Mirrors @aithos/protocol-core's `createIdentity`, `buildDidDocument` and
// `signDidDocument` — but fully in-memory (no $AITHOS_HOME, no fs). The
// shape produced here must be byte-identical to the CLI's output so the
// server's `verifyDidDocument` round-trips the signature.
//
// Scope: MVP onboarding. We skip `keyAgreement` (X25519) entirely because:
//   - the server's verifyDidDocument only checks the root signature
//   - the MVP edition is public-only, so no zone decryption path is needed
// When we add circle/self decryption later, we'll derive the X25519 keys
// from the Ed25519 seeds and add the keyAgreement block.

import * as ed from "@noble/ed25519";
import { x25519 } from "@noble/curves/ed25519";

import { generateKeyPair, sign, type KeyPair } from "./ed25519.js";
import {
  base64url,
  ed25519PublicKeyToMultibase,
  x25519PublicKeyToMultibase,
} from "./encoding.js";
import { canonicalize } from "./canonical.js";
import { edSeedToX25519Secret } from "./kex.js";

export type Sphere = "public" | "circle" | "self";
export const SPHERES: readonly Sphere[] = ["public", "circle", "self"];

export interface BrowserIdentity {
  readonly handle: string;
  readonly displayName: string;
  readonly did: string;
  /** Keys kept in memory. ONLY expose via the recovery bundle. */
  readonly root: KeyPair;
  readonly public: KeyPair;
  readonly circle: KeyPair;
  readonly self: KeyPair;
}

export interface VerificationMethod {
  readonly id: string;
  readonly type: "Ed25519VerificationKey2020";
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface KeyAgreementMethod {
  readonly id: string;
  readonly type: "X25519KeyAgreementKey2020";
  readonly controller: string;
  readonly publicKeyMultibase: string;
}

export interface DidDocumentProof {
  readonly type: "Ed25519Signature2020";
  readonly created: string;
  readonly verificationMethod: string;
  readonly proofPurpose: "assertionMethod";
  readonly proofValue: string;
}

export interface DidDocument {
  readonly "@context": readonly string[];
  readonly id: string;
  readonly verificationMethod: readonly VerificationMethod[];
  readonly keyAgreement?: readonly KeyAgreementMethod[];
  readonly aithos: {
    readonly version: "0.1.0";
    readonly display_name?: string;
    readonly created_at: string;
    readonly rotated: readonly unknown[];
  };
  readonly proof: DidDocumentProof;
}

/** Construct a fresh in-memory identity with 4 keypairs. */
export function createBrowserIdentity(
  handle: string,
  displayName: string,
): BrowserIdentity {
  const root = generateKeyPair();
  const pub = generateKeyPair();
  const circle = generateKeyPair();
  const self = generateKeyPair();
  const did = "did:aithos:" + ed25519PublicKeyToMultibase(root.publicKey);
  return {
    handle,
    displayName,
    did,
    root,
    public: pub,
    circle,
    self,
  };
}

/**
 * Build + sign a did.json document ready to POST via `publish_identity`.
 * Signed with the root key; verificationMethod URL is `{did}#root`.
 */
export function signedDidDocument(identity: BrowserIdentity): DidDocument {
  const did = identity.did;
  const now = new Date().toISOString();

  // X25519 key-agreement keys — one per sphere, derived deterministically
  // from the same seed that produced the Ed25519 signing key. Including
  // them here is what allows zone encryption (circle/self) to resolve the
  // recipient's public kex key from the DID document alone.
  const keyAgreement: KeyAgreementMethod[] = SPHERES.map((sphere) => {
    const xSk = edSeedToX25519Secret(identity[sphere].seed);
    const xPk = x25519.getPublicKey(xSk);
    xSk.fill(0); // zeroize the derived secret; we only needed the public key
    return {
      id: `${did}#${sphere}-kex`,
      type: "X25519KeyAgreementKey2020" as const,
      controller: did,
      publicKeyMultibase: x25519PublicKeyToMultibase(xPk),
    };
  });

  const verificationMethod: VerificationMethod[] = SPHERES.map((sphere) => ({
    id: `${did}#${sphere}`,
    type: "Ed25519VerificationKey2020",
    controller: did,
    publicKeyMultibase: ed25519PublicKeyToMultibase(identity[sphere].publicKey),
  }));

  // Build the unsigned doc, canonicalize, sign, then attach the proofValue.
  const unsigned = {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://aithos.dev/spec/v0.1",
    ],
    id: did,
    verificationMethod,
    keyAgreement,
    aithos: {
      version: "0.1.0" as const,
      display_name: identity.displayName,
      created_at: now,
      rotated: [] as unknown[],
    },
    proof: {
      type: "Ed25519Signature2020" as const,
      created: now,
      verificationMethod: `${did}#root`,
      proofPurpose: "assertionMethod" as const,
      proofValue: "",
    },
  };

  const bytes = new TextEncoder().encode(canonicalize(unsigned));
  const sig = sign(bytes, identity.root.seed);

  return {
    ...unsigned,
    proof: { ...unsigned.proof, proofValue: base64url(sig) },
  };
}

/** DID URL for a sphere verification method, e.g. `did:aithos:z…#public`. */
export function sphereDidUrl(identity: BrowserIdentity, sphere: Sphere): string {
  return `${identity.did}#${sphere}`;
}

/* -------------------------------------------------------------------------- */
/*  Re-hydration from persisted keystore                                      */
/* -------------------------------------------------------------------------- */

interface StoredSeeds {
  readonly handle: string;
  readonly displayName: string;
  readonly did: string;
  readonly seeds: {
    readonly root: string;
    readonly public: string;
    readonly circle: string;
    readonly self: string;
  };
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error("hex must be even-length");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return out;
}

function keyPairFromHexSeed(hex: string): KeyPair {
  const seed = hexToBytes(hex);
  return { seed, publicKey: ed.getPublicKey(seed) };
}

/**
 * Rehydrate a {@link BrowserIdentity} from the hex-encoded seeds that the
 * IndexedDB keystore persists. Public keys are re-derived client-side.
 */
export function browserIdentityFromStored(s: StoredSeeds): BrowserIdentity {
  return {
    handle: s.handle,
    displayName: s.displayName,
    did: s.did,
    root: keyPairFromHexSeed(s.seeds.root),
    public: keyPairFromHexSeed(s.seeds.public),
    circle: keyPairFromHexSeed(s.seeds.circle),
    self: keyPairFromHexSeed(s.seeds.self),
  };
}
