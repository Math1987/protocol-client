// @aithos/protocol-client — public API surface.
//
// Alpha phase: we re-export the full module surface to let consumers
// iterate fast. Names will be curated / narrowed before 0.1.0 stable.
//
// Import shape:
//   import { readRpc, buildSignedEnvelope, createBrowserIdentity } from "@aithos/protocol-client";
//
// Four naming collisions inherited from the monorepo are resolved here by
// picking a canonical source per name:
//   - `SealedZone`       → delegate-recipients (the zone enum "circle" | "self").
//                          crypto/encrypt's local `SealedZone` result object
//                          stays internal — use `encryptZone()` directly.
//   - `DidDocument`      → types.ts (the wire-format shape). crypto/identity's
//                          authoring shape stays internal to that module.
//   - `ZoneCipher`       → crypto/decrypt (the canonical shape).
//   - `Manifest`         → types.ts (wire-format). crypto/manifest's authoring
//                          structure stays internal; its builders are exported.

export const VERSION = "0.1.0-alpha.5";

// --- API client (JSON-RPC 2.0 to api.aithos.be) ---
export * from "./api.js";

// --- Connect handshake parser + sphere inference ---
export * from "./connect-request.js";

// --- DID helpers ---
export * from "./did.js";

// --- Wire-format types (canonical for DidDocument, Manifest) ---
export * from "./types.js";

// --- Storage contracts (what a keystore impl must produce/consume) ---
export * from "./storage-types.js";

// --- Zone parser (markdown → sections) ---
export * from "./zone-parser.js";

// --- Ethos edition editor (high-level: load, modify, publish) ---
export * from "./editor.js";

// --- Delegate recipients resolution (canonical for SealedZone) ---
export * from "./delegate-recipients.js";

// --- Mandate mint (build + sign a delegate bundle) ---
export * from "./mandate-mint.js";

// --- Onboarding (create identity, publish first edition) ---
export * from "./onboarding.js";

// --- Cryptography primitives ---
export * from "./crypto/canonical.js";
export * from "./crypto/ed25519.js";
export * from "./crypto/encoding.js";

// crypto/encrypt — exclude local SealedZone (canonical is from delegate-recipients).
export {
  encryptZone,
  type EncryptRecipient,
  type SealedWrap,
} from "./crypto/encrypt.js";

// crypto/decrypt — canonical for ZoneCipher.
export * from "./crypto/decrypt.js";

export * from "./crypto/envelope.js";

// crypto/identity — exclude local DidDocument (canonical is types.ts).
export {
  type BrowserIdentity,
  type DidDocumentProof,
  type KeyAgreementMethod,
  SPHERES,
  type Sphere,
  type VerificationMethod,
  browserIdentityFromStored,
  createBrowserIdentity,
  signedDidDocument,
  sphereDidUrl,
} from "./crypto/identity.js";

export * from "./crypto/kex.js";
export * from "./crypto/mandate.js";

// crypto/manifest — exclude ZoneCipher (→ decrypt) and Manifest (→ types).
export {
  type BuildDelegatePrivateEditionArgs,
  type BuildDelegatePrivateEditionResult,
  type BuildDelegatePublicEditionArgs,
  type BuildDelegatePublicEditionResult,
  type BuildFirstEditionArgs,
  type BuildFirstEditionResult,
  type BuildNextEditionArgs,
  type BuildNextEditionResult,
  type DelegatePublicSigner,
  type ManifestSignature,
  type Section,
  type ZoneDoc,
  type ZoneManifest,
  type ZoneSignature,
  type ZoneWrap,
  buildSignedFirstEdition,
  buildSignedNextEdition,
  buildSignedNextEditionAsDelegatePrivate,
  buildSignedNextEditionAsDelegatePublic,
  canonicalManifestHashHex,
} from "./crypto/manifest.js";
