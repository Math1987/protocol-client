// End-to-end mint of a delegate bundle.
//
// Given a connected owner identity + a scope set + a TTL, this:
//   1. generates a fresh Ed25519 keypair for the grantee,
//   2. signs a mandate binding that pubkey + chosen actor_sphere,
//   3. posts `aithos.publish_mandate` to the write API,
//   4. returns the shareable bundle (the grantee-side .aithos-delegate.json
//      that can be imported via /delegate).
//
// The grantee seed never leaves this function's call site except via the
// returned bundle blob — the caller is expected to either hand it to the
// user as a downloadable file or to the delegate directly through a
// secure channel. It is NOT persisted in the owner's IndexedDB.

import { browserIdentityFromStored } from "./crypto/identity.js";
import { generateKeyPair } from "./crypto/ed25519.js";
import {
  ed25519PublicKeyToMultibase,
  bytesToHex,
} from "./crypto/encoding.js";
import {
  signMandate,
  type Grantee,
  type MandateConstraints,
  type SignedMandate,
} from "./crypto/mandate.js";
import type { Sphere } from "./crypto/identity.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import type { StoredIdentity } from "./storage-types.js";

const WRITE_ENDPOINT =
  "https://api.aithos.be/mcp/primitives/write";

const DELEGATE_BUNDLE_VERSION = "0.1.0";

export interface MintArgs {
  readonly owner: StoredIdentity;
  readonly granteeId: string;
  readonly granteeLabel?: string;
  /**
   * Which of the owner's spheres signs the mandate. Upper-bounds what
   * scopes can be delegated — see `validateScopesAgainstSphere` in
   * crypto/mandate.ts.
   */
  readonly actorSphere: Sphere;
  readonly scopes: readonly string[];
  readonly ttlSeconds: number;
  readonly constraints?: MandateConstraints;
}

export interface MintResult {
  readonly mandate: SignedMandate;
  /**
   * The shareable file contents. The grantee imports this via /delegate
   * (see keystore.parseDelegateBundle for the expected shape).
   */
  readonly bundle: {
    readonly aithos_delegate_version: string;
    readonly mandate: SignedMandate;
    readonly delegate_seed_hex: string;
  };
  /** Pre-serialised Blob, convenient for `URL.createObjectURL`. */
  readonly bundleBlob: Blob;
}

export class MintError extends Error {
  readonly step: string;
  readonly data?: Record<string, unknown>;
  constructor(step: string, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "MintError";
    this.step = step;
    this.data = data;
  }
}

export async function mintDelegateBundle(args: MintArgs): Promise<MintResult> {
  const browserId = browserIdentityFromStored(args.owner);

  // 1. Fresh Ed25519 keypair for the grantee. The seed travels to the
  //    delegate in the bundle; the pubkey is baked into the mandate.
  const granteeKp = generateKeyPair();
  const granteePubMb = ed25519PublicKeyToMultibase(granteeKp.publicKey);

  const grantee: Grantee = {
    id: args.granteeId,
    pubkey: granteePubMb,
    ...(args.granteeLabel ? { label: args.granteeLabel } : {}),
  };

  // 2. Sign the mandate with the owner's requested sphere.
  let mandate: SignedMandate;
  try {
    mandate = signMandate({
      issuer: browserId,
      actorSphere: args.actorSphere,
      grantee,
      scopes: args.scopes,
      ttlSeconds: args.ttlSeconds,
      ...(args.constraints ? { constraints: args.constraints } : {}),
    });
  } catch (e) {
    throw new MintError("sign", (e as Error).message);
  }

  // 3. POST `aithos.publish_mandate`. The envelope is signed by the
  //    owner's root key — publish_mandate itself is root-only (spec
  //    §11.7: `mandate.issue` is a forbidden scope).
  const params = { mandate };
  const envelope = buildSignedEnvelope({
    iss: browserId.did,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_mandate",
    verificationMethod: `${browserId.did}#root`,
    params,
    signer: browserId.root,
  });

  const res = await fetch(WRITE_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.publish_mandate",
      method: "aithos.publish_mandate",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new MintError("publish_mandate", body.error.message, {
      code: body.error.code,
      ...(body.error.data ?? {}),
    });
  }

  // 4. Package the bundle for the delegate.
  const bundle = {
    aithos_delegate_version: DELEGATE_BUNDLE_VERSION,
    mandate,
    delegate_seed_hex: bytesToHex(granteeKp.seed),
  };
  const bundleBlob = new Blob([JSON.stringify(bundle, null, 2)], {
    type: "application/json",
  });

  return { mandate, bundle, bundleBlob };
}

/* -------------------------------------------------------------------------- */
/*  Defaults & display helpers                                                */
/* -------------------------------------------------------------------------- */

export const DEFAULT_READ_SCOPES: readonly string[] = [
  "ethos.read.circle",
];

/** A small set of human-readable TTL presets for the form. */
export const TTL_PRESETS: readonly { readonly label: string; readonly seconds: number }[] = [
  { label: "1 heure", seconds: 60 * 60 },
  { label: "24 heures", seconds: 24 * 60 * 60 },
  { label: "7 jours", seconds: 7 * 24 * 60 * 60 },
  { label: "30 jours", seconds: 30 * 24 * 60 * 60 },
];
