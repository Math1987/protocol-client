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

/* -------------------------------------------------------------------------- */
/*  signAndPublishMandate — for callers who already hold a grantee keypair    */
/* -------------------------------------------------------------------------- */

/**
 * Args for `signAndPublishMandate`. Like `MintArgs` but the caller provides
 * a fully-formed `Grantee` (including `pubkey`) instead of asking us to
 * generate a keypair.
 *
 * This is what extension-style integrations want: the extension already
 * holds its own delegate keypair, so the public half goes into the mandate
 * here while the seed never leaves the extension.
 */
export interface SignAndPublishMandateArgs {
  readonly owner: StoredIdentity;
  readonly grantee: Grantee;
  readonly actorSphere: Sphere;
  readonly scopes: readonly string[];
  readonly ttlSeconds: number;
  readonly constraints?: MandateConstraints;
  /** Override the default `https://api.aithos.be/mcp/primitives/write`. */
  readonly writeEndpoint?: string;
}

/**
 * Sign + publish a mandate without generating a grantee keypair. Throws
 * `MintError` with `step` = `"sign"` or `"publish_mandate"` on failure.
 *
 * For the simpler "I want to mint AND get a downloadable bundle" use case,
 * see `mintDelegateBundle`, which wraps this after generating a keypair.
 */
export async function signAndPublishMandate(
  args: SignAndPublishMandateArgs,
): Promise<SignedMandate> {
  const browserId = browserIdentityFromStored(args.owner);
  const writeEndpoint = args.writeEndpoint ?? WRITE_ENDPOINT;

  let mandate: SignedMandate;
  try {
    mandate = signMandate({
      issuer: browserId,
      actorSphere: args.actorSphere,
      grantee: args.grantee,
      scopes: args.scopes,
      ttlSeconds: args.ttlSeconds,
      ...(args.constraints ? { constraints: args.constraints } : {}),
    });
  } catch (e) {
    throw new MintError("sign", (e as Error).message);
  }

  const params = { mandate };
  const envelope = buildSignedEnvelope({
    iss: browserId.did,
    aud: writeEndpoint,
    method: "aithos.publish_mandate",
    verificationMethod: `${browserId.did}#root`,
    params,
    signer: browserId.root,
  });

  const res = await fetch(writeEndpoint, {
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

  return mandate;
}

/* -------------------------------------------------------------------------- */
/*  mintDelegateBundle — generates keypair + signs + bundles                  */
/* -------------------------------------------------------------------------- */

export async function mintDelegateBundle(args: MintArgs): Promise<MintResult> {
  // 1. Fresh Ed25519 keypair for the grantee.
  const granteeKp = generateKeyPair();
  const granteePubMb = ed25519PublicKeyToMultibase(granteeKp.publicKey);

  const grantee: Grantee = {
    id: args.granteeId,
    pubkey: granteePubMb,
    ...(args.granteeLabel ? { label: args.granteeLabel } : {}),
  };

  // 2 + 3. Delegate the sign/publish to the lower-level helper so the two
  // entry points stay in sync (and we get one place to fix bugs).
  const mandate = await signAndPublishMandate({
    owner: args.owner,
    grantee,
    actorSphere: args.actorSphere,
    scopes: args.scopes,
    ttlSeconds: args.ttlSeconds,
    ...(args.constraints ? { constraints: args.constraints } : {}),
  });

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
