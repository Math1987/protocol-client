// Onboarding orchestration — browser-side.
//
// Given a handle, display name, and first public section body, this module:
//   1. generates a fresh identity (4 Ed25519 keypairs in memory)
//   2. signs the did.json
//   3. posts `aithos.publish_identity` with a root-signed envelope
//   4. builds + signs the first edition (public zone only, MVP)
//   5. posts `aithos.publish_ethos_edition` with a public-sphere-signed envelope
//   6. returns the identity + metadata so the UI can render a success page and
//      offer a recovery-file download

import {
  createBrowserIdentity,
  signedDidDocument,
  type BrowserIdentity,
  type DidDocument,
} from "./crypto/identity.js";
import {
  buildSignedFirstEdition,
  type Manifest,
} from "./crypto/manifest.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";

const WRITE_ENDPOINT =
  "https://api.aithos.be/mcp/primitives/write";

export interface OnboardArgs {
  readonly handle: string;
  readonly displayName: string;
  readonly publicTitle: string;
  readonly publicBody: string;
  readonly tags?: readonly string[];
}

export interface OnboardResult {
  readonly identity: BrowserIdentity;
  readonly didDocument: DidDocument;
  readonly manifest: Manifest;
  readonly recoveryBlob: Blob;
}

export class OnboardError extends Error {
  readonly step: "publish_identity" | "publish_ethos_edition" | "network" | "validation";
  readonly data: Record<string, unknown> | undefined;

  constructor(step: OnboardError["step"], message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "OnboardError";
    this.step = step;
    this.data = data;
  }
}

/**
 * Run the full onboarding flow. Returns the new identity + signed docs.
 * Throws {@link OnboardError} with a `step` tag if any stage fails.
 */
export async function runOnboarding(args: OnboardArgs): Promise<OnboardResult> {
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/i.test(args.handle)) {
    throw new OnboardError(
      "validation",
      "handle must be 1-63 chars, alphanumerics + '-' / '_' only",
    );
  }
  if (!args.publicTitle.trim()) {
    throw new OnboardError("validation", "public title cannot be empty");
  }

  /* ---- 1. fresh identity ---- */
  const identity = createBrowserIdentity(args.handle, args.displayName);

  /* ---- 2. signed did.json ---- */
  const signedDoc = signedDidDocument(identity);

  /* ---- 3. POST publish_identity ---- */
  const publishIdentityParams = {
    did_document: signedDoc,
    handle: identity.handle,
    display_name: identity.displayName,
  };
  const identityEnv = buildSignedEnvelope({
    iss: identity.did,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_identity",
    verificationMethod: `${identity.did}#root`,
    params: publishIdentityParams,
    signer: identity.root,
  });
  await callWrite(
    "aithos.publish_identity",
    { ...publishIdentityParams, _envelope: identityEnv },
    "publish_identity",
  );

  /* ---- 4. first edition ---- */
  const { manifest, publicMarkdownBytes } = buildSignedFirstEdition({
    identity,
    signedDidDoc: signedDoc,
    publicTitle: args.publicTitle,
    publicBody: args.publicBody,
    tags: args.tags,
  });

  /* ---- 5. POST publish_ethos_edition ---- */
  const editionParams = {
    manifest,
    zones: {
      public: { bytes_base64: bytesToBase64Std(publicMarkdownBytes) },
    },
  };
  const editionEnv = buildSignedEnvelope({
    iss: identity.did,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_ethos_edition",
    verificationMethod: `${identity.did}#public`,
    params: editionParams,
    signer: identity.public,
  });
  await callWrite(
    "aithos.publish_ethos_edition",
    { ...editionParams, _envelope: editionEnv },
    "publish_ethos_edition",
  );

  /* ---- 6. recovery blob (plaintext v1; encrypted in a follow-up) ---- */
  const recovery = {
    aithos_recovery_version: "0.1.0-plaintext",
    warning:
      "THIS FILE CONTAINS YOUR PRIVATE KEYS IN PLAINTEXT. Store it offline, never email or upload.",
    handle: identity.handle,
    display_name: identity.displayName,
    did: identity.did,
    created_at: new Date().toISOString(),
    seeds_hex: {
      root: bytesToHexLocal(identity.root.seed),
      public: bytesToHexLocal(identity.public.seed),
      circle: bytesToHexLocal(identity.circle.seed),
      self: bytesToHexLocal(identity.self.seed),
    },
    public_keys_multibase: {
      // Informational, redundant with did.json but useful for quick reconnects
      // without re-deriving via @noble/ed25519 offline.
    },
  };
  const recoveryBlob = new Blob([JSON.stringify(recovery, null, 2) + "\n"], {
    type: "application/json",
  });

  return { identity, didDocument: signedDoc, manifest, recoveryBlob };
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

async function callWrite(
  method: string,
  params: unknown,
  step: OnboardError["step"],
): Promise<void> {
  let res: Response;
  try {
    res = await fetch(WRITE_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: method,
        method,
        params,
      }),
    });
  } catch (e) {
    throw new OnboardError("network", (e as Error).message);
  }
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new OnboardError(step, `${method} failed: ${body.error.message}`, {
      code: body.error.code,
      ...body.error.data,
    });
  }
  if (body.result === undefined) {
    throw new OnboardError(step, `${method} returned no result`);
  }
}

/** Standard base64 with `=` padding — matches `Buffer.from(x).toString("base64")`. */
function bytesToBase64Std(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

function bytesToHexLocal(b: Uint8Array): string {
  let out = "";
  for (let i = 0; i < b.length; i++) out += b[i]!.toString(16).padStart(2, "0");
  return out;
}
