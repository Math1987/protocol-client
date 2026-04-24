// High-level orchestrator for editing a live ethos.
//
// Takes the authenticated identity (from the keystore), fetches the current
// manifest + zone bytes, applies a public-zone edit (add / modify / delete),
// builds + signs a new edition, and POSTs `aithos.publish_ethos_edition`.
//
// Scope: public zone only for MVP. Circle/self bytes are fetched and
// rolled forward unchanged to avoid breaking ethos that have them.

import type { StoredDelegate, StoredIdentity } from "./storage-types.js";
import { browserIdentityFromStored } from "./crypto/identity.js";
import {
  buildSignedNextEdition,
  buildSignedNextEditionAsDelegatePrivate,
  buildSignedNextEditionAsDelegatePublic,
  type Manifest,
  type Section,
} from "./crypto/manifest.js";
import { buildSignedEnvelope } from "./crypto/envelope.js";
import { readRpc } from "./api.js";
import {
  tryDecryptAsDelegate,
  tryDecryptAsOwner,
  type ZoneCipher,
} from "./crypto/decrypt.js";
import { sha256 } from "@noble/hashes/sha2";
import { bytesToHex } from "./crypto/encoding.js";
// Side-effect import: wires sha512Sync into @noble/ed25519 so the Ed25519
// helpers below work without awaiting a WebCrypto handshake.
import * as ed25519Init from "./crypto/ed25519.js";
void ed25519Init;
import { getPublicKey } from "@noble/ed25519";
import type { DidDocument } from "./crypto/identity.js";
import {
  fetchActiveDelegateRecipients,
  fetchZoneRecipientsForDelegateWrite,
  type DelegateRecipientsByZone,
} from "./delegate-recipients.js";
import type { SignedMandate } from "./crypto/mandate.js";

const WRITE_ENDPOINT =
  "https://api.aithos.be/mcp/primitives/write";

export interface EditSnapshot {
  readonly manifest: Manifest;
  readonly publicSections: readonly Section[];
  /**
   * Decrypted sections for the private zones, indexed by sphere name.
   * Only populated if we have the sphere seed AND decryption succeeds.
   * A zone that's declared in the manifest but can't be decrypted (no
   * matching wrap, bad seed) is represented by an empty array + a
   * `zoneDecryptErrors` entry.
   */
  readonly circleSections?: readonly Section[];
  readonly selfSections?: readonly Section[];
  readonly zoneDecryptErrors?: Partial<Record<"circle" | "self", string>>;
  readonly zoneBytes: {
    readonly public?: Uint8Array;
    readonly circle?: Uint8Array;
    readonly self?: Uint8Array;
  };
}

export class EditError extends Error {
  readonly step: string;
  readonly data?: Record<string, unknown>;
  constructor(step: string, message: string, data?: Record<string, unknown>) {
    super(message);
    this.name = "EditError";
    this.step = step;
    this.data = data;
  }
}

/* -------------------------------------------------------------------------- */
/*  Load current state                                                        */
/* -------------------------------------------------------------------------- */

/**
 * Fetch the current manifest, parse the public zone into sections, and
 * download the raw bytes for every zone the manifest declares. Used by
 * the edit UI on entry so every subsequent save can build a valid new
 * edition with rolled-forward zones.
 *
 * When `identity` is supplied, we also attempt to decrypt circle/self
 * zones using the sphere seeds. A zone that can't be unwrapped (no
 * matching recipient in the wraps list) surfaces via
 * `zoneDecryptErrors`. Bytes are always returned regardless of whether
 * decryption succeeded, so the caller can still republish them verbatim.
 *
 * When `delegates` is non-empty, each bundle whose `subjectDid` matches
 * `did` is probed with its own Ed25519 delegate key against every private
 * zone, as a fallback after the owner-seed path. The first delegate seed
 * that successfully unwraps a zone wins — this matters when a subject's
 * ethos is covered by more than one mandate on the same device (e.g.
 * `ethos.read.circle` on mandate A, `ethos.read.self` on mandate B). A
 * hit fills in the matching `circleSections` / `selfSections` just like
 * the owner path; bookkeeping on scope / zone visibility still comes
 * from the mandate downstream.
 *
 * The legacy shape (a single `delegate` or null) is accepted for
 * backwards compatibility at existing call sites.
 */
export async function loadEditSnapshot(
  did: string,
  identity?: StoredIdentity,
  delegates?: StoredDelegate | null | readonly StoredDelegate[],
): Promise<EditSnapshot> {
  const delegatesForSubject: readonly StoredDelegate[] = Array.isArray(
    delegates,
  )
    ? (delegates as readonly StoredDelegate[]).filter(
        (d) => d.subjectDid === did,
      )
    : delegates && (delegates as StoredDelegate).subjectDid === did
      ? [delegates as StoredDelegate]
      : [];
  const [manifestSigned, publicSigned] = await Promise.all([
    readRpc<{ object: Manifest }>("aithos.get_ethos_manifest", { did }),
    readRpc<{ object: { bytes_base64: string; zone: string } }>(
      "aithos.get_ethos_zone",
      { did, zone: "public" },
    ).catch(() => null),
  ]);

  const manifest = manifestSigned.object;
  // Build as a plain mutable object; we freeze-in the readonly shape only
  // when returning from the function.
  const zoneBytes: {
    public?: Uint8Array;
    circle?: Uint8Array;
    self?: Uint8Array;
  } = {};

  if (publicSigned) {
    zoneBytes.public = bytesFromBase64(publicSigned.object.bytes_base64);
  }
  if (manifest.zones.circle) {
    const r = await readRpc<{ object: { bytes_base64: string } }>(
      "aithos.get_ethos_zone",
      { did, zone: "circle" },
    );
    zoneBytes.circle = bytesFromBase64(r.object.bytes_base64);
  }
  if (manifest.zones.self) {
    const r = await readRpc<{ object: { bytes_base64: string } }>(
      "aithos.get_ethos_zone",
      { did, zone: "self" },
    );
    zoneBytes.self = bytesFromBase64(r.object.bytes_base64);
  }

  // Parse public markdown → sections.
  const publicSections = zoneBytes.public
    ? parsePublicSections(new TextDecoder().decode(zoneBytes.public))
    : [];

  // Try to decrypt circle/self if the caller supplied an identity whose
  // sphere seeds match this subject. Any failure is surfaced via
  // zoneDecryptErrors so the UI can explain what's going on instead of
  // silently dropping the zone.
  const zoneDecryptErrors: Record<string, string> = {};
  let circleSections: Section[] | undefined;
  let selfSections: Section[] | undefined;

  const hasDelegates = delegatesForSubject.length > 0;
  if ((identity && identity.did === did) || hasDelegates) {
    for (const zone of ["circle", "self"] as const) {
      const zoneManifest = manifest.zones[zone];
      const bytes = zoneBytes[zone];
      if (!zoneManifest || !bytes) continue;
      const cipher = (zoneManifest as { cipher?: ZoneCipher }).cipher;
      if (!cipher) {
        zoneDecryptErrors[zone] = "manifest.zones." + zone + ".cipher missing";
        continue;
      }

      let plaintext: string | null = null;
      let lastError: string | null = null;

      // Owner path first — if we have the sphere seed and it decrypts,
      // we're done. This matches the original behaviour unchanged.
      if (identity && identity.did === did) {
        const seedHex = identity.seeds[zone];
        const seed = hexToBytes(seedHex);
        try {
          plaintext = tryDecryptAsOwner({
            ciphertext: bytes,
            cipher,
            subjectDid: did,
            sphere: zone,
            sphereSeed: seed,
          });
          if (plaintext === null) {
            lastError = "no wrap matches our sphere kex key";
          }
        } catch (e) {
          lastError = (e as Error).message ?? String(e);
        } finally {
          seed.fill(0);
        }
      }

      // Delegate fallback — try each delegate bundle we hold for this
      // subject until one unwraps the zone. Multiple mandates on the
      // same subject (e.g. a read.circle bundle + a read.self bundle)
      // each carry their own grantee key, and only the one whose key
      // sits in this zone's wrap list can decrypt — so iterating is the
      // only correct option.
      if (plaintext === null && hasDelegates) {
        for (const d of delegatesForSubject) {
          const delegateSeed = hexToBytes(d.delegateSeedHex);
          try {
            plaintext = tryDecryptAsDelegate({
              ciphertext: bytes,
              cipher,
              subjectDid: did,
              granteeId: d.granteeId,
              granteePubkeyMultibase: d.granteePubkeyMultibase,
              delegateSeed,
            });
            if (plaintext !== null) break;
          } catch (e) {
            lastError = (e as Error).message ?? String(e);
          } finally {
            delegateSeed.fill(0);
          }
        }
        if (plaintext === null && !lastError) {
          lastError = "no wrap matches any delegate kex key for this zone";
        }
      }

      if (plaintext === null) {
        if (lastError) zoneDecryptErrors[zone] = lastError;
        continue;
      }
      const sections = parsePublicSections(plaintext); // same format as public
      if (zone === "circle") circleSections = sections;
      else selfSections = sections;
    }
  }

  return {
    manifest,
    publicSections,
    zoneBytes,
    ...(circleSections ? { circleSections } : {}),
    ...(selfSections ? { selfSections } : {}),
    ...(Object.keys(zoneDecryptErrors).length > 0
      ? { zoneDecryptErrors: zoneDecryptErrors as Partial<Record<"circle" | "self", string>> }
      : {}),
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

/* -------------------------------------------------------------------------- */
/*  Section mutations                                                         */
/* -------------------------------------------------------------------------- */

export interface AddSectionInput {
  readonly title: string;
  readonly body: string;
  readonly tags?: readonly string[];
}

/** Append a new section to the given list, returning a new array. */
export function addSectionToList(
  current: readonly Section[],
  input: AddSectionInput,
): Section[] {
  const section: Section = {
    id: "sec_" + randomHex(12),
    title: input.title,
    body: input.body,
    gamma_ref: "gamma_none_" + randomHex(24),
    ...(input.tags && input.tags.length > 0 ? { tags: input.tags } : {}),
  };
  return [...current, section];
}

export interface ModifySectionInput {
  readonly sectionId: string;
  readonly title?: string;
  readonly body?: string;
  readonly tags?: readonly string[];
}

export function modifySectionInList(
  current: readonly Section[],
  input: ModifySectionInput,
): Section[] {
  return current.map((s) => {
    if (s.id !== input.sectionId) return s;
    return {
      ...s,
      title: input.title ?? s.title,
      body: input.body ?? s.body,
      ...(input.tags !== undefined
        ? input.tags.length > 0
          ? { tags: input.tags }
          : {}
        : s.tags && s.tags.length > 0
          ? { tags: s.tags }
          : {}),
      // Rotate gamma_ref so the sequence of edits has a unique marker.
      gamma_ref: "gamma_none_" + randomHex(24),
    };
  });
}

export function deleteSectionFromList(
  current: readonly Section[],
  sectionId: string,
): Section[] {
  return current.filter((s) => s.id !== sectionId);
}

/* -------------------------------------------------------------------------- */
/*  Publish                                                                   */
/* -------------------------------------------------------------------------- */

export interface PublishEditArgs {
  readonly identity: StoredIdentity;
  readonly snapshot: EditSnapshot;
  readonly newPublicSections: readonly Section[];
  /** Optional: updated sections for circle — re-seals the zone. */
  readonly newCircleSections?: readonly Section[];
  /** Optional: updated sections for self — re-seals the zone. */
  readonly newSelfSections?: readonly Section[];
  /**
   * Extra delegate recipients to include in the wrap list for each zone,
   * beyond what `fetchActiveDelegateRecipients` discovers via
   * `list_mandates`. Used by the mint flow to guarantee a just-published
   * mandate ends up in the same edition that gets sealed — DynamoDB's
   * index takes a second or two to surface the new row, and we don't
   * want the delegate to see title-only bytes just because they tested
   * too fast. Duplicates (same `didUrl`) are collapsed at the seal
   * layer, so passing a mandate that's ALSO in the index is harmless.
   */
  readonly extraDelegateRecipientsCircle?: readonly import("./crypto/encrypt.js").EncryptRecipient[];
  readonly extraDelegateRecipientsSelf?: readonly import("./crypto/encrypt.js").EncryptRecipient[];
}

export interface PublishEditResult {
  readonly manifest: Manifest;
  /**
   * Per-zone notes on delegate recipients we couldn't seal for. Absent when
   * no active mandate touched a sealed zone. The publish still succeeded —
   * affected delegates will see title-only until the next publish where
   * the problem is resolved.
   */
  readonly delegateSealWarnings?: DelegateRecipientsByZone["errors"];
}

/**
 * Publish a new edition. Always re-bakes the public zone; when
 * `newCircleSections` / `newSelfSections` are supplied, those zones are
 * re-encrypted for the owner AND for every active mandate holder whose
 * scope covers the zone (looked up via `aithos.list_mandates` before we
 * build the manifest). Delegate resolution is best-effort: a failure to
 * resolve one mandate doesn't block the publish, it just surfaces in
 * `delegateSealWarnings`.
 */
export async function publishZoneEdit(
  args: PublishEditArgs,
): Promise<PublishEditResult> {
  const browserId = browserIdentityFromStored(args.identity);

  // Fetch the currently-stored did.json and compute its sha256 — that's
  // what the new edition's `integrity.sha256_of_did_json` must point at.
  // Re-generating locally would drift because the doc's `created_at` is
  // stamped at sign time.
  //
  // In parallel, probe the mandates index for delegates that should
  // receive a wrap on the about-to-be-sealed zones. Both calls are
  // owner-authenticated reads so there's no ordering hazard.
  const [idResp, delegateRecipients] = await Promise.all([
    readRpc<{ object: DidDocument }>("aithos.get_identity", {
      did: browserId.did,
    }),
    fetchActiveDelegateRecipients(browserId.did).catch(() => ({
      circle: [],
      self: [],
      errors: [
        {
          mandate_id: "*",
          zone: "circle" as const,
          reason: "mandate listing unavailable — published for owner only",
        },
      ],
    })),
  ]);
  const didJsonBytes = new TextEncoder().encode(
    JSON.stringify(idResp.object, null, 2) + "\n",
  );
  const didJsonSha256Hex = bytesToHex(sha256(didJsonBytes));

  // Merge discovered + caller-supplied recipients. Dedup by didUrl so a
  // freshly-minted mandate passed in via `extraDelegateRecipients*` does
  // not produce a duplicate wrap when the DDB index catches up between
  // list_mandates and now.
  const mergedCircle = mergeRecipientsByDidUrl(
    delegateRecipients.circle,
    args.extraDelegateRecipientsCircle ?? [],
  );
  const mergedSelf = mergeRecipientsByDidUrl(
    delegateRecipients.self,
    args.extraDelegateRecipientsSelf ?? [],
  );

  const built = buildSignedNextEdition({
    identity: browserId,
    didJsonSha256Hex,
    currentManifest: args.snapshot.manifest,
    currentZoneBytes: {
      public: args.snapshot.zoneBytes.public,
      circle: args.snapshot.zoneBytes.circle,
      self: args.snapshot.zoneBytes.self,
    },
    newPublicSections: args.newPublicSections,
    ...(args.newCircleSections ? { newCircleSections: args.newCircleSections } : {}),
    ...(args.newSelfSections ? { newSelfSections: args.newSelfSections } : {}),
    ...(mergedCircle.length > 0 ? { delegateRecipientsCircle: mergedCircle } : {}),
    ...(mergedSelf.length > 0 ? { delegateRecipientsSelf: mergedSelf } : {}),
  });

  // Assemble the zones payload. The server requires bytes for every
  // zone the new manifest declares.
  const zones: Record<string, { bytes_base64: string }> = {
    public: { bytes_base64: bytesToBase64(built.publicMarkdownBytes) },
  };
  if (built.manifest.zones.circle && built.circleBytes) {
    zones.circle = { bytes_base64: bytesToBase64(built.circleBytes) };
  }
  if (built.manifest.zones.self && built.selfBytes) {
    zones.self = { bytes_base64: bytesToBase64(built.selfBytes) };
  }

  const params = { manifest: built.manifest, zones };
  const envelope = buildSignedEnvelope({
    iss: browserId.did,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_ethos_edition",
    verificationMethod: `${browserId.did}#public`,
    params,
    signer: browserId.public,
  });

  const res = await fetch(WRITE_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.publish_ethos_edition",
      method: "aithos.publish_ethos_edition",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new EditError(
      "publish_ethos_edition",
      body.error.message,
      { code: body.error.code, ...body.error.data },
    );
  }

  return {
    manifest: built.manifest,
    ...(delegateRecipients.errors.length > 0
      ? { delegateSealWarnings: delegateRecipients.errors }
      : {}),
  };
}

/* -------------------------------------------------------------------------- */
/*  Internals                                                                 */
/* -------------------------------------------------------------------------- */

function bytesFromBase64(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin);
}

/* -------------------------------------------------------------------------- */
/*  Publish — delegate path (public zone only, Phase E.1)                     */
/* -------------------------------------------------------------------------- */

export interface PublishAsDelegateArgs {
  /** Active delegate session from IndexedDB (what `/delegate` populated). */
  readonly delegate: StoredDelegate;
  /** Snapshot the delegate is editing — fetched via loadEditSnapshot for its DID. */
  readonly snapshot: EditSnapshot;
  /** New sections for the public zone. The delegate can only touch this zone. */
  readonly newPublicSections: readonly Section[];
}

export interface PublishAsDelegateResult {
  readonly manifest: Manifest;
}

/**
 * Publish a new edition as a delegate. Only the public zone is
 * (re-)signed by this helper — circle / self are rolled forward
 * byte-for-byte from the current manifest. The delegate signs the new
 * zone + the new manifest with its Ed25519 seed, attaches the full
 * §4.2 mandate to the envelope, and POSTs to `aithos.publish_ethos_edition`.
 *
 * Server-side: the envelope verifier (§11.4.5) checks the mandate
 * structure + time window + revocation + grantee.pubkey match; the
 * edition handler then checks `ethos.write.public` is in the mandate's
 * scopes, resolves delegate pubkeys for the manifest signature, and
 * applies the usual chain-integrity rules.
 */
export async function publishPublicZoneAsDelegate(
  args: PublishAsDelegateArgs,
): Promise<PublishAsDelegateResult> {
  const { delegate, snapshot, newPublicSections } = args;

  // Only the public zone can be delegated in this tranche. We catch a
  // common misuse: if a caller drops non-public sections here, we'd
  // silently publish only public and strand the other edits — better
  // to fail loud.
  if (!delegate.mandate || typeof delegate.mandate !== "object") {
    throw new EditError("delegate.mandate", "stored delegate is missing a mandate object");
  }

  // Parse the stored mandate shape as the client-side SignedMandate we
  // own in memory. The bundle imported at /delegate keeps it as a raw
  // Record<string, unknown> so the parser stays forgiving; the subset
  // we need here (id, scopes, grantee, issuer, signature) is asserted
  // at runtime before we touch the envelope.
  const mandate = delegate.mandate as unknown as SignedMandate;
  if (typeof mandate.id !== "string") {
    throw new EditError("delegate.mandate", "mandate.id missing on delegate bundle");
  }
  if (!Array.isArray(mandate.scopes) || !mandate.scopes.includes("ethos.write.public")) {
    throw new EditError(
      "delegate.scope",
      "delegate mandate does not grant ethos.write.public",
      { scopes: mandate.scopes },
    );
  }

  // Fetch did.json so we commit to the exact byte-shape the server
  // holds. The delegate has no way to regenerate it — they don't own
  // the identity — so trusting what the server returns is the only
  // option. If the server has a stale did.json, our sha256 will not
  // match the server's view of integrity and the publish will be
  // rejected, which is the right failure mode.
  const idResp = await readRpc<{ object: DidDocument }>(
    "aithos.get_identity",
    { did: snapshot.manifest.subject_did },
  );
  const didJsonBytes = new TextEncoder().encode(
    JSON.stringify(idResp.object, null, 2) + "\n",
  );
  const didJsonSha256Hex = bytesToHex(sha256(didJsonBytes));

  // Build the new edition with the delegate's key.
  const delegateSeed = hexToBytes(delegate.delegateSeedHex);
  const delegatePubkey = getPublicKey(delegateSeed);
  const built = buildSignedNextEditionAsDelegatePublic({
    currentManifest: snapshot.manifest,
    didJsonSha256Hex,
    newPublicSections,
    signer: {
      seed: delegateSeed,
      pubkeyMultibase: delegate.granteePubkeyMultibase,
      mandateId: mandate.id,
    },
  });

  // Assemble zones payload: new public bytes, plus rolled-forward
  // circle/self bytes (the server needs bytes for every zone declared
  // in the new manifest). We fetched the old bytes via loadEditSnapshot
  // already — just echo them back.
  const zones: Record<string, { bytes_base64: string }> = {
    public: { bytes_base64: bytesToBase64(built.publicMarkdownBytes) },
  };
  if (built.manifest.zones.circle && snapshot.zoneBytes.circle) {
    zones.circle = { bytes_base64: bytesToBase64(snapshot.zoneBytes.circle) };
  }
  if (built.manifest.zones.self && snapshot.zoneBytes.self) {
    zones.self = { bytes_base64: bytesToBase64(snapshot.zoneBytes.self) };
  }

  // Envelope signed by the delegate with the mandate attached. `iss`
  // stays the SUBJECT DID (the delegate acts on the subject's behalf);
  // the verificationMethod is the delegate's bare multibase pubkey so
  // the server knows to hit the mandate path.
  const params = { manifest: built.manifest, zones };
  const envelope = buildSignedEnvelope({
    iss: snapshot.manifest.subject_did,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_ethos_edition",
    verificationMethod: delegate.granteePubkeyMultibase,
    params,
    signer: { seed: delegateSeed, publicKey: delegatePubkey },
    mandate,
  });

  // Zeroize the seed copy we held in memory. The stored hex in IndexedDB
  // is still there, but this function-local copy shouldn't outlive the
  // call.
  delegateSeed.fill(0);

  const res = await fetch(WRITE_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.publish_ethos_edition",
      method: "aithos.publish_ethos_edition",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new EditError(
      "publish_ethos_edition",
      body.error.message,
      { code: body.error.code, ...body.error.data },
    );
  }

  return { manifest: built.manifest };
}

/* -------------------------------------------------------------------------- */
/*  Publish — delegate path (private zones, Phase E.2)                        */
/* -------------------------------------------------------------------------- */

export interface PublishPrivateAsDelegateArgs {
  readonly delegate: StoredDelegate;
  readonly snapshot: EditSnapshot;
  /** Which private zone — `circle` or `self`. */
  readonly zone: "circle" | "self";
  /** Sections to publish for that zone. Replaces the zone's entire content. */
  readonly newSections: readonly Section[];
}

export interface PublishPrivateAsDelegateResult {
  readonly manifest: Manifest;
  /** Per-mandate failures while building the wrap list. Publish still ran. */
  readonly recipientWarnings?: readonly { readonly mandate_id: string; readonly reason: string }[];
}

/**
 * Publish a new edition where a PRIVATE zone (circle or self) is
 * re-sealed by a delegate under their mandate. The delegate must carry
 * `ethos.write.<zone>` for this call to be accepted server-side.
 *
 * The re-seal fetches the authoritative wrap list
 * (`fetchZoneRecipientsForDelegateWrite`) so the owner + every other
 * active delegate keep access; skipping this step would silently strand
 * them with title-only bytes on the next read.
 *
 * The OTHER private zone (and the public zone) roll forward byte-for-byte.
 */
export async function publishPrivateZoneAsDelegate(
  args: PublishPrivateAsDelegateArgs,
): Promise<PublishPrivateAsDelegateResult> {
  const { delegate, snapshot, zone, newSections } = args;

  if (!delegate.mandate || typeof delegate.mandate !== "object") {
    throw new EditError("delegate.mandate", "stored delegate is missing a mandate object");
  }
  const mandate = delegate.mandate as unknown as SignedMandate;
  if (typeof mandate.id !== "string") {
    throw new EditError("delegate.mandate", "mandate.id missing on delegate bundle");
  }
  const requiredScope = `ethos.write.${zone}`;
  if (!Array.isArray(mandate.scopes) || !mandate.scopes.includes(requiredScope)) {
    throw new EditError(
      "delegate.scope",
      `delegate mandate does not grant ${requiredScope}`,
      { scopes: mandate.scopes },
    );
  }

  const subjectDid = snapshot.manifest.subject_did;

  // Three things fetched/computed in parallel:
  //   1. did.json of the subject — its sha256 anchors manifest.integrity.
  //   2. Recipient list — owner + writer + other active delegates.
  const [idResp, recipientsResult] = await Promise.all([
    readRpc<{ object: DidDocument }>("aithos.get_identity", { did: subjectDid }),
    fetchZoneRecipientsForDelegateWrite({
      subjectDid,
      zone,
      writer: {
        granteeId: delegate.granteeId,
        granteePubkeyMultibase: delegate.granteePubkeyMultibase,
      },
    }),
  ]);
  const didJsonBytes = new TextEncoder().encode(
    JSON.stringify(idResp.object, null, 2) + "\n",
  );
  const didJsonSha256Hex = bytesToHex(sha256(didJsonBytes));

  // Build the new edition.
  const delegateSeed = hexToBytes(delegate.delegateSeedHex);
  const delegatePubkey = getPublicKey(delegateSeed);
  const built = buildSignedNextEditionAsDelegatePrivate({
    currentManifest: snapshot.manifest,
    didJsonSha256Hex,
    zone,
    newSections,
    signer: {
      seed: delegateSeed,
      pubkeyMultibase: delegate.granteePubkeyMultibase,
      mandateId: mandate.id,
    },
    recipients: recipientsResult.recipients,
  });

  // Assemble zones payload: new encrypted bytes for the target zone,
  // current bytes for the other zones that stayed on the manifest.
  const zones: Record<string, { bytes_base64: string }> = {};
  if (built.manifest.zones.public && snapshot.zoneBytes.public) {
    zones.public = { bytes_base64: bytesToBase64(snapshot.zoneBytes.public) };
  }
  if (zone === "circle") {
    zones.circle = { bytes_base64: bytesToBase64(built.zoneBytes) };
    if (built.manifest.zones.self && snapshot.zoneBytes.self) {
      zones.self = { bytes_base64: bytesToBase64(snapshot.zoneBytes.self) };
    }
  } else {
    if (built.manifest.zones.circle && snapshot.zoneBytes.circle) {
      zones.circle = { bytes_base64: bytesToBase64(snapshot.zoneBytes.circle) };
    }
    zones.self = { bytes_base64: bytesToBase64(built.zoneBytes) };
  }

  const params = { manifest: built.manifest, zones };
  const envelope = buildSignedEnvelope({
    iss: subjectDid,
    aud: WRITE_ENDPOINT,
    method: "aithos.publish_ethos_edition",
    verificationMethod: delegate.granteePubkeyMultibase,
    params,
    signer: { seed: delegateSeed, publicKey: delegatePubkey },
    mandate,
  });
  delegateSeed.fill(0);

  const res = await fetch(WRITE_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: "aithos.publish_ethos_edition",
      method: "aithos.publish_ethos_edition",
      params: { ...params, _envelope: envelope },
    }),
  });
  const body = (await res.json()) as {
    result?: unknown;
    error?: { code: number; message: string; data?: Record<string, unknown> };
  };
  if (body.error) {
    throw new EditError(
      "publish_ethos_edition",
      body.error.message,
      { code: body.error.code, ...body.error.data },
    );
  }

  return {
    manifest: built.manifest,
    ...(recipientsResult.errors.length > 0
      ? { recipientWarnings: recipientsResult.errors }
      : {}),
  };
}

/** Merge two recipient lists, dedup by `didUrl`. First occurrence wins. */
function mergeRecipientsByDidUrl(
  a: readonly import("./crypto/encrypt.js").EncryptRecipient[],
  b: readonly import("./crypto/encrypt.js").EncryptRecipient[],
): import("./crypto/encrypt.js").EncryptRecipient[] {
  const seen = new Set<string>();
  const out: import("./crypto/encrypt.js").EncryptRecipient[] = [];
  for (const r of [...a, ...b]) {
    if (seen.has(r.didUrl)) continue;
    seen.add(r.didUrl);
    out.push(r);
  }
  return out;
}

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) hex += bytes[i]!.toString(16).padStart(2, "0");
  return hex.slice(0, n);
}

// Dynamic import at call site would slow the first-paint; re-export the
// parser here so the editor module is self-contained.
import { parsePublicZone } from "./zone-parser.js";
function parsePublicSections(md: string): Section[] {
  return [...parsePublicZone(md).sections];
}
