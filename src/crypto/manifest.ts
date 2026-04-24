// First-edition manifest builder — browser-side, MVP public-only.
//
// Mirrors the portion of @aithos/protocol-core's `ethos.ts` that we need
// to produce a first signed edition:
//
//   1. build a ZoneDoc = {sections: [...]}           (structured)
//   2. sign the ZoneDoc with the public sphere key   → ZoneSignature
//   3. render ZoneDoc to markdown (sha256_of_plaintext input)
//   4. compute sha256 of the rendered bytes
//   5. build Manifest + manifest.zones.public        (metadata)
//   6. sign the canonical manifest with manifest_signature="" placeholder
//   7. embed the final signature in manifest.integrity.manifest_signature
//
// MVP simplifications:
//   - only the public zone is included; circle/self are omitted from the
//     manifest (our server handler is happy to skip missing zones)
//   - no gamma log (manifest.gamma omitted); sections carry a synthetic
//     gamma_ref that the server does not validate
//   - sha256_of_did_json is computed from the actual signed did.json JSON,
//     matching what protocol-core would produce

import { sha256 } from "@noble/hashes/sha2";
import { x25519 } from "@noble/curves/ed25519";

import { canonicalize } from "./canonical.js";
import { base64url, bytesToHex } from "./encoding.js";
import type { DidDocument } from "./identity.js";
import type { BrowserIdentity } from "./identity.js";
import { sign } from "./ed25519.js";
import { edSeedToX25519Secret } from "./kex.js";
import { encryptZone, type EncryptRecipient } from "./encrypt.js";

export interface Section {
  readonly id: string;
  readonly title: string;
  readonly body: string;
  readonly tags?: readonly string[];
  readonly gamma_ref: string;
}

export interface ZoneDoc {
  readonly sections: readonly Section[];
}

export interface ZoneSignature {
  readonly alg: "ed25519";
  readonly key: string;
  readonly value: string;
  /**
   * Mandate id that authorises this signature, when `key` is a bare
   * multibase Ed25519 pubkey (delegate path). Absent when `key` is a
   * DID URL pointing to one of the subject's sphere keys (owner path).
   */
  readonly authorized_by?: string;
}

export interface ZoneWrap {
  readonly recipient: string;
  readonly alg: "x25519-hkdf-sha256-aead";
  readonly ephemeral_public: string;
  readonly wrap_nonce: string;
  readonly wrapped_key: string;
}

export interface ZoneCipher {
  readonly alg: "xchacha20poly1305-ietf";
  readonly nonce: string;
  readonly wraps: readonly ZoneWrap[];
}

export interface ZoneManifest {
  readonly file: string;
  readonly encrypted: boolean;
  readonly sha256_of_plaintext: string;
  readonly section_titles: readonly string[];
  readonly signature: ZoneSignature;
  /** Only present on encrypted zones (circle / self). */
  readonly cipher?: ZoneCipher;
}

export interface ManifestSignature {
  readonly alg: "ed25519";
  readonly key: string;
  readonly value: string;
  /** Delegate path — see ZoneSignature.authorized_by for semantics. */
  readonly authorized_by?: string;
}

export interface Manifest {
  readonly aithos: "0.2.0";
  readonly bundle_id: string;
  readonly subject_did: string;
  readonly subject_handle: string;
  readonly display_name: string;
  readonly edition: {
    readonly version: string;
    readonly created_at: string;
    readonly supersedes: string | null;
    readonly prev_hash: string | null;
    readonly height: number;
  };
  readonly zones: {
    readonly public?: ZoneManifest;
    readonly circle?: ZoneManifest;
    readonly self?: ZoneManifest;
  };
  readonly integrity: {
    readonly sha256_of_did_json: string;
    readonly manifest_signature: ManifestSignature;
  };
}

export interface BuildFirstEditionArgs {
  readonly identity: BrowserIdentity;
  readonly signedDidDoc: DidDocument;
  /** Title of the first public section. */
  readonly publicTitle: string;
  /** Markdown body of the first public section (raw, no YAML). */
  readonly publicBody: string;
  readonly tags?: readonly string[];
}

export interface BuildFirstEditionResult {
  readonly manifest: Manifest;
  readonly publicMarkdownBytes: Uint8Array;
}

/**
 * Build + sign the first edition. Returns the full signed manifest and the
 * rendered public.md bytes ready to upload to S3 via publish_ethos_edition.
 */
export function buildSignedFirstEdition(
  args: BuildFirstEditionArgs,
): BuildFirstEditionResult {
  const { identity, signedDidDoc, publicTitle, publicBody, tags } = args;
  const did = identity.did;
  const now = new Date();
  const nowIso = now.toISOString();
  const version = editionVersionFromDate(identity.handle, now);

  // 1. Build the ZoneDoc = {sections: [...]}
  const section: Section = {
    id: "sec_" + randomHex(12),
    title: publicTitle,
    body: publicBody,
    ...(tags && tags.length > 0 ? { tags } : {}),
    gamma_ref: "gamma_none_" + randomHex(24),
  };
  const zoneDoc: ZoneDoc = { sections: [section] };

  // 2. Sign the ZoneDoc with the public sphere key.
  const zoneSigBytes = sign(
    new TextEncoder().encode(canonicalize(zoneDoc)),
    identity.public.seed,
  );
  const zoneSignature: ZoneSignature = {
    alg: "ed25519",
    key: `${did}#public`,
    value: base64url(zoneSigBytes),
  };

  // 3. Render the ZoneDoc to markdown — byte-for-byte matching protocol-core's
  //    renderZoneMarkdown output.
  const markdownBytes = renderPublicMarkdown({
    zoneDoc,
    subjectDid: did,
    subjectHandle: identity.handle,
    editionVersion: version,
    createdAt: nowIso,
  });

  // 4. sha256 of rendered bytes.
  const plaintextSha = bytesToHex(sha256(markdownBytes));

  // 5. Assemble the public zone manifest entry.
  const zonePublic: ZoneManifest = {
    file: "public.md",
    encrypted: false,
    sha256_of_plaintext: plaintextSha,
    section_titles: [publicTitle],
    signature: zoneSignature,
  };

  // 6. Build the unsigned manifest with an empty manifest_signature value.
  const didJsonBytes = new TextEncoder().encode(
    JSON.stringify(signedDidDoc, null, 2) + "\n",
  );
  const didJsonSha = bytesToHex(sha256(didJsonBytes));

  const baseManifest: Omit<Manifest, "integrity"> & {
    integrity: { sha256_of_did_json: string; manifest_signature: ManifestSignature };
  } = {
    aithos: "0.2.0",
    bundle_id: `urn:aithos:${identity.handle}:${version}`,
    subject_did: did,
    subject_handle: identity.handle,
    display_name: identity.displayName,
    edition: {
      version,
      created_at: nowIso,
      supersedes: null,
      prev_hash: null,
      height: 1,
    },
    zones: {
      public: zonePublic,
    },
    integrity: {
      sha256_of_did_json: didJsonSha,
      manifest_signature: {
        alg: "ed25519",
        key: `${did}#public`,
        value: "",
      },
    },
  };

  // 7. Sign canonical(manifest with empty sig), then embed the signature.
  const manifestSigBytes = sign(
    new TextEncoder().encode(canonicalize(baseManifest)),
    identity.public.seed,
  );
  const manifest: Manifest = {
    ...baseManifest,
    integrity: {
      ...baseManifest.integrity,
      manifest_signature: {
        ...baseManifest.integrity.manifest_signature,
        value: base64url(manifestSigBytes),
      },
    },
  };

  return { manifest, publicMarkdownBytes: markdownBytes };
}

/* -------------------------------------------------------------------------- */
/*  Subsequent editions                                                       */
/* -------------------------------------------------------------------------- */

export interface BuildNextEditionArgs {
  readonly identity: BrowserIdentity;
  /**
   * Hex sha256 of the did.json currently stored in S3. Re-computing this
   * client-side from `signedDidDocument(identity)` would drift because
   * `created_at` is embedded in the doc — so we pass in what the server
   * actually has.
   */
  readonly didJsonSha256Hex: string;
  /** The previously-published manifest (will become `prev_hash`'s target). */
  readonly currentManifest: Manifest;
  /**
   * Raw bytes of zones already published under the previous edition. We
   * only re-upload the ones we want to roll forward unchanged — the
   * server requires bytes for every zone the NEW manifest declares.
   * Keyed by sphere name, value is the existing ciphertext/plaintext.
   */
  readonly currentZoneBytes: Partial<Record<"public" | "circle" | "self", Uint8Array>>;
  /**
   * Public-zone sections for the new edition. The public zone is ALWAYS
   * (re-)baked on every edit so its signature matches the new bundle_id.
   */
  readonly newPublicSections: readonly Section[];
  /**
   * Optional: updated sections for the circle / self zones. When passed,
   * the zone is re-encrypted with a fresh DEK + wrap for the owner.
   * When omitted, the previous zone is rolled forward unchanged.
   */
  readonly newCircleSections?: readonly Section[];
  readonly newSelfSections?: readonly Section[];
  /**
   * Extra wrap recipients beyond the owner. Each recipient receives its
   * own HKDF-derived wrap of the per-edition DEK, so importing a mandate
   * bundle lets the delegate decrypt the full plaintext — not just the
   * section titles pulled from `manifest.zones.<zone>.section_titles`.
   *
   * Keyed by zone so a mandate granting only circle doesn't accidentally
   * leak the self zone. Resolved upstream by
   * `fetchActiveDelegateRecipients`.
   */
  readonly delegateRecipientsCircle?: readonly import("./encrypt.js").EncryptRecipient[];
  readonly delegateRecipientsSelf?: readonly import("./encrypt.js").EncryptRecipient[];
}

export interface BuildNextEditionResult {
  readonly manifest: Manifest;
  readonly publicMarkdownBytes: Uint8Array;
  /** Present only when the previous manifest also had them, or when we
   *  re-encrypted them this edition. */
  readonly circleBytes?: Uint8Array;
  readonly selfBytes?: Uint8Array;
}

/**
 * Build + sign the NEXT edition — height = prev + 1, prev_hash pinned to
 * `canonicalManifestHashHex(currentManifest)`. Rolls forward circle/self
 * zones byte-for-byte (we can't decrypt them yet, so we treat them as
 * opaque storage units and their ZoneManifest entries stay unchanged).
 */
export function buildSignedNextEdition(
  args: BuildNextEditionArgs,
): BuildNextEditionResult {
  const { identity, didJsonSha256Hex, currentManifest, newPublicSections } = args;
  const did = identity.did;
  const now = new Date();
  const nowIso = now.toISOString();
  const newHeight = currentManifest.edition.height + 1;
  const version = editionVersionFromHeight(now, newHeight);
  const prevHash = canonicalManifestHashHex(currentManifest);

  /* ---- build + sign public ZoneDoc ---- */
  const publicZoneDoc: ZoneDoc = { sections: [...newPublicSections] };
  const publicSigBytes = sign(
    new TextEncoder().encode(canonicalize(publicZoneDoc)),
    identity.public.seed,
  );
  const publicZoneSignature: ZoneSignature = {
    alg: "ed25519",
    key: `${did}#public`,
    value: base64url(publicSigBytes),
  };
  const publicMarkdownBytes = renderPublicMarkdown({
    zoneDoc: publicZoneDoc,
    subjectDid: did,
    subjectHandle: identity.handle,
    editionVersion: version,
    createdAt: nowIso,
  });
  const publicSha = bytesToHex(sha256(publicMarkdownBytes));

  const zones: Manifest["zones"] = {
    public: {
      file: "public.md",
      encrypted: false,
      sha256_of_plaintext: publicSha,
      section_titles: newPublicSections.map((s) => s.title),
      signature: publicZoneSignature,
    },
  };

  /* ---- circle + self: re-seal if the caller gave new sections, else
   *      roll forward the existing zone untouched.
   */
  let newCircleBytes: Uint8Array | undefined;
  let newSelfBytes: Uint8Array | undefined;

  if (args.newCircleSections) {
    const sealed = sealPrivateZone({
      identity,
      sphere: "circle",
      sections: args.newCircleSections,
      editionVersion: version,
      editionCreatedAt: nowIso,
      delegateRecipients: args.delegateRecipientsCircle,
    });
    (zones as Record<string, ZoneManifest>).circle = sealed.zoneManifest;
    newCircleBytes = sealed.bytes;
  } else if (currentManifest.zones.circle) {
    (zones as Record<string, ZoneManifest>).circle = currentManifest.zones.circle;
  }

  if (args.newSelfSections) {
    const sealed = sealPrivateZone({
      identity,
      sphere: "self",
      sections: args.newSelfSections,
      editionVersion: version,
      editionCreatedAt: nowIso,
      delegateRecipients: args.delegateRecipientsSelf,
    });
    (zones as Record<string, ZoneManifest>).self = sealed.zoneManifest;
    newSelfBytes = sealed.bytes;
  } else if (currentManifest.zones.self) {
    (zones as Record<string, ZoneManifest>).self = currentManifest.zones.self;
  }

  const baseManifest: Manifest = {
    aithos: "0.2.0",
    bundle_id: `urn:aithos:${identity.handle}:${version}`,
    subject_did: did,
    subject_handle: identity.handle,
    display_name: currentManifest.display_name,
    edition: {
      version,
      created_at: nowIso,
      supersedes: currentManifest.edition.version,
      prev_hash: prevHash,
      height: newHeight,
    },
    zones,
    integrity: {
      sha256_of_did_json: didJsonSha256Hex,
      manifest_signature: {
        alg: "ed25519",
        key: `${did}#public`,
        value: "",
      },
    },
  };

  const manifestSig = sign(
    new TextEncoder().encode(canonicalize(baseManifest)),
    identity.public.seed,
  );
  const manifest: Manifest = {
    ...baseManifest,
    integrity: {
      ...baseManifest.integrity,
      manifest_signature: {
        ...baseManifest.integrity.manifest_signature,
        value: base64url(manifestSig),
      },
    },
  };

  return {
    manifest,
    publicMarkdownBytes,
    circleBytes: newCircleBytes ?? args.currentZoneBytes.circle,
    selfBytes: newSelfBytes ?? args.currentZoneBytes.self,
  };
}

/* -------------------------------------------------------------------------- */
/*  Seal a private zone for the owner                                         */
/* -------------------------------------------------------------------------- */

/**
 * Produce a signed + encrypted ZoneManifest entry for circle/self. The
 * wrap list always contains the owner's own sphere-kex key so the owner
 * can reopen their own zone after sign-out; every entry in
 * `delegateRecipients` is additionally sealed so the corresponding
 * mandate holder can decrypt with their grantee seed. Phase D.2 — before
 * this landed, zones published from the app were single-recipient and
 * mandate imports only exposed `section_titles`.
 */
function sealPrivateZone(args: {
  readonly identity: BrowserIdentity;
  readonly sphere: "circle" | "self";
  readonly sections: readonly Section[];
  readonly editionVersion: string;
  readonly editionCreatedAt: string;
  readonly delegateRecipients?: readonly EncryptRecipient[];
}): { readonly zoneManifest: ZoneManifest; readonly bytes: Uint8Array } {
  const { identity, sphere, sections, editionVersion, editionCreatedAt } = args;
  const did = identity.did;

  // 1. Sign the structured ZoneDoc with the sphere's Ed25519 seed.
  const zoneDoc: ZoneDoc = { sections: [...sections] };
  const zoneSigBytes = sign(
    new TextEncoder().encode(canonicalize(zoneDoc)),
    identity[sphere].seed,
  );
  const zoneSignature: ZoneSignature = {
    alg: "ed25519",
    key: `${did}#${sphere}`,
    value: base64url(zoneSigBytes),
  };

  // 2. Render the zone to markdown (byte-identical to protocol-core's
  //    renderZoneMarkdown for circle/self).
  const plaintext = renderZoneMarkdownText({
    zone: sphere,
    zoneDoc,
    subjectDid: did,
    subjectHandle: identity.handle,
    editionVersion,
    createdAt: editionCreatedAt,
  });

  // 3. sha256 of rendered plaintext — before encrypt, that's what the
  //    manifest references as `sha256_of_plaintext`.
  const plaintextSha = bytesToHex(sha256(new TextEncoder().encode(plaintext)));

  // 4. Derive the owner's X25519 pubkey for this sphere (recipient).
  const xSk = edSeedToX25519Secret(identity[sphere].seed);
  const xPk = x25519.getPublicKey(xSk);
  xSk.fill(0);

  // 5. Seal to every authorized recipient.
  //
  //    - Owner: always, under its sphere-kex DID URL. Without this the
  //      owner would lose the ability to re-open its own zone the moment
  //      the browser is signed out.
  //    - Delegates: zero or more entries, resolved upstream by
  //      fetchActiveDelegateRecipients based on the read-scope set of
  //      each active mandate. The wrap's `recipient` field is already
  //      baked into each EncryptRecipient.
  //
  //    De-duplication by didUrl is belt-and-braces — if a caller ever
  //    lists the owner a second time through the delegate list, we
  //    silently collapse it. encryptZone would happily emit two wraps
  //    for the same DID URL otherwise.
  const recipients: EncryptRecipient[] = [
    { didUrl: `${did}#${sphere}-kex`, x25519PublicKey: xPk },
  ];
  if (args.delegateRecipients) {
    const seen = new Set<string>(recipients.map((r) => r.didUrl));
    for (const r of args.delegateRecipients) {
      if (seen.has(r.didUrl)) continue;
      seen.add(r.didUrl);
      recipients.push(r);
    }
  }
  const sealed = encryptZone({
    plaintext,
    subjectDid: did,
    recipients,
  });

  const zoneManifest: ZoneManifest = {
    file: `${sphere}.md.enc`,
    encrypted: true,
    sha256_of_plaintext: plaintextSha,
    section_titles: sections.map((s) => s.title),
    signature: zoneSignature,
    cipher: sealed.cipher,
  };

  return { zoneManifest, bytes: sealed.ciphertext };
}

/**
 * Render a zone doc to markdown. Same format for public/circle/self per
 * protocol-core — the frontmatter's `zone:` field distinguishes them.
 */
function renderZoneMarkdownText(ctx: {
  zone: "public" | "circle" | "self";
  zoneDoc: ZoneDoc;
  subjectDid: string;
  subjectHandle: string;
  editionVersion: string;
  createdAt: string;
}): string {
  const lines: string[] = [
    "---",
    `aithos: "0.2.0"`,
    `zone: ${ctx.zone}`,
    `subject_did: ${ctx.subjectDid}`,
    `subject_handle: ${ctx.subjectHandle}`,
    `edition: ${ctx.editionVersion}`,
    `created_at: ${ctx.createdAt}`,
    "---",
    "",
  ];
  for (const sec of ctx.zoneDoc.sections) {
    lines.push(`# ${sec.title} <!-- ${sec.id} · ${sec.gamma_ref} -->`);
    if (sec.tags && sec.tags.length > 0) {
      lines.push(`<!-- tags: ${JSON.stringify([...sec.tags])} -->`);
    }
    lines.push("");
    lines.push(sec.body);
    lines.push("");
  }
  return lines.join("\n");
}

/**
 * Hash a manifest canonically with its signature value blanked out — the
 * value future `edition.prev_hash` references point at. Mirrors
 * `canonicalManifestHashHex` in protocol-core.
 */
export function canonicalManifestHashHex(m: Manifest): string {
  const blanked: Manifest = {
    ...m,
    integrity: {
      ...m.integrity,
      manifest_signature: { ...m.integrity.manifest_signature, value: "" },
    },
  };
  return bytesToHex(sha256(new TextEncoder().encode(canonicalize(blanked))));
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes).slice(0, n);
}

/**
 * Build the same edition version format protocol-core uses:
 *   `YYYY.MM.DD-<N>` where N is the index of the edition on that day.
 * For a first edition we always emit `-1` because we have no history yet.
 */
function editionVersionFromDate(_handle: string, d: Date): string {
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yyyy}.${mm}.${dd}-1`;
}

/**
 * Version for subsequent editions — use height as the suffix. Not perfectly
 * CLI-equivalent (which would re-number per day), but it's unique,
 * monotonic, and only informational (the server trusts `edition.height`,
 * not this string).
 */
function editionVersionFromHeight(d: Date, height: number): string {
  const yyyy = d.getUTCFullYear();
  const mm = String(d.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(d.getUTCDate()).padStart(2, "0");
  return `${yyyy}.${mm}.${dd}-${height}`;
}

interface RenderContext {
  readonly zoneDoc: ZoneDoc;
  readonly subjectDid: string;
  readonly subjectHandle: string;
  readonly editionVersion: string;
  readonly createdAt: string;
}

/* -------------------------------------------------------------------------- */
/*  Delegate: next edition with delegate-signed public zone                   */
/* -------------------------------------------------------------------------- */

export interface DelegatePublicSigner {
  /** Delegate Ed25519 seed (32 bytes). */
  readonly seed: Uint8Array;
  /** Delegate Ed25519 pubkey, multibase `z…` — used as the signature `key` field. */
  readonly pubkeyMultibase: string;
  /** Mandate id that authorises this write — embedded as `authorized_by`. */
  readonly mandateId: string;
}

export interface BuildDelegatePublicEditionArgs {
  /**
   * Current manifest (fetched from the server). The new edition inherits
   * subject_did / subject_handle / display_name and chains off the
   * current canonical hash. Circle/self zones roll forward untouched.
   */
  readonly currentManifest: Manifest;
  /**
   * Hex sha256 of the did.json currently in S3. The delegate doesn't own
   * the identity — they have to trust what the server's serving and
   * commit to it in the new edition's integrity block.
   */
  readonly didJsonSha256Hex: string;
  /** Sections to publish. Replaces the public zone entirely. */
  readonly newPublicSections: readonly Section[];
  /** The signing context — seed + pubkey multibase + mandate id. */
  readonly signer: DelegatePublicSigner;
}

export interface BuildDelegatePublicEditionResult {
  readonly manifest: Manifest;
  readonly publicMarkdownBytes: Uint8Array;
  /** Present when the current manifest had them — rolled forward bytes. */
  readonly circleBytes?: Uint8Array;
  readonly selfBytes?: Uint8Array;
}

/**
 * Build a new edition where the PUBLIC zone is (re-)signed by a delegate
 * under `mandateId`. Circle / self zones roll forward byte-for-byte —
 * the delegate cannot re-sign or re-seal them without the owner's sphere
 * keys, and this helper enforces that by never touching them.
 *
 * The manifest signature itself is ALSO produced by the delegate and
 * carries `authorized_by: mandateId`, so the server's scope check
 * (`ethos.write.public` required) accepts it.
 *
 * Caller is expected to pre-fetch the current manifest + current zone
 * bytes (same pattern as loadEditSnapshot). The function is pure with
 * respect to IO — just crypto + serialization.
 */
export function buildSignedNextEditionAsDelegatePublic(
  args: BuildDelegatePublicEditionArgs,
): BuildDelegatePublicEditionResult {
  const { currentManifest, didJsonSha256Hex, newPublicSections, signer } = args;
  const did = currentManifest.subject_did;
  const handle = currentManifest.subject_handle;
  const now = new Date();
  const nowIso = now.toISOString();
  const newHeight = currentManifest.edition.height + 1;
  const version = editionVersionFromHeight(now, newHeight);
  const prevHash = canonicalManifestHashHex(currentManifest);

  /* ---- build + sign public ZoneDoc with delegate key ---- */
  const publicZoneDoc: ZoneDoc = { sections: [...newPublicSections] };
  const publicSigBytes = sign(
    new TextEncoder().encode(canonicalize(publicZoneDoc)),
    signer.seed,
  );
  const publicZoneSignature: ZoneSignature = {
    alg: "ed25519",
    key: signer.pubkeyMultibase,
    value: base64url(publicSigBytes),
    authorized_by: signer.mandateId,
  };
  const publicMarkdownBytes = renderPublicMarkdown({
    zoneDoc: publicZoneDoc,
    subjectDid: did,
    subjectHandle: handle,
    editionVersion: version,
    createdAt: nowIso,
  });
  const publicSha = bytesToHex(sha256(publicMarkdownBytes));

  const zones: Manifest["zones"] = {
    public: {
      file: "public.md",
      encrypted: false,
      sha256_of_plaintext: publicSha,
      section_titles: newPublicSections.map((s) => s.title),
      signature: publicZoneSignature,
    },
  };
  // Roll circle / self forward exactly as the current manifest describes
  // them. Their ZoneManifest entries (including signatures) come along
  // unchanged — the delegate has no business modifying private zones in
  // this tranche.
  if (currentManifest.zones.circle) {
    (zones as Record<string, ZoneManifest>).circle = currentManifest.zones.circle;
  }
  if (currentManifest.zones.self) {
    (zones as Record<string, ZoneManifest>).self = currentManifest.zones.self;
  }

  /* ---- manifest scaffold + delegate-signed manifest_signature ---- */
  const baseManifest: Manifest = {
    aithos: "0.2.0",
    bundle_id: `urn:aithos:${handle}:${version}`,
    subject_did: did,
    subject_handle: handle,
    display_name: currentManifest.display_name,
    edition: {
      version,
      created_at: nowIso,
      supersedes: currentManifest.edition.version,
      prev_hash: prevHash,
      height: newHeight,
    },
    zones,
    integrity: {
      sha256_of_did_json: didJsonSha256Hex,
      manifest_signature: {
        alg: "ed25519",
        key: signer.pubkeyMultibase,
        value: "",
        authorized_by: signer.mandateId,
      },
    },
  };

  const manifestSig = sign(
    new TextEncoder().encode(canonicalize(baseManifest)),
    signer.seed,
  );
  const manifest: Manifest = {
    ...baseManifest,
    integrity: {
      ...baseManifest.integrity,
      manifest_signature: {
        ...baseManifest.integrity.manifest_signature,
        value: base64url(manifestSig),
      },
    },
  };

  return {
    manifest,
    publicMarkdownBytes,
    // The in-scope caller fetches these separately and echoes them back
    // in the server request body; we return undefined here since we're
    // not re-encoding them.
  };
}

/* -------------------------------------------------------------------------- */
/*  Delegate: next edition with delegate-signed PRIVATE zone (circle/self)    */
/* -------------------------------------------------------------------------- */

export interface BuildDelegatePrivateEditionArgs {
  readonly currentManifest: Manifest;
  readonly didJsonSha256Hex: string;
  /** Which private zone is being (re-)published. */
  readonly zone: "circle" | "self";
  /**
   * New sections for the target zone. The other private zone (if
   * declared) rolls forward byte-for-byte; the public zone also rolls
   * forward unchanged — the delegate can only touch one zone per edition
   * in this tranche.
   */
  readonly newSections: readonly Section[];
  /** Delegate signer (seed + pubkey multibase + mandate id). */
  readonly signer: DelegatePublicSigner;
  /**
   * Full wrap list. MUST include the owner's sphere-kex recipient, the
   * writing delegate, and every other active delegate with read/write
   * scope on this zone. Caller is responsible for assembly — see
   * fetchZoneRecipientsForDelegateWrite in lib/delegate-recipients.ts.
   */
  readonly recipients: readonly EncryptRecipient[];
}

export interface BuildDelegatePrivateEditionResult {
  readonly manifest: Manifest;
  /** Re-encrypted ciphertext for the target zone. */
  readonly zoneBytes: Uint8Array;
}

/**
 * Build a new edition where a PRIVATE zone (circle or self) is re-sealed
 * + re-signed by a delegate under `mandateId`. Public + the OTHER private
 * zone roll forward byte-for-byte from the current manifest (the
 * delegate only has authority for the one zone their mandate names).
 *
 * The wrap list `recipients` is authoritative: owner, writer, and any
 * other currently-authorised delegates MUST be present before this is
 * called. Seal here is forward-only; anyone missing from `recipients`
 * will see titles-only when fetching this edition.
 */
export function buildSignedNextEditionAsDelegatePrivate(
  args: BuildDelegatePrivateEditionArgs,
): BuildDelegatePrivateEditionResult {
  const { currentManifest, didJsonSha256Hex, zone, newSections, signer, recipients } = args;
  const did = currentManifest.subject_did;
  const handle = currentManifest.subject_handle;
  const now = new Date();
  const nowIso = now.toISOString();
  const newHeight = currentManifest.edition.height + 1;
  const version = editionVersionFromHeight(now, newHeight);
  const prevHash = canonicalManifestHashHex(currentManifest);

  /* ---- sign + render + encrypt the target zone ---- */
  const zoneDoc: ZoneDoc = { sections: [...newSections] };
  const zoneSigBytes = sign(
    new TextEncoder().encode(canonicalize(zoneDoc)),
    signer.seed,
  );
  const zoneSignature: ZoneSignature = {
    alg: "ed25519",
    key: signer.pubkeyMultibase,
    value: base64url(zoneSigBytes),
    authorized_by: signer.mandateId,
  };
  const plaintext = renderZoneMarkdownText({
    zone,
    zoneDoc,
    subjectDid: did,
    subjectHandle: handle,
    editionVersion: version,
    createdAt: nowIso,
  });
  const plaintextSha = bytesToHex(
    sha256(new TextEncoder().encode(plaintext)),
  );
  const sealed = encryptZone({
    plaintext,
    subjectDid: did,
    recipients,
  });
  const zoneManifest: ZoneManifest = {
    file: `${zone}.md.enc`,
    encrypted: true,
    sha256_of_plaintext: plaintextSha,
    section_titles: newSections.map((s) => s.title),
    signature: zoneSignature,
    cipher: sealed.cipher,
  };

  /* ---- assemble manifest.zones with roll-forward of untouched zones ---- */
  const zones: Manifest["zones"] = {
    public: currentManifest.zones.public!,
  };
  if (zone === "circle") {
    (zones as Record<string, ZoneManifest>).circle = zoneManifest;
    if (currentManifest.zones.self) {
      (zones as Record<string, ZoneManifest>).self = currentManifest.zones.self;
    }
  } else {
    // zone === "self"
    if (currentManifest.zones.circle) {
      (zones as Record<string, ZoneManifest>).circle = currentManifest.zones.circle;
    }
    (zones as Record<string, ZoneManifest>).self = zoneManifest;
  }

  /* ---- manifest scaffold + delegate-signed manifest_signature ---- */
  const baseManifest: Manifest = {
    aithos: "0.2.0",
    bundle_id: `urn:aithos:${handle}:${version}`,
    subject_did: did,
    subject_handle: handle,
    display_name: currentManifest.display_name,
    edition: {
      version,
      created_at: nowIso,
      supersedes: currentManifest.edition.version,
      prev_hash: prevHash,
      height: newHeight,
    },
    zones,
    integrity: {
      sha256_of_did_json: didJsonSha256Hex,
      manifest_signature: {
        alg: "ed25519",
        key: signer.pubkeyMultibase,
        value: "",
        authorized_by: signer.mandateId,
      },
    },
  };

  const manifestSig = sign(
    new TextEncoder().encode(canonicalize(baseManifest)),
    signer.seed,
  );
  const manifest: Manifest = {
    ...baseManifest,
    integrity: {
      ...baseManifest.integrity,
      manifest_signature: {
        ...baseManifest.integrity.manifest_signature,
        value: base64url(manifestSig),
      },
    },
  };

  return { manifest, zoneBytes: sealed.ciphertext };
}

/**
 * Render the public zone to markdown, matching protocol-core's
 * renderZoneMarkdown output byte-for-byte.
 */
function renderPublicMarkdown(ctx: RenderContext): Uint8Array {
  const lines: string[] = [
    "---",
    `aithos: "0.2.0"`,
    `zone: public`,
    `subject_did: ${ctx.subjectDid}`,
    `subject_handle: ${ctx.subjectHandle}`,
    `edition: ${ctx.editionVersion}`,
    `created_at: ${ctx.createdAt}`,
    "---",
    "",
  ];
  for (const sec of ctx.zoneDoc.sections) {
    lines.push(`# ${sec.title} <!-- ${sec.id} · ${sec.gamma_ref} -->`);
    if (sec.tags && sec.tags.length > 0) {
      lines.push(`<!-- tags: ${JSON.stringify([...sec.tags])} -->`);
    }
    lines.push("");
    lines.push(sec.body);
    lines.push("");
  }
  // Join with \n (Unix line endings, as protocol-core does).
  return new TextEncoder().encode(lines.join("\n"));
}
