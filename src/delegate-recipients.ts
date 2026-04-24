// Discover active delegate recipients for a given owner + zone.
//
// Every time the owner publishes a new edition, we want to include every
// currently-mandated delegate in the zone's wrap list — otherwise the
// delegate imports a bundle that unlocks *titles* only (the fallback
// rendered when no wrap matches its kex key).
//
// Flow:
//   1. list_mandates({issuer_did: me})  — paginated, index-backed
//   2. filter rows by: not revoked, now ∈ [not_before, not_after],
//      scopes ⊇ { ethos.read.<zone> }
//   3. for each surviving row, get_mandate({mandate_id}) to fetch
//      grantee.id + grantee.pubkey (multibase Ed25519)
//   4. convert the Ed25519 pubkey → X25519 via the standard
//      Edwards→Montgomery isogeny; wrap recipient id is
//      `${grantee.id}#${pubkey_multibase}` (matches tryDecryptAsDelegate)
//
// Errors on one mandate don't block the others — we log + skip. The
// caller (publishZoneEdit) ships recipients it could resolve. Worst case:
// the new edition is usable only by the owner, same as today's behaviour.

import { readRpc, AithosRpcError } from "./api.js";
import { edPubToX25519Pub } from "./crypto/kex.js";
import {
  multibaseToEd25519PublicKey,
  multibaseToX25519PublicKey,
} from "./crypto/encoding.js";
import type { EncryptRecipient } from "./crypto/encrypt.js";
import type { DidDocument } from "./crypto/identity.js";
import type { SignedMandate } from "./crypto/mandate.js";

/** Zones that support sealed delegate access at MVP. Public is plaintext. */
export type SealedZone = "circle" | "self";

const READ_SCOPE_FOR: Readonly<Record<SealedZone, string>> = {
  circle: "ethos.read.circle",
  self: "ethos.read.self",
};

/** One page of mandate cards, shaped like `Page<MandateCard>` server-side. */
interface MandateCard {
  readonly mandate_id: string;
  readonly issuer_did: string;
  readonly actor_did: string;
  readonly scopes?: readonly string[];
  readonly not_before?: number;
  readonly not_after?: number;
  readonly created_at: number;
}

interface MandatesPage {
  readonly items: readonly MandateCard[];
  readonly next_cursor?: string;
}

/**
 * Response shape of `aithos.get_mandate`: the signed mandate itself plus
 * the optional inline revocation (truthy → mandate is revoked).
 */
interface GetMandateResponse {
  readonly mandate: { readonly object: SignedMandate };
  readonly revoked: boolean;
}

export interface DelegateRecipientsByZone {
  readonly circle: readonly EncryptRecipient[];
  readonly self: readonly EncryptRecipient[];
  /** Non-fatal failures we couldn't resolve, surfaced for logging/UX. */
  readonly errors: readonly {
    readonly mandate_id: string;
    readonly zone: SealedZone;
    readonly reason: string;
  }[];
}

/**
 * Project an in-memory signed mandate into `EncryptRecipient` entries, one
 * per sealed zone the mandate covers. Used by callers that have the freshly
 * signed mandate object in hand (typically the mint flow, right after
 * `publish_mandate` succeeds) and can't afford the 1-2s DynamoDB index
 * settle before `list_mandates` sees the new row.
 *
 * The returned recipient `didUrl` is `${grantee.id}#${grantee.pubkey}` —
 * byte-identical to what `tryDecryptAsDelegate` reconstructs locally when
 * opening a wrap, so the match-by-string lookup on the delegate side
 * works on the first edition published after the mandate is minted.
 */
export function mandateToRecipients(
  mandate: SignedMandate,
): { readonly circle?: EncryptRecipient; readonly self?: EncryptRecipient } {
  const pubkeyMb = mandate.grantee?.pubkey;
  if (!pubkeyMb) return {};
  const granteeId = mandate.grantee?.id;
  if (!granteeId) return {};

  let xPub: Uint8Array;
  try {
    const edPub = multibaseToEd25519PublicKey(pubkeyMb);
    xPub = edPubToX25519Pub(edPub);
  } catch {
    return {};
  }
  const recipient: EncryptRecipient = {
    didUrl: `${granteeId}#${pubkeyMb}`,
    x25519PublicKey: xPub,
  };

  const out: { circle?: EncryptRecipient; self?: EncryptRecipient } = {};
  const scopes = mandate.scopes ?? [];
  if (scopes.includes("ethos.read.circle")) out.circle = recipient;
  if (scopes.includes("ethos.read.self")) out.self = recipient;
  return out;
}

/**
 * Fetch every active mandate issued by `ownerDid` and project them into
 * the recipient lists the zone-seal path needs. Active here means:
 *   - the `get_mandate` response is not marked `revoked`
 *   - `now` is within `[not_before, not_after]` (inclusive on both sides)
 *   - the mandate's scopes include the per-zone read scope
 *
 * Silent on the happy path (no mandates → empty lists). Never throws for
 * a per-mandate error — the lost recipients surface via `.errors` so a
 * caller can tell the user "couldn't seal for mandate X: …" without
 * aborting the whole publish.
 */
export async function fetchActiveDelegateRecipients(
  ownerDid: string,
  now: Date = new Date(),
): Promise<DelegateRecipientsByZone> {
  const nowSec = Math.floor(now.getTime() / 1000);

  // 1. Paginate list_mandates. We cap at a few pages — an owner with more
  //    than a few hundred active mandates is well outside MVP territory,
  //    and we'd rather take the hit of an occasional re-sync than block
  //    publish on a slow listing.
  const rows = await collectMandates(ownerDid);

  // 2. Filter by time window + zone scope. We keep per-zone buckets so
  //    one get_mandate call covers both zones when a mandate grants both.
  const perZoneCandidates: Record<SealedZone, MandateCard[]> = {
    circle: [],
    self: [],
  };
  for (const row of rows) {
    if (typeof row.not_before === "number" && row.not_before > nowSec) continue;
    if (typeof row.not_after === "number" && row.not_after < nowSec) continue;
    for (const z of ["circle", "self"] as const) {
      if ((row.scopes ?? []).includes(READ_SCOPE_FOR[z])) {
        perZoneCandidates[z].push(row);
      }
    }
  }

  // 3. Resolve full mandate for every unique mandate_id, to read grantee.
  //    Deduplicate across zones since one mandate can grant both.
  const uniqueIds = new Set<string>();
  for (const z of ["circle", "self"] as const) {
    for (const r of perZoneCandidates[z]) uniqueIds.add(r.mandate_id);
  }

  const fetched = new Map<string, SignedMandate | null>();
  const errors: DelegateRecipientsByZone["errors"][number][] = [];
  await Promise.all(
    Array.from(uniqueIds).map(async (mid) => {
      try {
        const resp = await readRpc<GetMandateResponse>("aithos.get_mandate", {
          mandate_id: mid,
        });
        if (resp.revoked) {
          fetched.set(mid, null);
          return;
        }
        fetched.set(mid, resp.mandate.object);
      } catch (e) {
        const reason =
          e instanceof AithosRpcError
            ? `${e.code}: ${e.message}`
            : (e as Error).message;
        // Attribute the error to every zone the mandate was supposed to
        // cover so the UX can explain the loss per zone.
        for (const z of ["circle", "self"] as const) {
          if (perZoneCandidates[z].some((r) => r.mandate_id === mid)) {
            errors.push({ mandate_id: mid, zone: z, reason });
          }
        }
        fetched.set(mid, null);
      }
    }),
  );

  // 4. Project each active mandate into an EncryptRecipient per zone.
  const out: Record<SealedZone, EncryptRecipient[]> = { circle: [], self: [] };
  for (const z of ["circle", "self"] as const) {
    for (const row of perZoneCandidates[z]) {
      const mandate = fetched.get(row.mandate_id);
      if (!mandate) continue;
      const pubkeyMb = mandate.grantee?.pubkey;
      if (!pubkeyMb) {
        errors.push({
          mandate_id: row.mandate_id,
          zone: z,
          reason: "grantee.pubkey missing — mandate can't be sealed for",
        });
        continue;
      }
      try {
        const edPub = multibaseToEd25519PublicKey(pubkeyMb);
        const xPub = edPubToX25519Pub(edPub);
        const didUrl = `${mandate.grantee.id}#${pubkeyMb}`;
        out[z].push({ didUrl, x25519PublicKey: xPub });
      } catch (e) {
        errors.push({
          mandate_id: row.mandate_id,
          zone: z,
          reason: `pubkey decode/convert failed: ${(e as Error).message}`,
        });
      }
    }
  }

  return { circle: out.circle, self: out.self, errors };
}

/* -------------------------------------------------------------------------- */
/*  Delegate-write recipient discovery (Phase E.2)                            */
/* -------------------------------------------------------------------------- */

export interface ZoneRecipientsForWrite {
  /** The full wrap list — owner + writing delegate + every other active delegate with read/write on this zone. */
  readonly recipients: readonly EncryptRecipient[];
  /** Non-fatal failures we couldn't project into recipients. */
  readonly errors: readonly {
    readonly mandate_id: string;
    readonly reason: string;
  }[];
}

export interface ZoneRecipientsForWriteOpts {
  /** The subject DID (whose zone we're writing). */
  readonly subjectDid: string;
  /** Which sealed zone — `circle` or `self`. */
  readonly zone: SealedZone;
  /**
   * The writing delegate's own (granteeId, pubkey multibase). Included in
   * the recipient list directly regardless of whether `list_mandates` has
   * indexed that mandate yet — sealing without yourself would brick your
   * next read of what you just wrote.
   */
  readonly writer: {
    readonly granteeId: string;
    readonly granteePubkeyMultibase: string;
  };
  /** Current moment — injectable for tests, defaults to Date(). */
  readonly now?: Date;
}

/**
 * Build the wrap list a delegate must seal a private zone for when
 * publishing a new edition. Contract:
 *
 *   - The owner must always be there, otherwise the subject can't open
 *     their own zone after sign-out. Derived from `keyAgreement` on the
 *     subject's did.json (publicKeyMultibase of `{did}#{zone}-kex`).
 *   - The writing delegate themselves — otherwise the first thing they
 *     try to re-read post-publish fails the wrap match.
 *   - Every other active delegate whose mandate grants `ethos.read.<z>`
 *     or `ethos.write.<z>` for this zone, and is neither revoked nor
 *     outside its validity window.
 *
 * Resolution mirrors `fetchActiveDelegateRecipients` but from the
 * delegate's (anonymous) point of view — list_mandates + get_mandate are
 * both public reads, so the call surface is identical.
 */
export async function fetchZoneRecipientsForDelegateWrite(
  opts: ZoneRecipientsForWriteOpts,
): Promise<ZoneRecipientsForWrite> {
  const { subjectDid, zone, writer } = opts;
  const now = opts.now ?? new Date();
  const nowSec = Math.floor(now.getTime() / 1000);
  const readScope = `ethos.read.${zone}`;
  const writeScope = `ethos.write.${zone}`;

  const recipients: EncryptRecipient[] = [];
  const seen = new Set<string>();
  const errors: ZoneRecipientsForWrite["errors"][number][] = [];

  // 1. Owner — read the subject's did.json and get the X25519 key for
  //    this zone's recipient slot.
  //
  //    Preferred source: the `keyAgreement` entry keyed
  //    `{did}#{zone}-kex` that `signedDidDocument` (identity.ts) has
  //    populated for every identity since the keyAgreement rollout.
  //
  //    Fallback: identities minted before that change don't carry
  //    keyAgreement at all. We can still derive the X25519 pubkey
  //    from the zone's Ed25519 verificationMethod via the standard
  //    Edwards → Montgomery isogeny — which is exactly what the owner
  //    does client-side when they seal their own zone (sealPrivateZone
  //    uses `x25519.getPublicKey(edSeedToX25519Secret(seed))`, whose
  //    public counterpart is edPubToX25519Pub of the same Ed25519
  //    pubkey). Falling back keeps the publish path working for
  //    pre-rollout identities without requiring them to re-publish
  //    did.json first.
  const didResp = await readRpc<{ object: DidDocument }>("aithos.get_identity", {
    did: subjectDid,
  });
  const didDoc = didResp.object;
  const ownerKexKeyId = `${subjectDid}#${zone}-kex`;

  let ownerX25519Pub: Uint8Array;
  const ownerKex = didDoc.keyAgreement?.find((k) => k.id === ownerKexKeyId);
  if (ownerKex) {
    ownerX25519Pub = multibaseToX25519PublicKey(ownerKex.publicKeyMultibase);
  } else {
    const sphereVm = didDoc.verificationMethod?.find(
      (v) => v.id === `${subjectDid}#${zone}`,
    );
    if (!sphereVm) {
      throw new Error(
        `neither ${ownerKexKeyId} nor ${subjectDid}#${zone} found in did.json — ` +
          `cannot seal for owner`,
      );
    }
    try {
      const edPub = multibaseToEd25519PublicKey(sphereVm.publicKeyMultibase);
      ownerX25519Pub = edPubToX25519Pub(edPub);
    } catch (e) {
      throw new Error(
        `failed to derive owner X25519 pubkey for zone ${zone}: ${(e as Error).message}`,
      );
    }
  }

  const ownerRecipient: EncryptRecipient = {
    didUrl: ownerKexKeyId,
    x25519PublicKey: ownerX25519Pub,
  };
  recipients.push(ownerRecipient);
  seen.add(ownerRecipient.didUrl);

  // 2. Writing delegate — compute X25519 from its own Ed25519 pubkey.
  try {
    const edPub = multibaseToEd25519PublicKey(writer.granteePubkeyMultibase);
    const writerRec: EncryptRecipient = {
      didUrl: `${writer.granteeId}#${writer.granteePubkeyMultibase}`,
      x25519PublicKey: edPubToX25519Pub(edPub),
    };
    if (!seen.has(writerRec.didUrl)) {
      recipients.push(writerRec);
      seen.add(writerRec.didUrl);
    }
  } catch (e) {
    // Malformed writer pubkey — the delegate bundle is broken, we can't
    // safely proceed (we'd seal only for the owner, locking the writer
    // out of re-reading its own write).
    throw new Error(
      `writer pubkey decode failed: ${(e as Error).message}`,
    );
  }

  // 3. Every other active delegate with read/write scope on this zone.
  const rows = await collectMandates(subjectDid);
  const candidates = rows.filter((row) => {
    if (typeof row.not_before === "number" && row.not_before > nowSec) return false;
    if (typeof row.not_after === "number" && row.not_after < nowSec) return false;
    const scopes = row.scopes ?? [];
    return scopes.includes(readScope) || scopes.includes(writeScope);
  });

  await Promise.all(
    candidates.map(async (row) => {
      try {
        const resp = await readRpc<{
          mandate: { object: SignedMandate };
          revoked: boolean;
        }>("aithos.get_mandate", { mandate_id: row.mandate_id });
        if (resp.revoked) return;
        const m = resp.mandate.object;
        const pubkeyMb = m.grantee?.pubkey;
        const granteeId = m.grantee?.id;
        if (!pubkeyMb || !granteeId) {
          errors.push({
            mandate_id: row.mandate_id,
            reason: "grantee.pubkey or .id missing",
          });
          return;
        }
        const didUrl = `${granteeId}#${pubkeyMb}`;
        if (seen.has(didUrl)) return;
        const edPub = multibaseToEd25519PublicKey(pubkeyMb);
        const xPub = edPubToX25519Pub(edPub);
        recipients.push({ didUrl, x25519PublicKey: xPub });
        seen.add(didUrl);
      } catch (e) {
        const reason =
          e instanceof AithosRpcError
            ? `${e.code}: ${e.message}`
            : (e as Error).message;
        errors.push({ mandate_id: row.mandate_id, reason });
      }
    }),
  );

  return { recipients, errors };
}

/* -------------------------------------------------------------------------- */
/*  internals                                                                 */
/* -------------------------------------------------------------------------- */

async function collectMandates(issuerDid: string): Promise<MandateCard[]> {
  const all: MandateCard[] = [];
  let cursor: string | undefined;
  // Bound the crawl — an owner with thousands of active mandates is a
  // separate conversation. At 200/page × 5 pages = 1000 we've already
  // issued more read traffic than the publish itself.
  for (let i = 0; i < 5; i++) {
    const page = await readRpc<MandatesPage>("aithos.list_mandates", {
      issuer_did: issuerDid,
      limit: 200,
      ...(cursor ? { cursor } : {}),
    });
    all.push(...page.items);
    if (!page.next_cursor) break;
    cursor = page.next_cursor;
  }
  return all;
}
