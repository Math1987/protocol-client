// Storage-shape contracts for identity and delegate records.
//
// These types describe the protocol-level content a keystore implementation
// must produce and consume. The implementation itself (IndexedDB, localStorage,
// encrypted file, remote KMS, etc.) lives outside this package — typically in
// `@aithos/extension-kit` or a consumer's own adapter.
//
// Kept distinct from the wire-format types so that a keystore author can
// version their storage schema (e.g. rewrap under a new passphrase, migrate
// between DB versions) without touching protocol signatures.

/**
 * A signed-in identity as persisted by a keystore.
 *
 * The `seeds` object holds hex-encoded 32-byte Ed25519 seeds for each key
 * role. Sphere keys (circle/self) are derived from these — see
 * `crypto/identity.ts` for the derivation.
 */
export interface StoredIdentity {
  readonly version: "0.1.0";
  readonly handle: string;
  readonly displayName: string;
  readonly did: string;
  /** Hex-encoded 32-byte Ed25519 seeds for each key role. */
  readonly seeds: {
    readonly root: string;
    readonly public: string;
    readonly circle: string;
    readonly self: string;
  };
  /** Added on save, not authoritative. */
  readonly savedAt: string;
}

/**
 * A delegate session — the material an extension or third-party app needs
 * to act on behalf of an owner under a mandate.
 *
 * The `mandate` field is the full signed Mandate bundle (§4.2 in the spec);
 * it's stored as an opaque JSON object here so the storage layer doesn't
 * lock in a particular parsed representation.
 */
export interface StoredDelegate {
  readonly version: "0.1.0";
  readonly subjectDid: string;
  /** The mandate we're acting under — stored as an opaque JSON object. */
  readonly mandate: Record<string, unknown>;
  /** Mandate ID, copied out for fast display/header checks. Used as the store key. */
  readonly mandateId: string;
  /** Grantee URN (e.g. `urn:aithos:agent:bob1`). */
  readonly granteeId: string;
  /** Grantee Ed25519 pubkey (multibase z…). Matches `mandate.grantee.pubkey`. */
  readonly granteePubkeyMultibase: string;
  /** Hex-encoded 32-byte Ed25519 seed for the delegate key. */
  readonly delegateSeedHex: string;
  readonly importedAt: string;
}
