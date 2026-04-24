// Wire types for the JSON-RPC responses. Subset of what the server returns —
// we only declare the fields the UI actually reads. Stays decoupled from
// @aithos/protocol-core so the app bundle doesn't balloon.

export interface DidProof {
  readonly proofValue: string;
  readonly verificationMethod: string;
  readonly created: string;
  readonly authorized_by?: string;
}

export interface SignedObject<T> {
  readonly object: T;
  readonly signature: DidProof;
  readonly fetched_at: string;
}

export interface DidDocument {
  readonly "@context": readonly string[];
  readonly id: string;
  readonly verificationMethod: readonly {
    readonly id: string;
    readonly type: string;
    readonly controller: string;
    readonly publicKeyMultibase: string;
  }[];
  readonly aithos?: {
    readonly version: string;
    readonly display_name?: string;
    readonly created_at: string;
  };
}

export interface Manifest {
  readonly aithos: string;
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
  readonly zones: Record<
    "public" | "circle" | "self",
    {
      readonly file: string;
      readonly encrypted: boolean;
      readonly sha256_of_plaintext: string;
      readonly section_titles: readonly string[];
    } | undefined
  >;
}

export interface ZoneBytesResponse {
  readonly did: string;
  readonly zone: string;
  readonly height: number;
  readonly encrypted: boolean;
  readonly sha256_of_plaintext: string;
  readonly bytes_base64: string;
}

export interface ResolveHandleMatch {
  readonly did: string;
  readonly did_prefix: string;
  readonly display_name?: string;
  readonly latest_height?: number;
  readonly created_at: number;
}

export interface ResolveHandleResult {
  readonly did: string;
  readonly handle: string;
  readonly did_prefix: string;
  readonly display_name?: string;
  readonly latest_height?: number;
  readonly created_at: number;
  readonly matches: readonly ResolveHandleMatch[];
}

export interface FeedItem {
  readonly did: string;
  readonly handle: string;
  readonly display_name?: string;
  readonly latest_height?: number;
  readonly created_at: number;
}

export interface FeedResult {
  readonly items: readonly FeedItem[];
  readonly next_cursor?: string;
}
