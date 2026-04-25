// Wire shape + validator for the Aithos extension connect handshake.
//
// An Aithos-aware browser extension opens a tab/popup at
// `https://app.aithos.be/connect?...` with a set of query parameters that
// describe what it needs (extension id, grantee pubkey, requested scopes,
// app display name, TTL). The host (typically a web app on aithos.be, but
// any other host implementing the same surface works the same way) parses
// those parameters and shows the user a confirmation UI.
//
// `parseConnectRequest` is the single source of truth for which parameter
// names exist, which formats are accepted, and which scopes are allowed.
// Any deviation between the extension that BUILDS the URL and the host
// that PARSES it would silently fail or produce confusing errors — keeping
// the contract here means both sides break loudly when the protocol shape
// drifts.
//
// See `@aithos/extension-kit`'s `buildConnectUrl` for the corresponding
// builder.

/* -------------------------------------------------------------------------- */
/*  Allowed values                                                            */
/* -------------------------------------------------------------------------- */

/** The scope strings the connect handshake will accept. */
export const CONNECT_ALLOWED_SCOPES: ReadonlySet<string> = new Set([
  "ethos.read.public",
  "ethos.read.circle",
  "ethos.read.self",
  "ethos.write.public",
  "ethos.write.circle",
  "ethos.write.self",
]);

export const CONNECT_TTL_MIN_SECONDS = 60 * 60; // 1 hour — anything shorter is an aberration
export const CONNECT_TTL_MAX_SECONDS = 60 * 60 * 24 * 180; // 6 months

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

/**
 * A parsed, validated connect request. After `parseConnectRequest` returns
 * `{ ok: true }`, all fields are guaranteed to be valid in shape — the
 * host can use them directly without re-checking.
 */
export interface ConnectRequest {
  /** Short slug identifying the app type (e.g. "mail", "linkedin"). */
  readonly app: string;
  /** Display name shown in the confirmation UI (e.g. "Aithos Mail"). */
  readonly name: string;
  /** Chrome extension ID (32 chars, a-p only — verified). */
  readonly ext: string;
  /** Grantee Ed25519 pubkey, multibase-encoded (z…). */
  readonly pubkey: string;
  /** Scopes from CONNECT_ALLOWED_SCOPES. Non-empty. */
  readonly scopes: readonly string[];
  /** TTL in seconds, between CONNECT_TTL_MIN_SECONDS and CONNECT_TTL_MAX_SECONDS. */
  readonly ttlSeconds: number;
}

/* -------------------------------------------------------------------------- */
/*  Parser                                                                    */
/* -------------------------------------------------------------------------- */

/**
 * Parse + validate a connect URL's query string. Returns either a
 * `{ ok: true, req }` discriminated union on success, or
 * `{ ok: false, error }` with a human-readable error string suitable for
 * display in the confirmation UI.
 *
 * Accepts a `URLSearchParams` (the host can build it from `location.search`
 * or from a normal URL constructor; either works because both yield the
 * same iteration shape).
 */
export function parseConnectRequest(
  q: URLSearchParams,
): { ok: true; req: ConnectRequest } | { ok: false; error: string } {
  const app = q.get("app") ?? "";
  const name = q.get("name") ?? app;
  const ext = q.get("ext") ?? "";
  const pubkey = q.get("pubkey") ?? "";
  const scopesRaw = q.get("scopes") ?? "";
  const ttlRaw = q.get("ttl") ?? "";

  if (!app) return { ok: false, error: "missing ?app" };
  if (!ext) return { ok: false, error: "missing ?ext (extension id)" };
  if (!/^[a-p]{32}$/.test(ext)) {
    return { ok: false, error: `?ext is not a valid Chrome extension id` };
  }
  if (!pubkey) return { ok: false, error: "missing ?pubkey" };
  if (!/^z[1-9A-HJ-NP-Za-km-z]+$/.test(pubkey)) {
    return { ok: false, error: `?pubkey is not a valid multibase z… string` };
  }

  const scopes = scopesRaw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  if (scopes.length === 0) {
    return { ok: false, error: "?scopes is empty" };
  }
  for (const s of scopes) {
    if (!CONNECT_ALLOWED_SCOPES.has(s)) {
      return { ok: false, error: `?scopes contains unknown scope "${s}"` };
    }
  }

  const ttl = Number.parseInt(ttlRaw, 10);
  if (
    !Number.isFinite(ttl) ||
    ttl < CONNECT_TTL_MIN_SECONDS ||
    ttl > CONNECT_TTL_MAX_SECONDS
  ) {
    return {
      ok: false,
      error: `?ttl must be between ${CONNECT_TTL_MIN_SECONDS} and ${CONNECT_TTL_MAX_SECONDS} seconds`,
    };
  }

  return {
    ok: true,
    req: { app, name, ext, pubkey, scopes, ttlSeconds: ttl },
  };
}

/* -------------------------------------------------------------------------- */
/*  Sphere inference                                                          */
/* -------------------------------------------------------------------------- */

/**
 * Pick the actor sphere that matches the requested scopes.
 *
 * Rules:
 *   - If any `ethos.write.X` scope is present, the actor sphere MUST be X.
 *   - At most one write target per mandate (mixing
 *     `ethos.write.circle` + `ethos.write.self` is rejected — mint two).
 *   - If only read scopes, default to `self` (private spheres can read
 *     anything; using `self` keeps the most options open).
 *
 * Returns the sphere on success or an `{ error }` object explaining why
 * no valid sphere can satisfy the requested scopes.
 */
export function inferActorSphere(
  scopes: readonly string[],
): "public" | "circle" | "self" | { error: string } {
  const writes = scopes.filter((s) => s.startsWith("ethos.write."));
  if (writes.length === 0) {
    return "self";
  }
  const targets = new Set(writes.map((s) => s.replace("ethos.write.", "")));
  if (targets.size > 1) {
    return {
      error:
        "requested mandate writes to multiple zones — mint separate mandates per zone",
    };
  }
  const [zone] = targets;
  if (zone === "public" || zone === "circle" || zone === "self") {
    return zone;
  }
  return { error: `unknown write target: ${zone}` };
}
