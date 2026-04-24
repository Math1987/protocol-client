// Helpers for rendering and parsing DIDs and zone bytes.

/** Strip the fragment off a DID URL. */
export function stripFragment(didUrl: string): string {
  const i = didUrl.indexOf("#");
  return i === -1 ? didUrl : didUrl.slice(0, i);
}

/**
 * Extract the multibase-encoded root public key from `did:aithos:<mb>`.
 * Returns null if the input isn't a did:aithos.
 */
export function rootMultibase(did: string): string | null {
  const m = did.match(/^did:aithos:([^#]+)/);
  return m ? (m[1] ?? null) : null;
}

/**
 * First `n` characters of the root multibase — used as a disambiguating
 * suffix in canonical URLs (aithos.be/@handle#<did-prefix>).
 */
export function didPrefix(did: string, n = 10): string | null {
  const mb = rootMultibase(did);
  return mb ? mb.slice(0, n) : null;
}

/** Turn a base64-encoded zone into its decoded bytes, as a string if UTF-8. */
export function decodeZoneText(bytesBase64: string): string {
  const bin = atob(bytesBase64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}

/** Unix-seconds → locale date string. */
export function formatDate(unixSeconds: number | undefined): string {
  if (!unixSeconds) return "";
  return new Date(unixSeconds * 1000).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
