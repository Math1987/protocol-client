// RFC 8785 JSON Canonicalization Scheme (JCS) — minimal implementation.
//
// Ported from @aithos/protocol-core's `canonical.ts`. Produces the exact
// same byte sequence as the reference implementation so client- and
// server-side signatures agree.
//
// Only supports the JSON subset that appears in Aithos documents: strings,
// numbers (safe integers, common fractions), booleans, null, arrays,
// objects. No BigInt, no Dates, no pathological floats — if a caller
// ever needs those, extend here first.

export function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") return serializeString(value);
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalize).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    // Keys sorted by their UTF-16 code unit sequence (JS default string ordering).
    const keys = Object.keys(obj).sort();
    const parts: string[] = [];
    for (const k of keys) {
      if (obj[k] === undefined) continue; // JSON excludes undefined.
      parts.push(serializeString(k) + ":" + canonicalize(obj[k]));
    }
    return "{" + parts.join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new Error("canonicalize: non-finite numbers are not JSON-representable");
  }
  // ES6 ToString gives exactly the shortest round-tripping form for safe ints
  // and typical fractions — JCS aligns with it.
  return String(n);
}

// JCS §3.2.2 string escape rules — minimal escapes only.
function serializeString(s: string): string {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c === 0x22) out += '\\"';
    else if (c === 0x5c) out += "\\\\";
    else if (c === 0x08) out += "\\b";
    else if (c === 0x09) out += "\\t";
    else if (c === 0x0a) out += "\\n";
    else if (c === 0x0c) out += "\\f";
    else if (c === 0x0d) out += "\\r";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += s[i];
  }
  return out + '"';
}
