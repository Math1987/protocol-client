// Parse the rendered public-zone markdown back into a structured ZoneDoc.
//
// Inverse of `renderPublicMarkdown` in lib/crypto/manifest.ts. The on-disk
// format is deterministic:
//
//   ---
//   aithos: "0.2.0"
//   zone: public
//   subject_did: ...
//   subject_handle: ...
//   edition: ...
//   created_at: ...
//   ---
//
//   # <title> <!-- <id> · <gamma_ref> -->
//   <!-- tags: ["a","b"] -->           (optional)
//
//   <body lines>
//
//   # <title 2> <!-- ... -->
//   ...
//
// This parser is deliberately forgiving about whitespace and keeps
// unrecognized top-of-file lines as non-content (skips them).

import type { Section } from "./crypto/manifest.js";

export interface ParsedZone {
  readonly sections: readonly Section[];
}

const SECTION_HEADER_RE = /^#\s+(.+?)\s+<!--\s+(\S+)\s+·\s+(\S+)\s+-->$/;
const TAGS_LINE_RE = /^<!--\s+tags:\s+(\[.*\])\s+-->$/;

export function parsePublicZone(markdown: string): ParsedZone {
  const lines = markdown.split("\n");
  let i = 0;

  // Skip YAML frontmatter (between the first pair of `---` lines).
  if (lines[i] === "---") {
    i++;
    while (i < lines.length && lines[i] !== "---") i++;
    if (i < lines.length) i++;
  }

  const sections: Section[] = [];

  while (i < lines.length) {
    while (i < lines.length && lines[i]!.trim() === "") i++;
    if (i >= lines.length) break;

    const header = lines[i]!.match(SECTION_HEADER_RE);
    if (!header) {
      // Unknown content outside any section — ignore.
      i++;
      continue;
    }
    const title = header[1]!;
    const id = header[2]!;
    const gamma_ref = header[3]!;
    i++;

    let tags: string[] | undefined;
    if (i < lines.length) {
      const tagMatch = lines[i]!.match(TAGS_LINE_RE);
      if (tagMatch) {
        try {
          const parsed = JSON.parse(tagMatch[1]!);
          if (Array.isArray(parsed)) tags = parsed.filter((t) => typeof t === "string");
        } catch {
          /* ignore malformed tags line */
        }
        i++;
      }
    }

    // Skip the blank separator between tags/title and body.
    while (i < lines.length && lines[i]!.trim() === "") i++;

    const bodyLines: string[] = [];
    while (i < lines.length && !lines[i]!.startsWith("# ")) {
      bodyLines.push(lines[i]!);
      i++;
    }
    while (bodyLines.length > 0 && bodyLines[bodyLines.length - 1]!.trim() === "") {
      bodyLines.pop();
    }
    const body = bodyLines.join("\n");

    sections.push({
      id,
      title,
      body,
      gamma_ref,
      ...(tags && tags.length > 0 ? { tags } : {}),
    });
  }

  return { sections };
}
