// Tests for parseConnectRequest + inferActorSphere — the wire shape
// for the extension ↔ host onboarding handshake.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  parseConnectRequest,
  inferActorSphere,
  CONNECT_TTL_MIN_SECONDS,
  CONNECT_TTL_MAX_SECONDS,
} from "../src/index.js";

const validExt = "doicbchenmlodboffhkblojhjjcpgonk"; // 32 chars, a-p only
const validPubkey = "z6MkXXXXXXXXXXXXXXXXXXXXXXXX";

function url(over: Record<string, string> = {}): URLSearchParams {
  const base: Record<string, string> = {
    app: "mail",
    name: "Aithos Mail",
    ext: validExt,
    pubkey: validPubkey,
    scopes: "ethos.write.self,ethos.read.circle",
    ttl: String(60 * 60 * 24 * 30),
  };
  return new URLSearchParams({ ...base, ...over });
}

test("parseConnectRequest — happy path", () => {
  const r = parseConnectRequest(url());
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.req.app, "mail");
    assert.equal(r.req.name, "Aithos Mail");
    assert.equal(r.req.ext, validExt);
    assert.equal(r.req.pubkey, validPubkey);
    assert.deepEqual([...r.req.scopes], ["ethos.write.self", "ethos.read.circle"]);
    assert.equal(r.req.ttlSeconds, 60 * 60 * 24 * 30);
  }
});

test("parseConnectRequest — name defaults to app slug if missing", () => {
  const q = url();
  q.delete("name");
  const r = parseConnectRequest(q);
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.req.name, "mail");
});

test("parseConnectRequest — rejects missing app", () => {
  const q = url();
  q.delete("app");
  const r = parseConnectRequest(q);
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /missing \?app/);
});

test("parseConnectRequest — rejects malformed extension id", () => {
  const r = parseConnectRequest(url({ ext: "not-an-extension-id" }));
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /Chrome extension id/);
});

test("parseConnectRequest — rejects extension id with capital letters", () => {
  // Chrome ext IDs are strictly lowercase a-p.
  const bad = "Doicbchenmlodboffhkblojhjjcpgonk";
  const r = parseConnectRequest(url({ ext: bad }));
  assert.equal(r.ok, false);
});

test("parseConnectRequest — rejects non-multibase pubkey", () => {
  const r = parseConnectRequest(url({ pubkey: "not-multibase" }));
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /multibase/);
});

test("parseConnectRequest — rejects unknown scope", () => {
  const r = parseConnectRequest(url({ scopes: "ethos.write.self,ethos.evil" }));
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /unknown scope/);
});

test("parseConnectRequest — rejects empty scopes", () => {
  const r = parseConnectRequest(url({ scopes: "" }));
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.error, /empty/);
});

test("parseConnectRequest — rejects ttl out of range", () => {
  const tooShort = parseConnectRequest(url({ ttl: String(CONNECT_TTL_MIN_SECONDS - 1) }));
  assert.equal(tooShort.ok, false);
  const tooLong = parseConnectRequest(url({ ttl: String(CONNECT_TTL_MAX_SECONDS + 1) }));
  assert.equal(tooLong.ok, false);
  const nan = parseConnectRequest(url({ ttl: "abc" }));
  assert.equal(nan.ok, false);
});

test("parseConnectRequest — trims and filters empty scopes", () => {
  const r = parseConnectRequest(url({ scopes: " ethos.read.self , , ethos.write.self " }));
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.deepEqual([...r.req.scopes], ["ethos.read.self", "ethos.write.self"]);
  }
});

/* -------------------------------------------------------------------------- */
/*  inferActorSphere                                                          */
/* -------------------------------------------------------------------------- */

test("inferActorSphere — read-only mandate → self", () => {
  assert.equal(
    inferActorSphere(["ethos.read.circle", "ethos.read.self"]),
    "self",
  );
});

test("inferActorSphere — write to self → self", () => {
  assert.equal(
    inferActorSphere(["ethos.write.self", "ethos.read.circle"]),
    "self",
  );
});

test("inferActorSphere — write to circle → circle", () => {
  assert.equal(
    inferActorSphere(["ethos.write.circle"]),
    "circle",
  );
});

test("inferActorSphere — write to public → public", () => {
  assert.equal(
    inferActorSphere(["ethos.write.public"]),
    "public",
  );
});

test("inferActorSphere — multiple write targets → error", () => {
  const r = inferActorSphere(["ethos.write.self", "ethos.write.circle"]);
  assert.notEqual(typeof r, "string");
  if (typeof r !== "string") {
    assert.match(r.error, /multiple zones/);
  }
});
