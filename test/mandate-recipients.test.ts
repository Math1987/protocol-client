// mandateToRecipients applies impliedRead — a write.X scope must
// produce a recipient for X, otherwise the delegate can't decrypt the
// zone it's supposed to write to.

import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mandateToRecipients,
  type SignedMandate,
} from "../src/index.js";

// A real Ed25519 multibase pubkey copied from a fixture mandate
// (z6Mk… is the multikey prefix for Ed25519 in the multibase format).
const PUBKEY = "z6MkokbQF9g3wr65GEWSRQ98s4oR2qgSfnmL499pySGuLc24";

function makeMandate(scopes: readonly string[]): SignedMandate {
  return {
    "aithos-mandate": "0.2.0",
    id: "mandate_test",
    issuer: "did:aithos:owner",
    issued_by_key: "did:aithos:owner#self",
    grantee: { id: "urn:aithos:agent", pubkey: PUBKEY },
    actor_sphere: "self",
    scopes: [...scopes],
    not_before: "2026-04-24T00:00:00Z",
    not_after: "2026-05-24T00:00:00Z",
    issued_at: "2026-04-24T00:00:00Z",
    nonce: "abcd",
    signature: { alg: "ed25519", key: "did:aithos:owner#self", value: "deadbeef" },
  } as unknown as SignedMandate;
}

test("read.self mandate produces self recipient (existing behaviour)", () => {
  const r = mandateToRecipients(makeMandate(["ethos.read.self"]));
  assert.ok(r.self, "expected self recipient");
  assert.equal(r.circle, undefined);
});

test("read.circle mandate produces circle recipient", () => {
  const r = mandateToRecipients(makeMandate(["ethos.read.circle"]));
  assert.ok(r.circle, "expected circle recipient");
  assert.equal(r.self, undefined);
});

test("write.self ALONE produces self recipient (impliedRead)", () => {
  // The bug fix: a delegate with only write.self must still be wrapped
  // in self's cipher so it can decrypt-then-republish.
  const r = mandateToRecipients(makeMandate(["ethos.write.self"]));
  assert.ok(r.self, "write.self must imply self recipient");
  assert.equal(r.circle, undefined);
});

test("write.circle ALONE produces circle recipient", () => {
  const r = mandateToRecipients(makeMandate(["ethos.write.circle"]));
  assert.ok(r.circle, "write.circle must imply circle recipient");
  assert.equal(r.self, undefined);
});

test("write.self + read.circle covers both", () => {
  const r = mandateToRecipients(
    makeMandate(["ethos.write.self", "ethos.read.circle"]),
  );
  assert.ok(r.self);
  assert.ok(r.circle);
});

test("read-only public-only mandate produces no recipients", () => {
  const r = mandateToRecipients(makeMandate(["ethos.read.public"]));
  assert.equal(r.self, undefined);
  assert.equal(r.circle, undefined);
});

test("missing grantee.pubkey returns empty", () => {
  const m = makeMandate(["ethos.write.self"]);
  const noKey = { ...m, grantee: { id: "urn:x" } } as unknown as SignedMandate;
  const r = mandateToRecipients(noKey);
  assert.equal(r.self, undefined);
});
