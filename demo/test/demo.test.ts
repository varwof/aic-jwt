// Demo library tests. Run with: npm test  (Node 22+, type stripping)
import { test } from "node:test";
import assert from "node:assert/strict";
import { verifyHumanCertificate } from "../src/lib/identity.ts";
import {
  createDemoWorld,
  demonstrateOutOfScopeIssuance,
  runScenario,
} from "../src/lib/scenario.ts";
import { tamperToken } from "../src/lib/ca.ts";

const subtle = globalThis.crypto.subtle;

async function genKey(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

test("happy path: human cert -> DA -> CA cert -> gateway permits", async () => {
  const world = await createDemoWorld();
  const result = await runScenario(world, "happy");
  assert.ok(result.report, "expected a verification report");
  assert.equal(result.report.permit, true);
  assert.ok(result.report.decision);
  assert.equal(result.report.decision.actor, "alice");
  assert.equal(result.report.decision.principal, "alice");
  for (const s of result.report.steps) assert.equal(s.status, "ok", `step ${s.n}`);
});

test("overreach request is denied at capability evaluation (step 9)", async () => {
  const world = await createDemoWorld();
  const result = await runScenario(world, "overreach");
  assert.ok(result.report && !result.report.permit);
  const step9 = result.report.steps.find((s) => s.n === 9);
  assert.equal(step9?.status, "fail");
  assert.match(result.report.error ?? "", /not allowed/);
});

test("expired certificate is denied at time check (step 3)", async () => {
  const world = await createDemoWorld();
  const result = await runScenario(world, "expired");
  assert.ok(result.report && !result.report.permit);
  assert.equal(result.report.steps.find((s) => s.n === 3)?.status, "fail");
  assert.equal(result.report.steps.find((s) => s.n === 9)?.status, "skip");
});

test("tampered token is denied at JWS verification (step 1)", async () => {
  const world = await createDemoWorld();
  assert.notEqual(tamperToken(world.certificate.token), world.certificate.token);
  const result = await runScenario(world, "tampered");
  assert.ok(result.report && !result.report.permit);
  assert.equal(result.report.steps.find((s) => s.n === 1)?.status, "fail");
});

test("spoofed presenter key is denied at identity binding (step 12)", async () => {
  const world = await createDemoWorld();
  const result = await runScenario(world, "spoofed");
  assert.ok(result.report && !result.report.permit);
  const step12 = result.report.steps.find((s) => s.n === 12);
  assert.equal(step12?.status, "fail");
  assert.match(result.report.error ?? "", /cnf: presenter/);
});

test("constraint violation (concurrency) is denied at step 7", async () => {
  const world = await createDemoWorld();
  const result = await runScenario(world, "concurrency");
  assert.ok(result.report && !result.report.permit);
  assert.equal(result.report.steps.find((s) => s.n === 7)?.status, "fail");
});

test("CA refuses out-of-scope delegation at issuance", async () => {
  const world = await createDemoWorld();
  const refusal = await demonstrateOutOfScopeIssuance(world);
  assert.equal(refusal.rejected, true);
  assert.match(refusal.reason, /least[- ]privilege|issuance refused|签发被拒/);
});

test("human certificate verifies against its key and rejects a wrong key", async () => {
  const world = await createDemoWorld();
  const claims = await verifyHumanCertificate(
    world.human.certificate,
    world.human.keyPair.publicKey,
  );
  assert.equal(claims.principal.id, "alice");
  const other = await genKey();
  await assert.rejects(
    verifyHumanCertificate(world.human.certificate, other.publicKey),
  );
});

test("DA nonce is a 32-byte base64url value", async () => {
  const world = await createDemoWorld();
  const bin = atob(world.da.claims.nonce.replace(/-/g, "+").replace(/_/g, "/"));
  const nb = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) nb[i] = bin.charCodeAt(i);
  assert.equal(nb.length, 32);
});
