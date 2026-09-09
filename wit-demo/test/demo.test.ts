// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// wit-demo 的 lib 逻辑在 Node 下复用 WebCrypto 跑 S1/S2/S4/S5/S7/S8/S10。
// 运行：
//   node --disable-warning=ExperimentalWarning --experimental-strip-types --test wit-demo/test/demo.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";

import { generateKey } from "../src/lib/jwk.ts";
import { Issuer, signArtifact } from "../src/lib/issuer.ts";
import { Verifier, mintWPT, witKeyOf } from "../src/lib/verifier.ts";
import { capabilityCoveredIn } from "../src/lib/subset.ts";
import { b64e, keyHashOf } from "../src/lib/jose.ts";
import type {
  Capability,
  DA,
  PA,
  Principal,
  Request,
  WITGrant,
  Decision,
} from "../src/lib/types.ts";
import type { VerifyOpts } from "../src/lib/verifier.ts";

const now0 = 1_700_000_000;
const targetURI = "https://rs.example.com/orders";

class Env {
  principal: CryptoKeyPair;
  issuer: CryptoKeyPair;
  iss: Issuer;
  ver: Verifier;

  constructor(principal: CryptoKeyPair, issuer: CryptoKeyPair) {
    this.principal = principal;
    this.issuer = issuer;
    this.iss = new Issuer("example.org", issuer.privateKey, "wk-01");
    this.ver = new Verifier({ "wk-01": issuer.publicKey }, () => now0);
  }
}

async function newEnv(): Promise<Env> {
  return new Env(await generateKey(), await generateKey());
}

async function capOf(scheme: string, id: string, params?: unknown): Promise<Capability> {
  const c: Capability = { scheme, id };
  if (params !== undefined) {
    c.params = JSON.parse(JSON.stringify(params));
  }
  return c;
}

async function principalOf(
  pair: CryptoKeyPair,
  realm: string,
  id: string,
): Promise<Principal> {
  return {
    realm,
    id,
    key_hash: await keyHashOf(pair.publicKey, "sha-256"),
    hash_alg: "sha-256",
  };
}

async function makeDA(
  p: Principal,
  agentID: string,
  caps: Capability[],
  mode: DA["delegation_mode"],
  now: number,
  lifetime = 3600,
): Promise<DA> {
  return {
    ver: 1,
    agent_id: agentID,
    principal: p,
    reason: { code: "access", desc: "grid access granted" },
    capabilities: caps,
    delegation_mode: mode,
    constraints: [],
    requested_lifetime: lifetime,
    ts: now,
    nonce: b64e(crypto.getRandomValues(new Uint8Array(32))),
  };
}

async function makePA(p: Principal, grants: Capability[]): Promise<PA> {
  return { ver: 1, principal: p, grants, constraints: [] };
}

const daCompact = (env: Env, d: DA): Promise<string> =>
  signArtifact("da+jwt", d, env.principal.privateKey);
const paCompact = (env: Env, p: PA): Promise<string> =>
  signArtifact("pa+jwt", p, env.principal.privateKey);

async function happyGrant(env: Env): Promise<WITGrant> {
  const p = await principalOf(env.principal, "realm.example", "alice");
  const grants = [await capOf("mysql", "query", { max_rows: 1000 })];
  const caps = [await capOf("mysql", "query", { max_rows: 500 })];
  const da = await makeDA(p, "agent-1", caps, "representative", now0);
  const pa = await makePA(p, grants);
  return env.iss.issue(await daCompact(env, da), await paCompact(env, pa), "agent-1", now0);
}

function entitlementPolicy() {
  return (_ent: Capability[], c: Capability): void => {
    const { ok } = capabilityCoveredIn(c, _ent);
    if (!ok) {
      throw new Error("requested capability not in entitlement");
    }
  };
}

async function happyInputs(env: Env) {
  const g = await happyGrant(env);
  const wpt = await mintWPT(g.wit_svid, "GET", targetURI, now0, await witKeyOf(g));
  const rc = await capOf("mysql", "query", { max_rows: 500 });
  const req: Request = {
    method: "GET",
    target_uri: targetURI,
    now: now0,
    requested_capability: rc,
  };
  const opts: VerifyOpts = { entitlement: g.entitlement, policy: entitlementPolicy() };
  return { wit: g.wit_svid, wpt, req, opts };
}

test("S1 happy path -> PERMIT", async () => {
  const env = await newEnv();
  const g = await happyGrant(env);
  const r = await happyInputs(env);
  void g;
  const d: Decision = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
  assert.equal(d.permit, true, `expected PERMIT, reason=${d.reason}`);
  assert.equal(d.reason, "PERMIT");
});

test("S2 agent caps exceed P_grants -> issuance denied (subset)", async () => {
  const env = await newEnv();
  const p = await principalOf(env.principal, "realm.example", "alice");
  const grants = [await capOf("mysql", "query", { max_rows: 1000 })];
  const caps = [await capOf("mysql", "query", { max_rows: 5000 })];
  const da = await makeDA(p, "agent-1", caps, "representative", now0);
  const pa = await makePA(p, grants);
  await assert.rejects(
    env.iss.issue(await daCompact(env, da), await paCompact(env, pa), "agent-1", now0),
    /subset/,
  );
});

test("S4 WPT signed with a different key -> DENY (pop)", async () => {
  const env = await newEnv();
  const r = await happyInputs(env);
  const other = await generateKey();
  const g = await happyGrant(env);
  const badWpt = await mintWPT(g.wit_svid, "GET", targetURI, now0, other.privateKey);
  const d = await env.ver.verify(g.wit_svid, badWpt, r.req, r.opts);
  assert.equal(d.permit, false);
  assert.ok(d.reason.includes("pop"), `reason=${d.reason}`);
});

test("S5 WPT aud != request target URI -> DENY (aud mismatch)", async () => {
  const env = await newEnv();
  const r = await happyInputs(env);
  const req: Request = {
    method: "POST",
    target_uri: "https://rs.example.com/invoices",
    now: now0,
  };
  const d = await env.ver.verify(r.wit, r.wpt, req, r.opts);
  assert.equal(d.permit, false);
  assert.ok(d.reason.includes("aud mismatch"), `reason=${d.reason}`);
});

test("S7 WPT replay -> second verify DENY (replay)", async () => {
  const env = await newEnv();
  const r = await happyInputs(env);
  const first = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
  assert.equal(first.permit, true, `first should PERMIT: ${first.reason}`);
  const second = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
  assert.equal(second.permit, false);
  assert.ok(second.reason.includes("replay"), `reason=${second.reason}`);
});

test("S8 no WPT (bearer misuse) -> DENY (pop required)", async () => {
  const env = await newEnv();
  const r = await happyInputs(env);
  const d = await env.ver.verify(r.wit, "", r.req, r.opts);
  assert.equal(d.permit, false);
  assert.ok(d.reason.includes("pop required"), `reason=${d.reason}`);
});

test("S10 requested capability outside entitlement -> DENY (policy:)", async () => {
  const env = await newEnv();
  const r = await happyInputs(env);
  const rc = await capOf("mysql", "drop");
  const req: Request = {
    method: "POST",
    target_uri: targetURI,
    now: now0,
    requested_capability: rc,
  };
  const d = await env.ver.verify(r.wit, r.wpt, req, r.opts);
  assert.equal(d.permit, false);
  assert.ok(d.reason.startsWith("policy:"), `reason=${d.reason}`);
});