// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// S1..S11 场景矩阵（与 go/scenarios_test.go 一一对应，同一表格编号）。
// 运行：
//   node --disable-warning=ExperimentalWarning --experimental-strip-types --test src/scenarios.test.ts

import { test } from "node:test";
import assert from "node:assert/strict";
import { createPublicKey, randomBytes } from "node:crypto";
import type { KeyObject } from "node:crypto";

import { generateES256Key, keyHashOf } from "./jwk.ts";
import { Issuer, signArtifact } from "./issuer.ts";
import { Verifier, mintWPT, MemoryReplayStore, witKeyOf } from "./verifier.ts";
import { capabilityCoveredIn } from "./subset.ts";
import { signJWS, b64e } from "./jose.ts";
import type {
  Capability,
  DA,
  PA,
  Principal,
  Request,
  VerifyOpts,
  WITGrant,
  Decision,
} from "./types.ts";

const now0 = 1_700_000_000;
const targetURI = "https://rs.example.com/orders";

class Env {
  principal: KeyObject;
  issuerKey: KeyObject;
  iss: Issuer;
  ver: Verifier;

  constructor() {
    this.principal = generateES256Key();
    this.issuerKey = generateES256Key();
    this.iss = new Issuer("example.org", this.issuerKey, "wk-01");
    this.ver = new Verifier(
      { "wk-01": createPublicKey(this.issuerKey) },
      new MemoryReplayStore(),
    );
    this.ver.nowFn = () => now0;
  }
}

function mustKey(t: { name: string }): KeyObject {
  void t;
  return generateES256Key();
}

/** 构造 Capability，params 经 JSON 规范化（数字统一成 number）。 */
function capOf(scheme: string, id: string, params?: unknown): Capability {
  const c: Capability = { scheme, id };
  if (params !== undefined) {
    c.params = JSON.parse(JSON.stringify(params));
  }
  return c;
}

function principalOf(priv: KeyObject, realm: string, id: string): Principal {
  return {
    realm,
    id,
    key_hash: keyHashOf(createPublicKey(priv), "sha-256"),
    hash_alg: "sha-256",
  };
}

function makeDA(
  p: Principal,
  agentID: string,
  caps: Capability[],
  mode: DA["delegation_mode"],
  lifetime: number,
  now: number,
): DA {
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
    nonce: b64e(randomBytes(32)),
  };
}

function makePA(p: Principal, grants: Capability[]): PA {
  return { ver: 1, principal: p, grants, constraints: [] };
}

function daCompact(env: Env, d: DA): string {
  return signArtifact("da+jwt", d, env.principal);
}

function paCompact(env: Env, p: PA): string {
  return signArtifact("pa+jwt", p, env.principal);
}

/** 用发放服务密钥对修改后的 claims 重新签名（测试专用：WIT "改了字节但仍是有效生产产物"）。 */
function reSignWIT(env: Env, wit: string, mutate: (c: Record<string, unknown>) => void): string {
  const parts = wit.split(".");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString());
  const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString());
  mutate(claims);
  return signJWS(header, claims, env.issuerKey);
}

function happyGrant(env: Env): WITGrant {
  const p = principalOf(env.principal, "realm.example", "alice");
  const grants = [capOf("mysql", "query", { max_rows: 1000 })];
  const caps = [capOf("mysql", "query", { max_rows: 500 })];
  const da = makeDA(p, "agent-1", caps, "representative", 3600, now0);
  const pa = makePA(p, grants);
  return env.iss.issue(daCompact(env, da), paCompact(env, pa), "agent-1", now0);
}

function entitlementPolicy() {
  return (_ent: Capability[], c: Capability): void => {
    const { ok } = capabilityCoveredIn(c, _ent);
    if (!ok) {
      throw new Error("requested capability not in entitlement");
    }
  };
}

function happyInputs(env: Env) {
  const g = happyGrant(env);
  const wpt = mintWPT(g.wit_svid, "GET", targetURI, now0, witKeyOf(g));
  const rc = capOf("mysql", "query", { max_rows: 500 });
  const req: Request = {
    method: "GET",
    target_uri: targetURI,
    now: now0,
    requested_capability: rc,
  };
  const opts: VerifyOpts = { entitlement: g.entitlement, policy: entitlementPolicy() };
  return { wit: g.wit_svid, wpt, req, opts };
}

interface Run {
  wit: string;
  wpt: string;
  req: Request;
  opts: VerifyOpts;
  issueErr: string;
}

interface Case {
  id: string;
  name: string;
  wantPermit: boolean;
  wantReason: string;
  prepare: (env: Env) => Run;
}

const cases: Case[] = [
  {
    id: "S1",
    name: "happy path",
    wantPermit: true,
    wantReason: "",
    prepare: (env) => {
      const r = happyInputs(env);
      return { ...r, issueErr: "" };
    },
  },
  {
    id: "S2",
    name: "agent caps exceed P_grants (max_rows 5000 > 1000)",
    wantPermit: false,
    wantReason: "subset",
    prepare: (env) => {
      const p = principalOf(env.principal, "realm.example", "alice");
      const grants = [capOf("mysql", "query", { max_rows: 1000 })];
      const caps = [capOf("mysql", "query", { max_rows: 5000 })];
      const da = makeDA(p, "agent-1", caps, "representative", 3600, now0);
      const pa = makePA(p, grants);
      let issueErr = "";
      try {
        env.iss.issue(daCompact(env, da), paCompact(env, pa), "agent-1", now0);
      } catch (e) {
        issueErr = (e as Error).message;
      }
      return { wit: "", wpt: "", req: {} as Request, opts: {}, issueErr };
    },
  },
  {
    id: "S3",
    name: "tampered WIT + original WPT -> wth mismatch",
    wantPermit: false,
    wantReason: "wth mismatch",
    prepare: (env) => {
      const r = happyInputs(env);
      const bad = reSignWIT(env, r.wit, (c) => (c["tamper_flag"] = true));
      return { wit: bad, wpt: r.wpt, req: r.req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S4",
    name: "WPT signed with a different key",
    wantPermit: false,
    wantReason: "pop",
    prepare: (env) => {
      const r = happyInputs(env);
      const other = mustKey({ name: "S4" });
      const g = happyGrant(env);
      const badWpt = mintWPT(g.wit_svid, "GET", targetURI, now0, other);
      return { wit: g.wit_svid, wpt: badWpt, req: r.req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S5",
    name: "WPT aud != request target URI",
    wantPermit: false,
    wantReason: "aud mismatch",
    prepare: (env) => {
      const r = happyInputs(env);
      const req: Request = {
        method: "POST",
        target_uri: "https://rs.example.com/invoices",
        now: now0,
      };
      return { wit: r.wit, wpt: r.wpt, req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S6",
    name: "WPT expired (now > exp)",
    wantPermit: false,
    wantReason: "expired",
    prepare: (env) => {
      const r = happyInputs(env);
      env.ver.nowFn = () => now0 + 121; // WPT exp = now0+120
      const req: Request = { ...r.req, now: now0 + 121 };
      return { wit: r.wit, wpt: r.wpt, req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S7",
    name: "WPT replay",
    wantPermit: false,
    wantReason: "replay",
    prepare: (env) => {
      const r = happyInputs(env);
      const first: Decision = env.ver.verify(r.wit, r.wpt, r.req, r.opts);
      assert.equal(first.permit, true, `first verify should be PERMIT: ${first.reason}`);
      return { ...r, issueErr: "" };
    },
  },
  {
    id: "S8",
    name: "no WPT (bearer misuse)",
    wantPermit: false,
    wantReason: "pop required",
    prepare: (env) => {
      const r = happyInputs(env);
      env.ver.replay = new MemoryReplayStore();
      return { wit: r.wit, wpt: "", req: r.req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S9",
    name: "WIT carries aud (WIT-SVID MUST NOT)",
    wantPermit: false,
    wantReason: "aud-in-wit",
    prepare: (env) => {
      const r = happyInputs(env);
      const bad = reSignWIT(env, r.wit, (c) => (c["aud"] = targetURI));
      return { wit: bad, wpt: r.wpt, req: r.req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S10",
    name: "requested capability outside entitlement -> policy deny",
    wantPermit: false,
    wantReason: "policy:",
    prepare: (env) => {
      const r = happyInputs(env);
      const rc = capOf("mysql", "drop");
      const req: Request = { method: "POST", target_uri: targetURI, now: now0, requested_capability: rc };
      return { wit: r.wit, wpt: r.wpt, req, opts: r.opts, issueErr: "" };
    },
  },
  {
    id: "S11",
    name: "WPT alg != WIT cnf.jwk.alg",
    wantPermit: false,
    wantReason: "alg mismatch",
    prepare: (env) => {
      const r = happyInputs(env);
      const g = happyGrant(env);
      const valid = mintWPT(g.wit_svid, "GET", targetURI, now0, witKeyOf(g));
      const parts = valid.split(".");
      const payload = JSON.parse(Buffer.from(parts[1], "base64url").toString());
      const bad = signJWS({ typ: "wpt+jwt", alg: "RS256" }, payload, witKeyOf(g));
      const req: Request = { method: "GET", target_uri: targetURI, now: now0 };
      return { wit: g.wit_svid, wpt: bad, req, opts: r.opts, issueErr: "" };
    },
  },
];

for (const c of cases) {
  test(`${c.id} ${c.name}`, () => {
    const env = new Env();
    const run = c.prepare(env);
    if (run.issueErr !== "") {
      assert.equal(c.wantPermit, false, `expected issuance OK, got error ${run.issueErr}`);
      assert.ok(
        run.issueErr.includes(c.wantReason),
        `issue error "${run.issueErr}" missing "${c.wantReason}"`,
      );
      return;
    }
    const d = env.ver.verify(run.wit, run.wpt, run.req, run.opts);
    assert.equal(d.permit, c.wantPermit, `reason=${d.reason} checks=${JSON.stringify(d.checks)}`);
    if (!d.permit) {
      assert.ok(
        d.reason.includes(c.wantReason),
        `reason "${d.reason}" missing expected "${c.wantReason}"`,
      );
    }
  });
}