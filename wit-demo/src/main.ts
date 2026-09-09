// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// UI 胶水 + 场景驱动：可点击步骤 + 场景选择器 + 逐项验证报告。
// 与 wit-wpt-interop（Go/TS）共用同一套检查语义（此目录内复制实现）。

import { Issuer, signArtifact } from "./lib/issuer.ts";
import { Verifier, mintWPT, witKeyOf } from "./lib/verifier.ts";
import { generateKey } from "./lib/jwk.ts";
import { b64e, keyHashOf } from "./lib/jose.ts";
import { capabilityCoveredIn } from "./lib/subset.ts";
import type {
  Capability,
  DA,
  PA,
  Principal,
  Request,
  WITGrant,
  Decision,
} from "./lib/types.ts";
import type { VerifyOpts } from "./lib/verifier.ts";

interface StepGroup {
  title: string;
  entries: string[];
}

interface ScenarioResult {
  steps: StepGroup[];
  decision?: Decision;
  issueError?: string;
}

const now0 = 1_700_000_000;
const targetURI = "https://rs.example.com/orders";

// ---------------------------------------------------------------------------
// 场景输入构造（与 wit-demo/test/demo.test.ts 相同 helper）
// ---------------------------------------------------------------------------

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

interface Env {
  principal: CryptoKeyPair;
  issuer: CryptoKeyPair;
  iss: Issuer;
  ver: Verifier;
}

async function newEnv(): Promise<Env> {
  const principal = await generateKey();
  const issuer = await generateKey();
  const iss = new Issuer("example.org", issuer.privateKey, "wk-01");
  const ver = new Verifier({ "wk-01": issuer.publicKey }, () => now0);
  return { principal, issuer, iss, ver };
}

async function happyGrant(env: Env): Promise<{ grant: WITGrant; steps: StepGroup[] }> {
  const steps: StepGroup[] = [];
  steps.push({ title: "1 · Principal (human) signs PA + DA", entries: [] });
  const p = await principalOf(env.principal, "realm.example", "alice");
  const grants = [await capOf("mysql", "query", { max_rows: 1000 })];
  const caps = [await capOf("mysql", "query", { max_rows: 500 })];
  steps[0].entries.push(
    `principal ${p.realm}/${p.id} key_hash=${p.key_hash.slice(0, 12)}…`,
    `P_grants: mysql:query max_rows=1000`,
  );
  const da = await makeDA(p, "agent-1", caps, "representative", now0);
  const pa = await makePA(p, grants);

  steps.push({
    title: "2 · Delegation request (agent_id, C_agent, constraints, lifetime, nonce)",
    entries: [
      `agent_id=agent-1  C_agent: mysql:query max_rows=500  lifetime=3600s`,
    ],
  });

  const daTok = await signArtifact("da+jwt", da, env.principal.privateKey);
  const paTok = await signArtifact("pa+jwt", pa, env.principal.privateKey);
  steps[0].entries.push("DA signed (compact JWS)", "PA signed (compact JWS)");

  steps.push({ title: "3 · AIC-aware issuance service", entries: [] });
  const grant = await env.iss.issue(daTok, paTok, "agent-1", now0);
  steps[2].entries.push(
    "DA signature + principal.key_hash verified",
    "agent_id matches spiffe://example.org/agent/agent-1",
    "C_agent ⊆ P_grants (max_rows 500 ≤ 1000)",
    `issued WIT-SVID spiffe://example.org/agent/agent-1, kid=wk-01, cnf (new P-256 keypair)`,
  );
  return { grant, steps };
}

function entitlementPolicy() {
  return (_ent: Capability[], c: Capability): void => {
    const { ok } = capabilityCoveredIn(c, _ent);
    if (!ok) {
      throw new Error("requested capability not in entitlement");
    }
  };
}

async function happyInputs(env: Env, steps: StepGroup[], grant: WITGrant) {
  steps.push({
    title: "4 · Agent builds HTTP request + WPT (PoP)",
    entries: [],
  });
  const witKey = await witKeyOf(grant);
  const wpt = await mintWPT(grant.wit_svid, "GET", targetURI, now0, witKey);
  steps[3].entries.push(
    `GET ${targetURI}`,
    "WPT signed with WIT cnf.jwk private key (wth = SHA-256(WIT))",
  );
  const rc = await capOf("mysql", "query", { max_rows: 500 });
  const req: Request = {
    method: "GET",
    target_uri: targetURI,
    now: now0,
    requested_capability: rc,
  };
  const opts: VerifyOpts = { entitlement: grant.entitlement, policy: entitlementPolicy() };
  return { wit: grant.wit_svid, wpt, req, opts };
}

// ---------------------------------------------------------------------------
// 场景
// ---------------------------------------------------------------------------

async function runScenario(id: string): Promise<ScenarioResult> {
  const env = await newEnv();
  const { grant, steps } = await happyGrant(env);

  switch (id) {
    case "S1": {
      const r = await happyInputs(env, steps, grant);
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const d = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
      steps[4].entries.push("all checks pass");
      return { steps, decision: d };
    }
    case "S2": {
      const p = await principalOf(env.principal, "realm.example", "alice");
      const grants = [await capOf("mysql", "query", { max_rows: 1000 })];
      const caps = [await capOf("mysql", "query", { max_rows: 5000 })];
      const da = await makeDA(p, "agent-1", caps, "representative", now0);
      const pa = await makePA(p, grants);
      const daTok = await signArtifact("da+jwt", da, env.principal.privateKey);
      const paTok = await signArtifact("pa+jwt", pa, env.principal.privateKey);
      steps.push({ title: "3 · AIC-aware issuance service", entries: [] });
      let errMsg = "";
      try {
        await env.iss.issue(daTok, paTok, "agent-1", now0);
      } catch (e) {
        errMsg = (e as Error).message;
      }
      steps[2].entries.push(`DA valid, but C_agent 5000 > P_grants 1000`);
      return { steps, issueError: errMsg || "expected issuance to fail" };
    }
    case "S4": {
      const r = await happyInputs(env, steps, grant);
      const other = await generateKey();
      steps[3].entries.push("(attacker signs WPT with a DIFFERENT key)");
      const badWpt = await mintWPT(grant.wit_svid, "GET", targetURI, now0, other.privateKey);
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const d = await env.ver.verify(r.wit, badWpt, r.req, r.opts);
      return { steps, decision: d };
    }
    case "S5": {
      const r = await happyInputs(env, steps, grant);
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const req: Request = { method: "POST", target_uri: "https://rs.example.com/invoices", now: now0 };
      steps[4].entries.push(`request targets ${req.target_uri}, but WPT aud=${r.req.target_uri}`);
      const d = await env.ver.verify(r.wit, r.wpt, req, r.opts);
      return { steps, decision: d };
    }
    case "S7": {
      const r = await happyInputs(env, steps, grant);
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const first = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
      steps[4].entries.push(`1st attempt → ${first.permit ? "PERMIT" : "DENY"}`);
      const second = await env.ver.verify(r.wit, r.wpt, r.req, r.opts);
      steps[4].entries.push(`2nd attempt (same WPT) → ${second.permit ? "PERMIT" : "DENY: " + second.reason}`);
      return { steps, decision: second };
    }
    case "S8": {
      const r = await happyInputs(env, steps, grant);
      steps[3].entries.push("(WPT omitted — bearer-style use of WIT)");
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const d = await env.ver.verify(r.wit, "", r.req, r.opts);
      return { steps, decision: d };
    }
    case "S10": {
      const r = await happyInputs(env, steps, grant);
      steps[3].entries.push("agent asks for mysql:drop (outside entitlement)");
      const rc = await capOf("mysql", "drop");
      const req: Request = { method: "POST", target_uri: targetURI, now: now0, requested_capability: rc };
      steps.push({ title: "5 · Resource server verification", entries: [] });
      const d = await env.ver.verify(r.wit, r.wpt, req, r.opts);
      return { steps, decision: d };
    }
    default:
      throw new Error("unknown scenario");
  }
}

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------

const app = document.getElementById("app");
if (!app) {
  throw new Error("missing #app container");
}

const scenarios: Array<[string, string]> = [
  ["S1", "Happy path: valid DA → WIT-SVID → WPT PoP → PERMIT"],
  ["S2", "Issuance denied: C_agent exceeds P_grants (subset)"],
  ["S4", "DENY: WPT signed with a different key (PoP)"],
  ["S5", "DENY: WPT aud ≠ request target URI"],
  ["S7", "DENY: WPT replay on second attempt"],
  ["S8", "DENY: no WPT (bearer misuse)"],
  ["S10", "DENY: requested capability outside entitlement (policy:)"],
];

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (cls) {
    node.className = cls;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
}

function renderSteps(container: HTMLElement, steps: StepGroup[]) {
  container.textContent = "";
  for (const g of steps) {
    const card = el("div", "card");
    card.appendChild(el("h2", undefined, g.title));
    for (const e of g.entries) {
      const line = el("div", "log");
      line.appendChild(el("span", "tag", "›"));
      line.appendChild(el("span", undefined, e));
      card.appendChild(line);
    }
    container.appendChild(card);
  }
}

function renderChecks(container: HTMLElement, decision: Decision) {
  const card = el("div", "card");
  card.appendChild(el("h2", undefined, "Resource server — verification report"));
  const verdict = el("div", decision.permit ? "verdict pill perm" : "verdict pill deny", decision.permit ? "PERMIT" : "DENY");
  card.appendChild(verdict);
  const reason = el("div", "muted", `reason: ${decision.reason}`);
  card.appendChild(reason);

  const table = el("table");
  const thead = el("thead");
  const hr = el("tr");
  for (const h of ["check", "result", "detail"]) {
    hr.appendChild(el("th", undefined, h));
  }
  thead.appendChild(hr);
  table.appendChild(thead);
  const tbody = el("tbody");
  for (const c of decision.checks) {
    const tr = el("tr");
    tr.appendChild(el("td", undefined, c.step));
    const res = el("td", c.ok ? "ok" : "no", c.ok ? "PASS" : "FAIL");
    tr.appendChild(res);
    tr.appendChild(el("td", undefined, c.detail));
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  card.appendChild(table);
  container.appendChild(card);
}

function renderNotes() {
  const note = el("div", "card");
  note.appendChild(el("h2", undefined, "What just happened"));
  note.appendChild(el("div", "muted", "Step 3 is the issuance-control hook: AIC DA/PA are validated BEFORE the WIT-SVID is minted. The WIT carries identity + cnf only; the entitlement recorded at issuance drives step 8 of the verification pipeline."));
  return note;
}

const appEl = app;

const controls = el("div", "card controls");
const select = el("select");
for (const [id, label] of scenarios) {
  const opt = el("option");
  opt.value = id;
  opt.textContent = label;
  select.appendChild(opt);
}
const runBtn = el("button", undefined, "Run scenario");
controls.appendChild(select);
controls.appendChild(runBtn);

const stepsHost = el("div", "steps");
const reportHost = el("div");

appEl.appendChild(controls);
appEl.appendChild(stepsHost);
appEl.appendChild(reportHost);
appEl.appendChild(renderNotes());

async function run() {
  runBtn.disabled = true;
  runBtn.textContent = "running…";
  stepsHost.textContent = "";
  reportHost.textContent = "";
  const id = select.value;
  try {
    const result = await runScenario(id);
    renderSteps(stepsHost, result.steps);
    if (result.issueError) {
      const card = el("div", "card");
      card.appendChild(el("h2", undefined, "Issuance result"));
      const v = el("div", "verdict pill deny", "DENY");
      card.appendChild(v);
      card.appendChild(el("div", "err", `reason: ${result.issueError}`));
      reportHost.appendChild(card);
    } else if (result.decision) {
      renderChecks(reportHost, result.decision);
    }
  } catch (e) {
    const card = el("div", "card");
    card.appendChild(el("h2", undefined, "Unexpected error"));
    card.appendChild(el("div", "err", (e as Error).message));
    reportHost.appendChild(card);
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run scenario";
  }
}

runBtn.addEventListener("click", run);
void run();