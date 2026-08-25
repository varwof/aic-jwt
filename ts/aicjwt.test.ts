// AIC-JWT WebCrypto conformance + OAuth-scenario tests.
// Run with: node --test ts/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  TYP_DA, TYP_OUTER, MODE_AUTHORIZED, MODE_REPRESENTATIVE,
  CONSTRAINT_SCHEME, ALLOWED_MODE_REPRESENTATIVE,
  b64uEncode, b64uDecode, signCompact, verifyCompact, parseCompact,
  signBytes, MAX_TOKEN_SIZE,
  keyHashOf, jwkThumbprint, spkiHash, matchPattern, matchCapabilities,
  paramsWithinGrant, evaluateConstraints, validate, validateDA,
  buildDPoP, verifyDPoP, stableStringify,
  type OuterClaims, type DAClaims, type PAClaims, type Capability,
  type VerifyOptions, type NonceStore, type Audience, type Decision,
} from "./aicjwt.ts";

const subtle = globalThis.crypto.subtle;

async function genECDSA(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
}

async function genRSA(): Promise<CryptoKeyPair> {
  return subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
}

async function genEd25519(): Promise<CryptoKeyPair | null> {
  try {
    return await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  } catch {
    return null; // older browsers / Node versions
  }
}

class MemNonceStore implements NonceStore {
  private m = new Set<string>();
  checkAndAdd(nonce: string): void {
    if (this.m.has(nonce)) throw new Error("reused nonce");
    this.m.add(nonce);
  }
}

interface Env {
  issuer: CryptoKeyPair;
  principal: CryptoKeyPair;
  agent: CryptoKeyPair;
  now: Date;
  pa: PAClaims;
}

async function newEnv(): Promise<Env> {
  const issuer = await genECDSA();
  const principal = await genECDSA();
  const agent = await genECDSA();
  const now = new Date(Math.floor(Date.now() / 1000) * 1000);
  const principalBinding = {
    realm: "corp.com",
    id: "zhangsan",
    key_hash: await keyHashOf(principal.publicKey, "sha-256"),
    hash_alg: "sha-256",
  };
  const pa: PAClaims = {
    ver: 1,
    principal: principalBinding,
    grants: [
      { scheme: "database", id: "query:*", params: { max_rows: 1000 } },
      { scheme: "database", id: "admin:reset", params: { window: "08:00-18:00" } },
    ],
    delegation_policy: { max_agents: 1, allowed_mode: ALLOWED_MODE_REPRESENTATIVE },
  };
  return { issuer, principal, agent, now, pa };
}

const CAPS = [{ scheme: "database", id: "query:SELECT", params: { max_rows: 100 } }] as Capability[];

async function buildDA(env: Env, mode: string, caps: Capability[], mut?: (d: DAClaims) => void): Promise<{ token: string; da: DAClaims }> {
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const da: DAClaims = {
    ver: 1,
    agent_id: "agent:db-analyst-01",
    principal: {
      realm: "corp.com",
      id: "zhangsan",
      key_hash: await keyHashOf(env.principal.publicKey, "sha-256"),
      hash_alg: "sha-256",
    },
    reason: { code: "DATA_ANALYSIS", desc: "scheduled analysis" },
    capabilities: caps,
    delegation_mode: mode,
    requested_lifetime: 3600,
    ts: Math.floor(env.now.getTime() / 1000),
    nonce: b64uEncode(nonce),
  };
  if (mut) mut(da);
  const token = await signCompact({ alg: "ES256", typ: TYP_DA, kid: "principal-1" }, da, env.principal.privateKey);
  return { token, da };
}

async function buildOuter(
  env: Env,
  daToken: string,
  da: DAClaims | undefined,
  mode: string,
  caps: Capability[],
  mut?: (o: OuterClaims) => void,
): Promise<string> {
  const jti = da ? da.nonce : "test-jti";
  const outer: OuterClaims = {
    iss: "https://as.example.com",
    sub: "agent:db-analyst-01",
    aud: "https://rs.example.com" as Audience,
    iat: Math.floor(env.now.getTime() / 1000),
    exp: Math.floor(env.now.getTime() / 1000) + 3600,
    jti,
    cnf: { jkt: await keyHashOf(env.agent.publicKey, "jkt") },
    aic: {
      ver: 1,
      principal: {
        realm: "corp.com",
        id: "zhangsan",
        key_hash: await keyHashOf(env.principal.publicKey, "sha-256"),
        hash_alg: "sha-256",
      },
      delegation_mode: mode,
      capabilities: caps,
    },
    da: daToken,
  };
  if (mut) mut(outer);
  return signCompact({ alg: "ES256", typ: TYP_OUTER, kid: "issuer-1" }, outer, env.issuer.privateKey);
}

function databasePlugins(): Record<string, (req: Capability) => void> {
  return {
    database: (req) => {
      if (req.id.startsWith("query:") || req.id.startsWith("admin:")) return;
      throw new Error(`database plugin denies ${req.id}`);
    },
    http: () => undefined,
  };
}

function defaultOpts(env: Env): VerifyOptions {
  return {
    now: env.now,
    expectedIssuer: "https://as.example.com",
    expectedAudience: ["https://rs.example.com"],
    issuerKeys: { "issuer-1": env.issuer.publicKey },
    principalJWKS: { "principal-1": env.principal.publicKey },
    requestCapability: { scheme: "database", id: "query:SELECT" },
    requestContext: { now: env.now, sourceIP: "10.1.2.3", concurrentCount: 1 },
    constraintStrict: false,
    capabilityPlugins: databasePlugins() as unknown as VerifyOptions["capabilityPlugins"],
    nonceStore: new MemNonceStore(),
    rejectDepthGT1: true,
    pa: env.pa,
  };
}

async function check(env: Env, tok: string, cap: Capability, overrides?: Partial<VerifyOptions>): Promise<Decision> {
  return validate(tok, { ...defaultOpts(env), requestCapability: cap, ...overrides });
}

// ---- unit: glob matching --------------------------------------------------

test("TS: glob matching precedence", () => {
  const cases: [string, string, boolean, number][] = [
    ["http:GET:/api/v1/users", "http:GET:/api/v1/users", true, 6],
    ["http:GET:/api/v1/users", "http:GET:/api/v1/orders", false, 0],
    ["http:GET:/api/v1/*", "http:GET:/api/v1/users", true, 5],
    ["http:GET:/api/v1/*", "http:GET:/api/v1/users/42", false, 0],
    ["http:GET:/api/v1/**", "http:GET:/api/v1/users/42", true, 4],
    ["http:*:/api/v1/*", "http:POST:/api/v1/users", true, 5],
    ["http:*", "http:GET:/api/v1/users", true, 1],
    ["http:*", "https:GET:/api", false, 0],
    ["database:query:*", "database:query:SELECT", true, 5],
    ["database:query:*", "database:admin:reset", false, 0],
    // 07-capability extensions: alternation and char class.
    ["http:{GET,POST}", "http:POST", true, 3],
    ["http:{GET,POST}", "http:DELETE", false, 0],
    ["http:[A-Z]", "http:G", true, 2],
    ["http:[A-Z]", "http:g", false, 0],
    ["http:user*", "http:username", true, 5],
    ["http:[A-Z]*:/api/*", "http:GET:/api/users", true, 5],
    ["http:{GET,POST}:/api/v1/*", "http:POST:/api/v1/users", true, 5],
  ];
  for (const [p, t, wantMatch, wantScore] of cases) {
    const r = matchPattern(p, t);
    assert.equal(r.matched, wantMatch, `pattern ${p} vs ${t}`);
    assert.equal(r.score, wantScore, `score ${p} vs ${t}`);
  }
  const allowed: Capability[] = [
    { scheme: "database", id: "query:*" },
    { scheme: "database", id: "query:SELECT" },
  ];
  assert.ok(matchCapabilities(allowed, { scheme: "database", id: "query:SELECT" }));
  assert.ok(matchCapabilities(allowed, { scheme: "database", id: "query:EXPLAIN" }));
});

// ---- unit: params / constraints / key hashes ------------------------------

test("TS: parameter intersection", () => {
  assert.ok(paramsWithinGrant({ max_rows: 1000 }, { max_rows: 100 }));
  assert.ok(!paramsWithinGrant({ max_rows: 1000 }, { max_rows: 5000 }));
  assert.ok(paramsWithinGrant({ regions: ["cn", "eu"] }, { regions: ["cn"] }));
});

test("TS: constraints", () => {
  const ctx = { now: new Date(), sourceIP: "10.1.2.3", concurrentCount: 1 };
  const cs: Capability[] = [
    { scheme: CONSTRAINT_SCHEME, id: "allowed-cidr", params: ["10.0.0.0/8"] },
    { scheme: CONSTRAINT_SCHEME, id: "time-window", params: { start: "00:00", end: "23:59" } },
    { scheme: CONSTRAINT_SCHEME, id: "max-concurrent", params: { max: 5 } },
  ];
  assert.deepEqual(evaluateConstraints(cs, ctx, false), []);
  assert.throws(() => evaluateConstraints(cs, { ...ctx, sourceIP: "192.168.1.1" }, false), /not in allowed/);
  assert.throws(() => evaluateConstraints(cs, { ...ctx, concurrentCount: 5 }, false), /max-concurrent/);
  const notes = evaluateConstraints(
    [{ scheme: CONSTRAINT_SCHEME, id: "future-type", params: {} }, ...cs],
    ctx,
    false,
  );
  assert.equal(notes.length, 1);
  assert.throws(() => evaluateConstraints([{ scheme: CONSTRAINT_SCHEME, id: "future-type", params: {} }], ctx, true), /unknown constraint/);
  assert.throws(() => evaluateConstraints([{ scheme: "evil", id: "allowed-cidr", params: [] }], ctx, false), /scheme/);
});

test("TS: key hashes", async () => {
  const env = await newEnv();
  const sh = await keyHashOf(env.principal.publicKey, "sha-256");
  assert.equal(sh.length, 43);
  const jkt = await jwkThumbprint(await subtle.exportKey("jwk", env.agent.publicKey));
  assert.equal(jkt.length, 43);
  const spki = await spkiHash(env.principal.publicKey, "sha-256");
  assert.equal(spki, sh);
});

// ---- negative pipeline ------------------------------------------------------

test("TS: negative validation cases", async () => {
  const env = await newEnv();
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const base = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS);

  await check(env, base, CAPS[0]); // baseline permit

  // tampered payload
  const { header, parts } = parseCompact(base);
  void header;
  const t1 = parts[0] + "." + b64uEncode(new TextEncoder().encode(JSON.stringify({ ...JSON.parse(new TextDecoder().decode(b64uDecode(parts[1]))), sub: "agent:evil" }))) + "." + parts[2];
  await assert.rejects(check(env, t1, CAPS[0]), /signature/);

  // expired (iat in the past, exp before now but after iat)
  const expired = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => {
    const s = Math.floor(env.now.getTime() / 1000);
    o.iat = s - 3600;
    o.exp = s - 60;
  });
  await assert.rejects(check(env, expired, CAPS[0]), /expired/);

  // lifetime exceeds requested
  const long = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => { o.exp = o.iat + 7200; });
  await assert.rejects(check(env, long, CAPS[0]), /requested_lifetime/);

  // alg=none
  const { parts: p2 } = parseCompact(base);
  const noneTok = b64uEncode(new TextEncoder().encode(JSON.stringify({ alg: "none", typ: TYP_OUTER, kid: "issuer-1" }))) + "." + p2[1] + ".";
  await assert.rejects(check(env, noneTok, CAPS[0]), /none/);

  // HS256 confusion
  const hsTok = b64uEncode(new TextEncoder().encode(JSON.stringify({ alg: "HS256", typ: TYP_OUTER, kid: "issuer-1" }))) + "." + p2[1] + ".c2ln";
  await assert.rejects(check(env, hsTok, CAPS[0]), /allowlist/);

  // key_hash mismatch: DA claims a different principal key
  const other = await genECDSA();
  const { token: badDaTok, da: badDa } = await buildDA(env, MODE_AUTHORIZED, CAPS, (d) => {
    d.principal.key_hash = "x".repeat(43);
  });
  void other;
  const badOuter = await buildOuter(env, badDaTok, badDa, MODE_AUTHORIZED, CAPS);
  await assert.rejects(check(env, badOuter, CAPS[0]), /key_hash/);

  // nonce reuse
  const store = new MemNonceStore();
  await check(env, base, CAPS[0], { nonceStore: store });
  await assert.rejects(check(env, base, CAPS[0], { nonceStore: store }), /reused nonce/);

  // inconsistent capabilities
  const inconsistent = await buildOuter(env, daTok, da, MODE_AUTHORIZED, [{ scheme: "database", id: "admin:reset" }]);
  await assert.rejects(check(env, inconsistent, CAPS[0]), /capabilities !=/);

  // unknown scheme fail-closed: the capability is allowed in the
  // token but no plugin is registered for the scheme.
  const mysteryCaps = [...CAPS, { scheme: "mystery", id: "do:thing" }];
  const { token: mDaTok, da: mDa } = await buildDA(env, MODE_AUTHORIZED, mysteryCaps);
  const mTok = await buildOuter(env, mDaTok, mDa, MODE_AUTHORIZED, mysteryCaps);
  await assert.rejects(check(env, mTok, { scheme: "mystery", id: "do:thing" }), /unknown capability scheme/);

  // representative without PA
  const { token: repDaTok, da: repDa } = await buildDA(env, MODE_REPRESENTATIVE, CAPS);
  const repTok = await buildOuter(env, repDaTok, repDa, MODE_REPRESENTATIVE, CAPS);
  await assert.rejects(check(env, repTok, CAPS[0], { pa: undefined }), /representative mode requires/);

  // missing cnf
  const noCnf = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => { o.cnf = undefined as never; });
  await assert.rejects(check(env, noCnf, CAPS[0]), /cnf required/);

  // audience confusion
  await assert.rejects(check(env, base, CAPS[0], { expectedAudience: ["https://rs-b.example.com"] }), /aud/);

  // malformed
  await assert.rejects(check(env, "not-a-jws", CAPS[0]), /malformed/);
});

// ---- OAuth scenarios ---------------------------------------------------------

test("TS: bearer access token - permit, deny, audit actor", async () => {
  const env = await newEnv();
  const { token: daTok } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const tok = await buildOuter(env, daTok, undefined as never, MODE_AUTHORIZED, CAPS, (o) => { o.da = daTok; });
  const dec = await check(env, tok, CAPS[0]);
  assert.equal(dec.actor, "agent:db-analyst-01");
  await assert.rejects(check(env, tok, { scheme: "database", id: "admin:reset" }), /not allowed/);
});

test("TS: representative audit actor + P_grants subset", async () => {
  const env = await newEnv();
  const { token: daTok } = await buildDA(env, MODE_REPRESENTATIVE, CAPS);
  const tok = await buildOuter(env, daTok, undefined as never, MODE_REPRESENTATIVE, CAPS, (o) => { o.da = daTok; });
  const dec = await check(env, tok, CAPS[0]);
  assert.equal(dec.actor, "zhangsan");
  // capability outside P_grants must fail
  const { token: daTok2 } = await buildDA(env, MODE_REPRESENTATIVE, [{ scheme: "database", id: "admin:purge" }]);
  const tok2 = await buildOuter(env, daTok2, undefined as never, MODE_REPRESENTATIVE, [{ scheme: "database", id: "admin:purge" }], (o) => { o.da = daTok2; });
  await assert.rejects(check(env, tok2, { scheme: "database", id: "admin:purge" }), /P_grants/);
});

test("TS: DPoP binding + replay + cnf", async () => {
  const env = await newEnv();
  const { token: daTok } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const tok = await buildOuter(env, daTok, undefined as never, MODE_AUTHORIZED, CAPS, (o) => { o.da = daTok; });
  const { proof } = await buildDPoP(env.agent, "ES256", "POST", "https://rs.example.com/api/db", tok, env.now);
  const pub = await verifyDPoP(proof, tok, "POST", "https://rs.example.com/api/db", env.now);
  const dec = await check(env, tok, CAPS[0], { presenterKey: pub });
  assert.ok(dec.permit);
  // wrong htu
  const { proof: proof2 } = await buildDPoP(env.agent, "ES256", "POST", "https://rs.example.com/evil", tok, env.now);
  await assert.rejects(verifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db", env.now), /htu/);
  // replay
  const replay = new MemNonceStore();
  await verifyDPoP(proof, tok, "POST", "https://rs.example.com/api/db", env.now, replay);
  await assert.rejects(verifyDPoP(proof, tok, "POST", "https://rs.example.com/api/db", env.now, replay), /reused nonce/);
});

test("TS: status list revocation", async () => {
  const env = await newEnv();
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const revoked = new Set<string>();
  const tok = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => {
    o.status = { idx: 1, uri: "https://as.example.com/status/1" };
  });
  await check(env, tok, CAPS[0], { statusChecker: (r) => { if (revoked.has(r.uri)) throw new Error("revoked"); } });
  revoked.add("https://as.example.com/status/1");
  await assert.rejects(check(env, tok, CAPS[0], { statusChecker: (r) => { if (revoked.has(r.uri)) throw new Error("revoked"); } }), /revoked/);
});

test("TS: constraints enforcement end-to-end", async () => {
  const env = await newEnv();
  const constraints = [
    { scheme: CONSTRAINT_SCHEME, id: "allowed-cidr", params: ["10.0.0.0/8"] },
    { scheme: CONSTRAINT_SCHEME, id: "time-window", params: { start: "00:00", end: "23:59" } },
    { scheme: CONSTRAINT_SCHEME, id: "max-concurrent", params: { max: 5 } },
  ];
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS, (d) => { d.constraints = constraints; });
  const tok = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => { o.aic.constraints = constraints; });
  await check(env, tok, CAPS[0]);
  await assert.rejects(check(env, tok, CAPS[0], { requestContext: { now: env.now, sourceIP: "192.168.1.1", concurrentCount: 1 } }), /not in allowed/);
  await assert.rejects(check(env, tok, CAPS[0], { requestContext: { now: env.now, sourceIP: "10.1.2.3", concurrentCount: 5 } }), /max-concurrent/);
});

test("TS: multi-level depth check", async () => {
  const env = await newEnv();
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const tok = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS, (o) => {
    o.aic.chain_depth = 2;
    o.aic.max_depth = 1;
  });
  await assert.rejects(check(env, tok, CAPS[0]), /max_depth/);
});

test("TS: EdDSA algorithm (feature-detected)", async () => {
  const kp = await genEd25519();
  if (!kp) {
    console.log("  (skipped: Ed25519 WebCrypto not available in this runtime)");
    return;
  }
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const da: DAClaims = {
    ver: 1,
    agent_id: "agent:ed",
    principal: { realm: "corp.com", id: "zhangsan", key_hash: "x".repeat(43), hash_alg: "jkt" },
    reason: { code: "TEST", desc: "eddsa" },
    capabilities: [{ scheme: "http", id: "GET:/api/v1/*" }],
    delegation_mode: MODE_AUTHORIZED,
    requested_lifetime: 3600,
    ts: Math.floor(Date.now() / 1000),
    nonce: b64uEncode(nonce),
  };
  const daTok = await signCompact({ alg: "EdDSA", typ: TYP_DA, kid: "ed-1" }, da, kp.privateKey);
  await verifyCompact(daTok, "EdDSA", kp.publicKey);
  assert.ok(daTok.split(".").length === 3);
  // key hash: jkt binding of an Ed25519 key
  const jkt = await keyHashOf(kp.publicKey, "jkt");
  assert.equal(jkt.length, 43);
  // SPKI hash also works for Ed25519
  const spki = await spkiHash(kp.publicKey, "sha-256");
  assert.equal(spki.length, 43);
});

test("TS: RSA algorithms RS256 and PS256", async () => {
  const env = await newEnv();
  const rsaPkcs1 = await genRSA();
  const rsaPss = await subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );
  const rsaPss384 = await subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-384" },
    true,
    ["sign", "verify"],
  );
  const rsaPss512 = await subtle.generateKey(
    { name: "RSA-PSS", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-512" },
    true,
    ["sign", "verify"],
  );
  const nonce = new Uint8Array(32);
  globalThis.crypto.getRandomValues(nonce);
  const da: DAClaims = {
    ver: 1,
    agent_id: "agent:rsa",
    principal: { realm: "corp.com", id: "zhangsan", key_hash: await keyHashOf(env.principal.publicKey, "sha-256"), hash_alg: "sha-256" },
    reason: { code: "TEST", desc: "rsa" },
    capabilities: CAPS,
    delegation_mode: MODE_AUTHORIZED,
    requested_lifetime: 3600,
    ts: Math.floor(Date.now() / 1000),
    nonce: b64uEncode(nonce),
  };
  const daTok1 = await signCompact({ alg: "RS256", typ: TYP_DA, kid: "rsa-1" }, da, rsaPkcs1.privateKey);
  await verifyCompact(daTok1, "RS256", rsaPkcs1.publicKey);
  const daTok2 = await signCompact({ alg: "PS256", typ: TYP_DA, kid: "rsa-pss-1" }, da, rsaPss.privateKey);
  await verifyCompact(daTok2, "PS256", rsaPss.publicKey);
  const daTok3 = await signCompact({ alg: "PS384", typ: TYP_DA, kid: "rsa-pss-384" }, da, rsaPss384.privateKey);
  await verifyCompact(daTok3, "PS384", rsaPss384.publicKey);
  const daTok4 = await signCompact({ alg: "PS512", typ: TYP_DA, kid: "rsa-pss-512" }, da, rsaPss512.privateKey);
  await verifyCompact(daTok4, "PS512", rsaPss512.publicKey);
});

test("TS: stableStringify is order-independent", () => {
  assert.equal(
    stableStringify({ b: 1, a: [2, { d: 3, c: 4 }] }),
    stableStringify({ a: [2, { c: 4, d: 3 }], b: 1 }),
  );
});

test("TS: DA standalone validation", async () => {
  const env = await newEnv();
  const { token: daTok } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const parsed = await validateDA(daTok, { now: env.now, principalJWKS: { "principal-1": env.principal.publicKey }, nonceStore: new MemNonceStore() });
  assert.equal(parsed.agent_id, "agent:db-analyst-01");
});

function utf8e(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function b64uDecodeStr(str: string): string {
  return new TextDecoder().decode(b64uDecode(str));
}

test("TS: duplicate JSON keys rejected (header and payload)", async () => {
  const env = await newEnv();
  const opts = defaultOpts(env);
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const base = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS);
  const parts = base.split(".");
  const payloadStr = b64uDecodeStr(parts[1]);

  // header with duplicate alg (RFC 8725 hardening)
  const dupHeader = '{"alg":"none","alg":"ES256","typ":"aic+jwt","kid":"issuer-1"}';
  const input = b64uEncode(utf8e(dupHeader)) + "." + b64uEncode(utf8e(payloadStr));
  const sig = await signBytes("ES256", utf8e(input), env.issuer.privateKey);
  await assert.rejects(
    () => validate(input + "." + b64uEncode(sig), opts),
    /duplicate JSON member names/,
  );

  // payload with duplicate sub
  const idx = payloadStr.indexOf('"sub":');
  assert.ok(idx >= 0);
  const dupPayload = payloadStr.slice(0, idx) + '"sub":"agent:evil",' + payloadStr.slice(idx);
  const input2 = b64uEncode(utf8e(parts[0])) + "." + b64uEncode(utf8e(dupPayload));
  const sig2 = await signBytes("ES256", utf8e(input2), env.issuer.privateKey);
  await assert.rejects(
    () => validate(input2 + "." + b64uEncode(sig2), opts),
    /duplicate JSON member names/,
  );
});

test("TS: oversized token rejected", async () => {
  const env = await newEnv();
  const opts = defaultOpts(env);
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, CAPS);
  const base = await buildOuter(env, daTok, da, MODE_AUTHORIZED, CAPS);
  const parts = base.split(".");
  const payload = JSON.parse(b64uDecodeStr(parts[1])) as Record<string, unknown>;
  payload.padding = "x".repeat(MAX_TOKEN_SIZE + 1024);
  const big = JSON.stringify(payload);
  const input = b64uEncode(utf8e(parts[0])) + "." + b64uEncode(utf8e(big));
  const sig = await signBytes("ES256", utf8e(input), env.issuer.privateKey);
  const bigTok = input + "." + b64uEncode(sig);
  assert.ok(bigTok.length > MAX_TOKEN_SIZE);
  await assert.rejects(() => validate(bigTok, opts), /exceeds max/);
});

test("TS: oversized capability params rejected", async () => {
  const env = await newEnv();
  const opts = defaultOpts(env);
  const bigParams = { note: "x".repeat(600) };
  const badCaps = [{ scheme: "database", id: "query:SELECT", params: bigParams }] as Capability[];
  const { token: daTok, da } = await buildDA(env, MODE_AUTHORIZED, badCaps);
  const tok = await buildOuter(env, daTok, da, MODE_AUTHORIZED, badCaps);
  await assert.rejects(() => validate(tok, opts), /params exceed/);
});
