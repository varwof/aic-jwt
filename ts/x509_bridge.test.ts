// X.509 -> AIC-JWT bridge conformance tests (ts/x509_bridge.ts).
// Run with: node --test ts/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  validate, validateDA, signCompact, keyHashOf, b64uDecode, b64uEncode,
  MODE_AUTHORIZED, MODE_REPRESENTATIVE, TYP_DA, TYP_OUTER,
  type OuterClaims, type DAClaims, type Capability, type VerifyOptions,
  type NonceStore, type Decision,
} from "./aicjwt.ts";
import {
  parseAIC, mapToClaims, encodeTBS, encodeAIC, verifyDelegation,
  buildAICCertificate, findAIC,
  type X509AIC, type X509Capability,
} from "./x509_bridge.ts";
import {
  OID_AIC, OID_SIG_ECDSA_SHA256, oidToString, certExtensions,
} from "./asn1.ts";

const subtle = globalThis.crypto.subtle;

async function genECDSA(): Promise<CryptoKeyPair> {
  return subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
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
}

async function newEnv(): Promise<Env> {
  return {
    issuer: await genECDSA(),
    principal: await genECDSA(),
    agent: await genECDSA(),
    now: new Date(Math.floor(Date.now() / 1000) * 1000),
  };
}

const CAPS: X509Capability[] = [
  { scheme_id: "database", capability_id: "query:*" },
  { scheme_id: "http", capability_id: "GET:/api/v1/*" },
];

function newNonce(): Uint8Array {
  const n = new Uint8Array(32);
  globalThis.crypto.getRandomValues(n);
  return n;
}

async function buildSignedAIC(env: Env, mode: number, caps: X509Capability[]): Promise<{ aic: X509AIC; extValue: Uint8Array; tbs: Uint8Array }> {
  const keyHashBytes = b64uDecode(await keyHashOf(env.principal.publicKey, "sha-256"));
  const ts = env.now;
  const nonce = newNonce();

  const unsigned: X509AIC = {
    version: 1,
    agentId: "agent:db-analyst-01",
    principalUid: { realm: "corp.com", identifier: "zhangsan", keyHash: keyHashBytes, hashAlgo: null },
    capabilities: caps,
    delegationMode: mode,
    authorizationConstraints: [],
    authorization: {
      reasonCode: "DATA_ANALYSIS",
      reasonDesc: "scheduled analysis",
      requestedLifetime: 3600,
      timestamp: ts,
      nonce,
      signatureAlgorithm: null, // filled after signing
      signatureValue: new Uint8Array(0),
    },
    extensions: [],
  };

  const tbs = encodeTBS(unsigned);
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, env.principal.privateKey, tbs));

  const aic: X509AIC = {
    ...unsigned,
    authorization: {
      ...unsigned.authorization,
      signatureAlgorithm: OID_SIG_ECDSA_SHA256,
      signatureValue: sig,
    },
  };
  return { aic, extValue: encodeAIC(aic), tbs };
}

function databasePlugin(req: Capability): void {
  if (req.id.startsWith("query:") || req.id.startsWith("admin:")) return;
  throw new Error(`database plugin denies ${req.id}`);
}

function defaultOpts(env: Env, principal: CryptoKeyPair, pa?: import("./aicjwt.ts").PAClaims): VerifyOptions {
  return {
    now: env.now,
    expectedIssuer: "https://as.example.com",
    expectedAudience: ["https://rs.example.com"],
    issuerKeys: { "issuer-1": env.issuer.publicKey },
    principalJWKS: { "principal-1": principal.publicKey },
    requestCapability: { scheme: "database", id: "query:SELECT" },
    requestContext: { now: env.now, sourceIP: "10.1.2.3", concurrentCount: 1 },
    constraintStrict: false,
    capabilityPlugins: { database: databasePlugin },
    nonceStore: new MemNonceStore(),
    rejectDepthGT1: true,
    pa,
  };
}

async function check(env: Env, principal: CryptoKeyPair, tok: string, cap: Capability, pa?: import("./aicjwt.ts").PAClaims): Promise<Decision> {
  return validate(tok, { ...defaultOpts(env, principal, pa), requestCapability: cap });
}

async function makePA(env: Env, principal: CryptoKeyPair): Promise<import("./aicjwt.ts").PAClaims> {
  return {
    ver: 1,
    principal: {
      realm: "corp.com",
      id: "zhangsan",
      key_hash: await keyHashOf(principal.publicKey, "sha-256"),
      hash_alg: "sha-256",
    },
    grants: [
      { scheme: "database", id: "query:*", params: { max_rows: 1000 } },
      { scheme: "database", id: "admin:reset", params: { window: "08:00-18:00" } },
    ],
    delegation_policy: { max_agents: 1, allowed_mode: "representative_allowed" as const },
  };
}

async function signDA(env: Env, principal: CryptoKeyPair, da: DAClaims): Promise<string> {
  return signCompact({ alg: "ES256", typ: TYP_DA, kid: "principal-1" }, da, principal.privateKey);
}

test("TS x509 bridge: parseAIC + mapToClaims mapping (authorized + representative)", async () => {
  for (const { mode, jsonMode } of [
    { mode: 0, jsonMode: MODE_AUTHORIZED },
    { mode: 1, jsonMode: MODE_REPRESENTATIVE },
  ]) {
    const env = await newEnv();
    const { aic, extValue } = await buildSignedAIC(env, mode, CAPS);

    const parsed = parseAIC(extValue);
    assert.equal(parsed.agentId, "agent:db-analyst-01");
    assert.deepEqual(parsed.principalUid.keyHash, aic.principalUid.keyHash);

    const { da, outer } = await mapToClaims(parsed, { daAudience: "https://as.example.com" });

    assert.equal(outer.sub, "agent:db-analyst-01");
    assert.equal(da.agent_id, "agent:db-analyst-01");
    assert.equal(da.delegation_mode, jsonMode);
    assert.equal(outer.aic.delegation_mode, jsonMode);
    assert.equal(da.principal.key_hash, await keyHashOf(env.principal.publicKey, "sha-256"));
    assert.equal(da.ver, 2);
    assert.equal(da.iss, "corp.com:zhangsan");
    assert.equal(da.nonce, b64uEncode(aic.authorization.nonce));
    assert.equal(da.jti, da.nonce);
    assert.equal(da.exp, Math.floor(env.now.getTime() / 1000) + 3600);
    assert.equal(da.capabilities.length, 2);

    if (jsonMode === MODE_AUTHORIZED) {
      assert.equal(da.sub, da.agent_id);
    } else {
      assert.equal(da.sub, "corp.com:zhangsan");
    }
  }
});

test("TS x509 bridge: verifyDelegation over reconstructed TBS", async () => {
  const env = await newEnv();
  const { aic, tbs } = await buildSignedAIC(env, 0, CAPS);

  const principalKey = await subtle.importKey(
    "spki",
    await subtle.exportKey("spki", env.principal.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  await assert.doesNotReject(() => verifyDelegation(aic, principalKey));

  // Tampering the agent id used to rebuild the TBS must break verification.
  const bad = { ...aic, agentId: "agent:attacker" };
  await assert.rejects(() => verifyDelegation(bad, principalKey), /invalid/);

  // A different key must fail.
  const otherKey = await subtle.importKey(
    "spki",
    await subtle.exportKey("spki", env.agent.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  await assert.rejects(() => verifyDelegation(aic, otherKey), /invalid/);
  assert.ok(tbs);
});

test("TS x509 bridge: end-to-end converted DA -> validateDA -> RS decision", async () => {
  const env = await newEnv();
  const { aic, extValue } = await buildSignedAIC(env, 0, CAPS);
  const parsed = parseAIC(extValue);
  const { da } = await mapToClaims(parsed, { daAudience: "https://as.example.com" });

  // Master AIC signature over the TBS still verifies (authenticity).
  const principalKey = await subtle.importKey(
    "spki",
    await subtle.exportKey("spki", env.principal.publicKey),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
  await assert.doesNotReject(() => verifyDelegation(parsed, principalKey));

  // Converted DA claims, signed by the principal as a JWT (Mode B).
  const daToken = await signDA(env, env.principal, da);
  await assert.doesNotReject(() => validateDA(daToken, {
    now: env.now,
    issuerKeys: {},
    principalJWKS: { "principal-1": env.principal.publicKey },
  }));

  // Outer token issued from the converted DA, then RS decision.
  const outer: OuterClaims = {
    iss: "https://as.example.com",
    sub: "agent:db-analyst-01",
    aud: "https://rs.example.com",
    iat: Math.floor(env.now.getTime() / 1000),
    exp: Math.floor(env.now.getTime() / 1000) + 3600,
    jti: da.nonce,
    cnf: { jkt: await keyHashOf(env.agent.publicKey, "jkt") },
    aic: {
      ver: 1,
      principal: da.principal,
      delegation_mode: MODE_AUTHORIZED,
      capabilities: CAPS.map((c) => ({ scheme: c.scheme_id, id: c.capability_id })),
    },
    da: daToken,
  };
  const tok = await signCompact({ alg: "ES256", typ: TYP_OUTER, kid: "issuer-1" }, outer, env.issuer.privateKey);
  const dec = await check(env, env.principal, tok, { scheme: "database", id: "query:SELECT" });
  assert.ok(dec.permit);
});

test("TS x509 bridge: certificate extension extraction + findAIC round-trip", async () => {
  const env = await newEnv();
  const { aic } = await buildSignedAIC(env, 0, CAPS);

  const spki = await subtle.exportKey("spki", env.agent.publicKey);
  const certDER = buildAICCertificate(aic, new Uint8Array(spki));

  const exts = certExtensions(certDER);
  assert.ok(exts.has(oidToString(OID_AIC)));

  const found = findAIC(certDER);
  assert.ok(found);
  assert.equal(found.agentId, "agent:db-analyst-01");
  assert.equal(found.capabilities.length, 2);
});
