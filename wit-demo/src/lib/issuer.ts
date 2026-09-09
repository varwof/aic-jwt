// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 浏览器版 AIC-aware 发放服务：签发前校验 DA/PA。语义与 Go/TS harness 一致，
// 但全部实现为 async（WebCrypto）。

import { signJWS, verifyJWS, parseHeader, b64d, keyHashOf } from "./jose.ts";
import { jwkOfPub, pubOfJwk, generateKey } from "./jwk.ts";
import { capabilitiesCovered, validateConstraints } from "./subset.ts";
import type { DA, PA, WITGrant, Principal, Capability } from "./types.ts";
import type { ECJWK } from "./jwk.ts";

export class Issuer {
  trustDomain: string;
  signingKey: CryptoKey;
  signingKid: string;

  constructor(trustDomain: string, key: CryptoKey, kid: string) {
    this.trustDomain = trustDomain;
    this.signingKey = key;
    this.signingKid = kid;
  }

  async issue(
    da: string,
    paOpt: string,
    agentID: string,
    now: number,
  ): Promise<WITGrant> {
    const daRes = await parseArtifact(da, "da+jwt");
    const d = daRes.payload as DA;
    if (d.ver !== 1) {
      throw new Error(`DA: unsupported ver ${d.ver}`);
    }
    // 1. 校验 principal.key_hash 与签名公钥一致
    await checkKeyHash(daRes.pub, d.principal);
    if (agentID === "") {
      throw new Error("DA: agentID is empty");
    }
    if (d.agent_id !== agentID) {
      throw new Error(
        `DA: agent_id ${d.agent_id} != requested identity path ${agentID}`,
      );
    }
    if (/\s/.test(agentID)) {
      throw new Error(`DA: agent_id ${agentID} has invalid characters`);
    }
    if (d.requested_lifetime < 1 || d.requested_lifetime > 86400) {
      throw new Error(
        `DA: requested_lifetime ${d.requested_lifetime} out of range [1,86400]`,
      );
    }
    if (b64d(d.nonce).length !== 32) {
      throw new Error("DA: nonce must be 32 bytes base64url");
    }
    if (d.delegation_mode !== "authorized" && d.delegation_mode !== "representative") {
      throw new Error(`DA: unsupported delegation_mode ${d.delegation_mode}`);
    }
    validateConstraints(d.constraints);

    let grants: Capability[];
    if (d.delegation_mode === "representative") {
      // 2. representative 必须带 PA，且与 DA 同一 principal
      if (paOpt === "") {
        throw new Error("representative DA requires a PA");
      }
      const paRes = await parseArtifact(paOpt, "pa+jwt");
      const p = paRes.payload as PA;
      if (p.ver !== 1) {
        throw new Error(`PA: unsupported ver ${p.ver}`);
      }
      if (
        p.principal.key_hash !== d.principal.key_hash ||
        p.principal.hash_alg !== d.principal.hash_alg
      ) {
        throw new Error("PA principal does not match DA principal");
      }
      validateConstraints(p.constraints);
      // 3. C_agent ⊆ P_grants
      const { ok, detail } = capabilitiesCovered(d.capabilities, p.grants);
      if (!ok) {
        throw new Error(`issuance denied: ${detail}`);
      }
      grants = p.grants;
    } else {
      // authorized：DA 即授权快照
      grants = d.capabilities;
      if (paOpt !== "") {
        throw new Error("authorized DA must not carry a PA");
      }
    }

    // 4. 生成 WIT 密钥对（模拟 wit_svid_key，issuance-time 映射）
    const witKey = await generateKey();
    const spiffeId = `spiffe://${this.trustDomain}/agent/${agentID}`;
    const exp = now + d.requested_lifetime;
    const witClaims = {
      iss: spiffeId,
      sub: spiffeId,
      iat: now,
      exp,
      cnf: {
        jwk: await jwkOfPub(witKey.publicKey),
        alg: "ES256",
      },
    };
    const witHeader = {
      typ: "wit+jwt",
      alg: "ES256",
      kid: this.signingKid,
    };
    const token = await signJWS(witHeader, witClaims, this.signingKey);

    return {
      spiffe_id: spiffeId,
      wit_svid: token,
      wit_private_key: (await crypto.subtle.exportKey(
        "jwk",
        witKey.privateKey,
      )) as ECJWK & { d: string },
      kid: this.signingKid,
      entitlement: grants,
      exp,
    };
  }
}

/** 为 DA/PA 签发自包含 compact JWS，header 内嵌签发者公钥 JWK。 */
export async function signArtifact(
  typ: "da+jwt" | "pa+jwt",
  claims: unknown,
  priv: CryptoKey,
): Promise<string> {
  const pubJwk = await crypto.subtle.exportKey("jwk", priv);
  const header = {
    typ,
    alg: "ES256",
    jwk: { kty: pubJwk.kty, crv: pubJwk.crv, x: pubJwk.x, y: pubJwk.y },
  };
  return signJWS(header, claims, priv);
}

/** 验签并返回 payload 与签名公钥（公钥取自 header 的 jwk）。 */
export async function parseArtifact(
  s: string,
  wantTyp: string,
): Promise<{ payload: unknown; pub: CryptoKey }> {
  const hdr = parseHeader<{ typ?: string; alg?: string; jwk?: any }>(s);
  if (hdr.typ !== wantTyp) {
    throw new Error(`bad typ ${hdr.typ} (want ${wantTyp})`);
  }
  if (hdr.alg !== "ES256") {
    throw new Error(`unsupported alg ${hdr.alg}`);
  }
  const pub = await pubOfJwk(hdr.jwk);
  const res = await verifyJWS(s, pub);
  return { payload: res.payload, pub };
}

async function checkKeyHash(pub: CryptoKey, p: Principal): Promise<void> {
  const h = await keyHashOf(pub, p.hash_alg);
  if (h !== p.key_hash) {
    throw new Error("principal.key_hash does not match DA signing key");
  }
}