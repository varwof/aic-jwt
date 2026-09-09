// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// TS 版 AIC-aware 发放服务：签发 WIT-SVID 前校验 DA/PA。语义与 go/issuer.go 一致。
// 失败抛 Error（可读），不产生半成品 grant。

import type { KeyObject } from "node:crypto";
import { createPublicKey } from "node:crypto";
import { signJWS, verifyJWS, parseHeader, b64d } from "./jose.ts";
import { jwkOfPub, pubOfJwk, keyHashOf, generateES256Key } from "./jwk.ts";
import type { ECJWK } from "./jwk.ts";
import {
  capabilitiesCovered,
  validateConstraints,
} from "./subset.ts";
import type { DA, PA, WITGrant, Principal, Capability } from "./types.ts";

export class Issuer {
  trustDomain: string;
  signingKey: KeyObject;
  signingKid: string;

  constructor(trustDomain: string, key: KeyObject, kid: string) {
    this.trustDomain = trustDomain;
    this.signingKey = key;
    this.signingKid = kid;
  }

  issue(da: string, paOpt: string, agentID: string, now: number): WITGrant {
    const daRes = parseArtifact(da, "da+jwt");
    const d = daRes.payload as DA;
    if (d.ver !== 1) {
      throw new Error(`DA: unsupported ver ${d.ver}`);
    }
    // 1. 校验 principal.key_hash 与签名公钥一致
    checkKeyHash(daRes.pub, d.principal);
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
      const paRes = parseArtifact(paOpt, "pa+jwt");
      const p = paRes.payload as PA;
      if (p.ver !== 1) {
        throw new Error(`PA: unsupported ver ${p.ver}`);
      }
      if (p.principal.key_hash !== d.principal.key_hash ||
          p.principal.hash_alg !== d.principal.hash_alg) {
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
      // authorized：DA 即授权快照，entitlement 直接取 DA capabilities
      grants = d.capabilities;
      if (paOpt !== "") {
        throw new Error("authorized DA must not carry a PA");
      }
    }

    // 4. 生成 WIT 密钥对（模拟 wit_svid_key 随响应下发；与 AIC agent 密钥是
    //    issuance-time 映射，非同一把）
    const witKey = generateES256Key();
    const spiffeId = `spiffe://${this.trustDomain}/agent/${agentID}`;
    const exp = now + d.requested_lifetime;
    const witClaims = {
      iss: spiffeId,
      sub: spiffeId,
      iat: now,
      exp,
      cnf: {
        jwk: jwkOfPub(witKey),
        alg: "ES256",
      },
    };
    const witHeader = {
      typ: "wit+jwt",
      alg: "ES256",
      kid: this.signingKid,
    };
    const token = signJWS(witHeader, witClaims, this.signingKey);

    return {
      spiffe_id: spiffeId,
      wit_svid: token,
      wit_private_key: jwkOfPriv(witKey),
      kid: this.signingKid,
      entitlement: grants,
      exp,
    };
  }
}

function jwkOfPriv(priv: KeyObject): ECJWK {
  return priv.export({ format: "jwk" }) as ECJWK;
}

/** 为 DA/PA 签发自包含 compact JWS，header 内嵌签发者公钥 JWK。 */
export function signArtifact(
  typ: "da+jwt" | "pa+jwt",
  claims: unknown,
  priv: KeyObject,
): string {
  const header = {
    typ,
    alg: "ES256",
    jwk: jwkOfPub(createPublicKey(priv)),
  };
  return signJWS(header, claims, priv);
}

/** 验签并返回 payload 与签名公钥（公钥取自 header 的 jwk）。 */
export function parseArtifact(
  s: string,
  wantTyp: string,
): { payload: unknown; pub: KeyObject } {
  const hdr = parseHeader(s) as { typ?: string; alg?: string; jwk?: ECJWK };
  if (hdr.typ !== wantTyp) {
    throw new Error(`bad typ ${hdr.typ} (want ${wantTyp})`);
  }
  if (hdr.alg !== "ES256") {
    throw new Error(`unsupported alg ${hdr.alg}`);
  }
  const pub = pubOfJwk(hdr.jwk as ECJWK);
  const res = verifyJWS(s, pub);
  return { payload: res.payload as unknown, pub };
}

function checkKeyHash(pub: KeyObject, p: Principal): void {
  const h = keyHashOf(pub, p.hash_alg);
  if (h !== p.key_hash) {
    throw new Error("principal.key_hash does not match DA signing key");
  }
}