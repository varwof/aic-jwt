// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// TS 版 jwk：EC P-256 JWK、RFC 7638 jkt、key_hash。语义与 go/jwk.go 一致。

import { createHash, generateKeyPairSync, createPublicKey, createPrivateKey } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { b64e } from "./jose.ts";

export interface ECJWK {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
}

export function jwkOfPriv(priv: KeyObject): ECJWK {
  const j = priv.export({ format: "jwk" }) as ECJWK;
  return j;
}

export function jwkOfPub(pub: KeyObject): ECJWK {
  const j = pub.export({ format: "jwk" }) as ECJWK;
  return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
}

export function pubOfJwk(j: ECJWK): KeyObject {
  return createPublicKey({ key: j as object, format: "jwk" });
}

export function privOfJwk(j: ECJWK): KeyObject {
  if (!j.d) {
    throw new Error("JWK has no private component d");
  }
  return createPrivateKey({ key: j as object, format: "jwk" });
}

/** 本地生成 EC P-256 私钥（KeyObject）。 */
export function generateES256Key(): KeyObject {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return privateKey;
}

/** RFC 7638 jkt：规范化 {"crv","kty","x","y"} 字典序无空白 → SHA-256 → base64url。 */
export function jktOf(pub: KeyObject): string {
  const j = jwkOfPub(pub);
  const canonical = `{"crv":"${j.crv}","kty":"${j.kty}","x":"${j.x}","y":"${j.y}"}`;
  return b64e(createHash("sha256").update(canonical).digest());
}

/** key_hash = base64url(SHA-256(SPKI DER))，alg 必须 sha-256。 */
export function keyHashOf(pub: KeyObject, alg: string): string {
  if (alg !== "sha-256") {
    throw new Error(`unsupported hash alg ${alg}`);
  }
  const der = pub.export({ type: "spki", format: "der" });
  return b64e(createHash("sha256").update(der).digest());
}