// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 浏览器版 jwk：EC P-256 生成/导入导出/jkt（RFC 7638）。WebCrypto 实现。

import { b64e } from "./jose.ts";

export interface ECJWK {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
}

/** 本地生成 EC P-256 密钥对。 */
export async function generateKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
}

export async function jwkOfPub(key: CryptoKey): Promise<ECJWK> {
  const j = (await crypto.subtle.exportKey("jwk", key)) as ECJWK;
  return { kty: j.kty, crv: j.crv, x: j.x, y: j.y };
}

export async function jwkOfPriv(key: CryptoKey): Promise<ECJWK & { d: string }> {
  const j = (await crypto.subtle.exportKey("jwk", key)) as ECJWK & { d: string };
  if (!j.d) {
    throw new Error("unexpected: private key has no d");
  }
  return j;
}

export async function pubOfJwk(j: ECJWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    j,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
}

export async function privOfJwk(j: ECJWK): Promise<CryptoKey> {
  if (!j.d) {
    throw new Error("JWK has no private component d");
  }
  return crypto.subtle.importKey(
    "jwk",
    j,
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
}

/** RFC 7638 jkt：规范化 {"crv","kty","x","y"} 字典序无空白 → SHA-256 → base64url。 */
export async function jktOf(pub: CryptoKey): Promise<string> {
  const j = await jwkOfPub(pub);
  const canonical = `{"crv":"${j.crv}","kty":"${j.kty}","x":"${j.x}","y":"${j.y}"}`;
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return b64e(new Uint8Array(digest));
}