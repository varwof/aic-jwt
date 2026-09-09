// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// TS 版 jose：base64url、compact JWS、ES256 签名/验签（node:crypto）。
// 注释语义与 go/jose.go 严格一致；ES256 用 ieee-p1363 直接产出/校验原始 R||S。

import { createHash, createSign, createVerify } from "node:crypto";
import type { KeyObject, SignKeyObjectInput, VerifyKeyObjectInput } from "node:crypto";

export const b64e = (b: Uint8Array): string =>
  Buffer.from(b).toString("base64url");

export const b64d = (s: string): Uint8Array => {
  const b = Buffer.from(s, "base64url");
  if (b.length === 0 && s.length !== 0) {
    throw new Error("bad base64url");
  }
  return b;
};

export interface CompactParts {
  header: Uint8Array;
  payload: Uint8Array;
  sig: Uint8Array;
}

/** 把 compact JWS 拆成三段（解码后）。 */
export function parseCompact(s: string): CompactParts {
  const parts = s.split(".");
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS (got ${parts.length} parts)`);
  }
  return {
    header: b64d(parts[0]),
    payload: b64d(parts[1]),
    sig: b64d(parts[2]),
  };
}

function es256SignInput(key: SignKeyObjectInput) {
  return {
    key: key as SignKeyObjectInput,
    dsaEncoding: "ieee-p1363" as const,
  };
}

function es256VerifyInput(key: VerifyKeyObjectInput) {
  return {
    key: key as VerifyKeyObjectInput,
    dsaEncoding: "ieee-p1363" as const,
  };
}

/** 构造 compact JWS（签名输入 = "h64.p64"）。 */
export function signJWS(
  header: unknown,
  payload: unknown,
  priv: KeyObject,
): string {
  const h = Buffer.from(JSON.stringify(header));
  const p = Buffer.from(JSON.stringify(payload));
  const input = `${b64e(h)}.${b64e(p)}`;
  const sig = createSign("sha256").update(input).sign(es256SignInput(priv));
  return `${input}.${b64e(sig)}`;
}

/** 验签并返回 Header/Payload 对象（header 视为受保护）。 */
export function verifyJWS<T = unknown, P = unknown>(
  s: string,
  pub: KeyObject,
): { header: T; payload: P } {
  const { header, payload, sig } = parseCompact(s);
  const input = `${b64e(header)}.${b64e(payload)}`;
  const ok = createVerify("sha256")
    .update(input)
    .verify(es256VerifyInput(pub), Buffer.from(sig));
  if (!ok) {
    throw new Error("signature verification failed");
  }
  return {
    header: JSON.parse(new TextDecoder().decode(header)) as T,
    payload: JSON.parse(new TextDecoder().decode(payload)) as P,
  };
}

/** 只解析 header（不验签），用于检查 typ/alg/kid。 */
export function parseHeader(s: string): any {
  return JSON.parse(new TextDecoder().decode(parseCompact(s).header));
}

/** wth = base64url(SHA-256(UTF-8(WIT compact ASCII 原文)))。 */
export const wthOf = (wit: string): string =>
  b64e(createHash("sha256").update(wit, "utf8").digest());