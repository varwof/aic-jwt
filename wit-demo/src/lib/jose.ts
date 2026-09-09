// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 浏览器版 jose：base64url、compact JWS、ES256 签名/验签（WebCrypto，零依赖）。
// WebCrypto 的 ECDSA sign/verify 直接给出/接收原始 r||s（RFC 7518 §3.4）。

const te = new TextEncoder();
const td = new TextDecoder();

export const utf8 = (s: string): Uint8Array => te.encode(s);

export const b64e = (b: Uint8Array): string => {
  let s = "";
  for (const byte of b) {
    s += String.fromCharCode(byte);
  }
  return btoa(s).replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
};

export const b64d = (s: string): Uint8Array => {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4 !== 0) {
    t += "=";
  }
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    out[i] = bin.charCodeAt(i);
  }
  return out;
};

const dec = (b: Uint8Array): string => td.decode(b);

export interface CompactParts {
  header: string;
  payload: string;
  sig: Uint8Array;
}

/** 拆 compact JWS：header/payload 解码为字符串，sig 保留字节。 */
export function parseCompact(s: string): CompactParts {
  const parts = s.split(".");
  if (parts.length !== 3) {
    throw new Error(`not a compact JWS (got ${parts.length} parts)`);
  }
  return {
    header: dec(b64d(parts[0])),
    payload: dec(b64d(parts[1])),
    sig: b64d(parts[2]),
  };
}

/** 只解析 header（不验签）。 */
export function parseHeader<T = Record<string, unknown>>(s: string): T {
  return JSON.parse(parseCompact(s).header) as T;
}

/** 构造 compact JWS（签名输入 = "h64.p64"）。 */
export async function signJWS(
  header: unknown,
  payload: unknown,
  priv: CryptoKey,
): Promise<string> {
  const h = b64e(utf8(JSON.stringify(header)));
  const p = b64e(utf8(JSON.stringify(payload)));
  const input = `${h}.${p}`;
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, priv, utf8(input)),
  );
  return `${input}.${b64e(sig)}`;
}

/** 验签（header 视为受保护）并返回 Header/Payload 对象。 */
export async function verifyJWS<T = unknown, P = unknown>(
  s: string,
  pub: CryptoKey,
): Promise<{ header: T; payload: P }> {
  const { header, payload, sig } = parseCompact(s);
  const input = `${b64e(utf8(header))}.${b64e(utf8(payload))}`;
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pub,
    sig,
    utf8(input),
  );
  if (!ok) {
    throw new Error("signature verification failed");
  }
  return {
    header: JSON.parse(header) as T,
    payload: JSON.parse(payload) as P,
  };
}

/** wth = base64url(SHA-256(UTF-8(WIT compact ASCII 原文)))。 */
export async function wthOf(wit: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", utf8(wit));
  return b64e(new Uint8Array(digest));
}

/** key_hash = base64url(SHA-256(SPKI DER))，alg 必须 sha-256。 */
export async function keyHashOf(pub: CryptoKey, alg: string): Promise<string> {
  if (alg !== "sha-256") {
    throw new Error(`unsupported hash alg ${alg}`);
  }
  const der = await crypto.subtle.exportKey("spki", pub);
  const digest = await crypto.subtle.digest("SHA-256", der);
  return b64e(new Uint8Array(digest));
}