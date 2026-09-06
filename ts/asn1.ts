// Minimal ASN.1 DER codec + X.509 AIC extraction.
//
// Zero-dependency, browser/Node compatible (Uint8Array + TextEncoder only).
// The encodings mirror the Go reference `github.com/varwof/types` AIC
// ASN.1 structures (aic.go / principal.go) so that a `DelegationAuthTBS`
// reconstructed here is byte-identical to the one the principal signed in the
// X.509 profile.  Field order and default/omit rules are reproduced exactly.

// ---- tags ---------------------------------------------------------------

export const T_SEQUENCE = 0x30; // [UNIVERSAL 16] constructed
export const T_SET = 0x31;
export const T_INTEGER = 0x02;
export const T_OCTET_STRING = 0x04;
export const T_OID = 0x06;
export const T_UTF8_STRING = 0x0c;
export const T_GENERALIZED_TIME = 0x18;

export function ctxConstructed(tag: number): number {
  return 0xa0 + tag; // context-specific [tag] constructed
}

// ---- OIDs (mirror github.com/varwof/types/oid.go) ----------------------

export const OID_AIC = [1, 3, 6, 1, 4, 1, 66257, 1, 1];
export const OID_SHA256 = [2, 16, 840, 1, 101, 3, 4, 2, 1];
export const OID_SHA384 = [2, 16, 840, 1, 101, 3, 4, 2, 2];
export const OID_SHA512 = [2, 16, 840, 1, 101, 3, 4, 2, 3];
export const OID_SIG_ECDSA_SHA256 = [1, 2, 840, 10045, 4, 3, 2];
export const OID_SIG_ECDSA_SHA384 = [1, 2, 840, 10045, 4, 3, 3];
export const OID_SIG_ECDSA_SHA512 = [1, 2, 840, 10045, 4, 3, 4];
export const OID_SIG_RSA_SHA256 = [1, 2, 840, 113549, 1, 1, 11];
export const OID_SIG_RSA_SHA384 = [1, 2, 840, 113549, 1, 1, 12];
export const OID_SIG_RSA_SHA512 = [1, 2, 840, 113549, 1, 1, 13];
export const OID_SIG_ED25519 = [1, 3, 101, 112];
export const DSS_SHA256 = [2, 16, 840, 1, 101, 3, 4, 3, 2];

export function oidEqual(a: readonly number[], b: readonly number[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function oidToString(oid: readonly number[]): string {
  return oid.join(".");
}

// ---- low-level DER primitives ------------------------------------------

function derLen(n: number): Uint8Array {
  if (n < 0x80) return new Uint8Array([n]);
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function tl(tag: number, content: Uint8Array): Uint8Array {
  const len = derLen(content.length);
  const out = new Uint8Array(1 + len.length + content.length);
  out[0] = tag;
  out.set(len, 1);
  out.set(content, 1 + len.length);
  return out;
}

export function derPrimitive(tag: number, content: Uint8Array): Uint8Array {
  return tl(tag, content);
}

export function derSeq(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((a, b) => a + b.length, 0);
  const body = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    body.set(p, o);
    o += p.length;
  }
  return tl(T_SEQUENCE, body);
}

export function derOid(oid: readonly number[]): Uint8Array {
  const bytes: number[] = [];
  bytes.push(oid[0] * 40 + oid[1]);
  for (let i = 2; i < oid.length; i++) {
    let v = oid[i];
    const group: number[] = [];
    do {
      group.unshift(v & 0x7f);
      v >>>= 7;
    } while (v > 0);
    for (let k = 0; k < group.length; k++) {
      bytes.push(k === group.length - 1 ? group[k] : group[k] | 0x80);
    }
  }
  return tl(T_OID, new Uint8Array(bytes));
}

export function derInt(n: number): Uint8Array {
  if (n === 0) return derPrimitive(T_INTEGER, new Uint8Array([0]));
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>>= 8;
  }
  if (bytes[0] & 0x80) bytes.unshift(0x00); // keep positive
  return derPrimitive(T_INTEGER, new Uint8Array(bytes));
}

export function derUtf8(s: string): Uint8Array {
  return derPrimitive(T_UTF8_STRING, new TextEncoder().encode(s));
}

export function derOctet(b: Uint8Array): Uint8Array {
  return derPrimitive(T_OCTET_STRING, b);
}

export function derCtxConstructed(tag: number, content: Uint8Array): Uint8Array {
  return tl(ctxConstructed(tag), content);
}

// Encode a Date as DER GeneralizedTime in UTC (YYYYMMDDHHMMSSZ) with
// second precision, matching Go's encoding/asn1 generalized output.
export function derGeneralizedTime(d: Date): Uint8Array {
  const s = d.toISOString(); // yyyy-MM-ddTHH:mm:ss.sssZ
  let secs = s.slice(0, 4) + s.slice(5, 7) + s.slice(8, 10);
  secs += s.slice(11, 13) + s.slice(14, 16) + s.slice(17, 19);
  secs += "Z";
  return derPrimitive(T_GENERALIZED_TIME, new TextEncoder().encode(secs));
}

// Parse a DER GeneralizedTime (YYYYMMDDHHMMSSZ / ISO) back to epoch ms.
export function parseGeneralizedTime(b: Uint8Array): number {
  const s = new TextDecoder().decode(b);
  const yr = +s.slice(0, 4);
  const mo = +s.slice(4, 6);
  const da = +s.slice(6, 8);
  const hh = +s.slice(8, 10);
  const mi = +s.slice(10, 12);
  const ss = +s.slice(12, 14);
  return Date.UTC(yr, mo - 1, da, hh, mi, ss);
}

export function derAlgorithmIdentifier(oid: readonly number[]): Uint8Array {
  return derSeq(derOid(oid));
}

// ---- DER reader (splits a SEQUENCE/SET body into [tag, content]) -------

export interface DERElement {
  tag: number;
  content: Uint8Array; // full content octets (after the length header)
}

/** Reads `<tag><len><content>` at the start of `buf`, returning the element and the byte offset just past its content. */
export function readElement(buf: Uint8Array, off: number): { el: DERElement; next: number } {
  if (off >= buf.length) throw new Error("ASN.1: unexpected end (tag)");
  const tag = buf[off];
  let i = off + 1;
  if (i >= buf.length) throw new Error("ASN.1: unexpected end (len)");
  let len = buf[i];
  let lengthOfLen = 1;
  if (len === 0x80) throw new Error("ASN.1: indefinite length not allowed in DER");
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4) throw new Error(`ASN.1: bad long-form length n=${n}`);
    len = 0;
    for (let k = 0; k < n; k++) {
      len = (len << 8) | buf[i + 1 + k];
    }
    lengthOfLen = 1 + n;
  }
  i += lengthOfLen;
  if (i + len > buf.length) throw new Error("ASN.1: content overruns buffer");
  return {
    el: { tag, content: buf.subarray(i, i + len) },
    next: i + len,
  };
}

/** Splits the body of a constructed element into its child elements. */
export function derChildren(content: Uint8Array): DERElement[] {
  const out: DERElement[] = [];
  let off = 0;
  while (off < content.length) {
    const { el, next } = readElement(content, off);
    out.push(el);
    off = next;
  }
  return out;
}

// Unsigned big-endian integer content -> number (safe for AIC sizes).
export function derIntValue(content: Uint8Array): number {
  let v = 0;
  for (const b of content) v = v * 256 + b;
  return v;
}

// ---- X.509 certificate extension extraction ----------------------------

export interface X509Extension {
  id: string;
  critical: boolean;
  value: Uint8Array;
}

/**
 * Extracts the extensions from an X.509 (DER) certificate body by walking
 * Certificate -> tbsCertificate -> [3] extensions -> SEQUENCE OF Extension.
 * Returns a map keyed by the extension OID string.
 */
export function certExtensions(certDER: Uint8Array): Map<string, X509Extension> {
  const cert = derChildren(certDER);
  if (cert.length < 1 || cert[0].tag !== T_SEQUENCE) throw new Error("x509: not a Certificate SEQUENCE");
  const tbs = derChildren(cert[0].content);
  if (tbs.length < 1 || tbs[0].tag !== T_SEQUENCE) throw new Error("x509: tbsCertificate not a SEQUENCE");
  const tbsFields = derChildren(tbs[0].content);
  // The last field (if context-specific constructed tag 3) is the
  // [3] EXPLICIT Extensions.
  const last = tbsFields[tbsFields.length - 1];
  if (!last || last.tag !== ctxConstructed(3)) return new Map();
  const extSeq = derChildren(last.content);
  if (extSeq.length !== 1 || extSeq[0].tag !== T_SEQUENCE) throw new Error("x509: Extensions not a SEQUENCE");
  const map = new Map<string, X509Extension>();
  for (const e of derChildren(extSeq[0].content)) {
    const fields = derChildren(e.content);
    if (fields.length < 2) continue;
    const idEl = fields[0];
    if (idEl.tag !== T_OID) continue;
    const oid = decodeOid(idEl.content);
    const valueEl = fields[fields.length - 1];
    // value is OCTET STRING; critical (if present) is BOOLEAN after OID.
    let critical = false;
    for (const f of fields) {
      if (f.tag === 0x01) critical = denInt(f.content) !== 0;
    }
    map.set(oid.join("."), { id: oid.join("."), critical, value: valueEl.content });
  }
  return map;
}

export function denInt(b: Uint8Array): number {
  let v = 0;
  for (const x of b) v = v * 256 + x;
  return v;
}

export function decodeOid(content: Uint8Array): number[] {
  const oid: number[] = [];
  const first = content[0];
  oid.push(Math.floor(first / 40), first % 40);
  let val = 0;
  for (let i = 1; i < content.length; i++) {
    val = val * 128 + (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) {
      oid.push(val);
      val = 0;
    }
  }
  return oid;
}
