// X.509 -> AIC-JWT bridge (draft Section 5.4 / 10.6 Mode B).
//
// Mirrors the Go reference `github.com/varwof/types` + aicjwt bridge:
//   - parseAIC     : ASN.1 DER AIC extension -> structured AIC (ParseAIC)
//   - mapToClaims  : AIC -> { outer, da } claims  (MapX509ToClaims)
//   - encodeTBS    : AIC -> DelegationAuthTBS DER  (Go DelegationAuthTBS)
//   - verifyDelegation : verify the principal-signed DA over encodeTBS
//                        (VerifyX509Delegation)
//
// Zero-dependency: uses WebCrypto + ts/asn1.ts only.

import {
  T_SEQUENCE, T_INTEGER, T_UTF8_STRING, T_GENERALIZED_TIME,
  ctxConstructed, derSeq, derInt, derUtf8, derOctet, derCtxConstructed,
  derGeneralizedTime, derAlgorithmIdentifier, derChildren, derPrimitive,
  derOid, parseGeneralizedTime, derIntValue, oidEqual, oidToString,
  OID_AIC, OID_SHA256, OID_SHA384, OID_SHA512,
  OID_SIG_ECDSA_SHA256, OID_SIG_ECDSA_SHA384, OID_SIG_ECDSA_SHA512,
  OID_SIG_RSA_SHA256, OID_SIG_RSA_SHA384, OID_SIG_RSA_SHA512,
  OID_SIG_ED25519, certExtensions,
} from "./asn1.ts";
import type { DERElement } from "./asn1.ts";

export interface X509Capability {
  scheme_id: string;
  capability_id: string;
  parameters?: Uint8Array;
}

export interface X509PrincipalUid {
  realm: string;
  identifier: string;
  keyHash: Uint8Array;
  hashAlgo: number[] | null; // OID; null => default SHA-256
}

export interface X509Authorization {
  reasonCode: string;
  reasonDesc: string;
  requestedLifetime: number;
  timestamp: Date;
  nonce: Uint8Array;
  signatureAlgorithm: number[] | null;
  signatureValue: Uint8Array;
}

export interface X509ExtField {
  id: number[];
  critical: boolean;
  value: Uint8Array;
}

export interface X509AIC {
  version: number;
  agentId: string;
  principalUid: X509PrincipalUid;
  capabilities: X509Capability[];
  delegationMode: number; // 0 = authorized, 1 = representative
  authorizationConstraints: X509Capability[];
  authorization: X509Authorization;
  extensions: X509ExtField[];
}

export interface BridgeOptions {
  now?: Date; // re-anchor DA ts when set (Mode B)
  daAudience: string;
  daRequestedLifetime?: number;
}

export interface BridgeClaims {
  outer: import("./aicjwt.ts").OuterClaims;
  da: import("./aicjwt.ts").DAClaims;
}

// ---- ASN.1 parsing ------------------------------------------------------

export function parseAIC(extValue: Uint8Array): X509AIC {
  const root = derChildren(extValue);
  if (root.length !== 1 || root[0].tag !== T_SEQUENCE) throw new Error("AIC: not a SEQUENCE");
  const fields = derChildren(root[0].content);
  let i = 0;

  // version INTEGER default:1 (omitted when 1)
  let version = 1;
  if (i < fields.length && fields[i].tag === T_INTEGER) version = derIntValue(fields[i++].content);

  // agentId UTF8 (required)
  if (i >= fields.length || fields[i].tag !== T_UTF8_STRING) throw new Error("AIC: agentId (UTF8String) required");
  const agentId = new TextDecoder().decode(fields[i++].content);

  // principalUid SEQUENCE (required)
  if (i >= fields.length || fields[i].tag !== T_SEQUENCE) throw new Error("AIC: principalUid required");
  const principalUid = parsePrincipalUid(fields[i++].content);

  // capabilities SEQUENCE OF (required)
  if (i >= fields.length || fields[i].tag !== T_SEQUENCE) throw new Error("AIC: capabilities required");
  const capabilities = parseCapabilities(fields[i++].content);

  // delegationMode INTEGER default:0
  let delegationMode = 0;
  if (i < fields.length && fields[i].tag === T_INTEGER) delegationMode = derIntValue(fields[i++].content);

  let authorizationConstraints: X509Capability[] = [];
  if (i < fields.length && fields[i].tag === ctxConstructed(0)) {
    const inner = derChildren(fields[i++].content);
    authorizationConstraints = parseCapabilities(inner[0].content);
  }

  // delegationAuthorization SEQUENCE (required per spec)
  if (i >= fields.length || fields[i].tag !== T_SEQUENCE) throw new Error("AIC: delegationAuthorization required");
  const authorization = parseAuthorization(fields[i++].content);

  let extensions: X509ExtField[] = [];
  if (i < fields.length && fields[i].tag === ctxConstructed(1)) {
    const inner = derChildren(fields[i++].content);
    for (const e of derChildren(inner[0].content)) {
      const ef = derChildren(e.content);
      const idRaw = ef[0];
      const id = decodeOidContent(idRaw.content);
      let critical = false;
      let value = new Uint8Array(0);
      for (const f of ef) {
        if (f.tag === 0x01) critical = derIntValue(f.content) !== 0;
        if (f.tag === 0x04) value = f.content;
      }
      extensions.push({ id, critical, value });
    }
  }

  return {
    version, agentId, principalUid, capabilities, delegationMode,
    authorizationConstraints, authorization, extensions,
  };
}

export function parsePrincipalUid(content: Uint8Array): X509PrincipalUid {
  const fields = derChildren(content);
  let i = 0;
  let version = 1;
  if (i < fields.length && fields[i].tag === T_INTEGER) version = derIntValue(fields[i++].content);
  if (i + 3 > fields.length) throw new Error("AIC: principalUid truncated");
  const realm = new TextDecoder().decode(fields[i++].content);
  const identifier = new TextDecoder().decode(fields[i++].content);
  const keyHash = fields[i++].content;
  let hashAlgo: number[] | null = null;
  if (i < fields.length && fields[i].tag === ctxConstructed(0)) {
    const algSeq = derChildren(fields[i++].content);
    const h = derChildren(algSeq[0].content)[0];
    hashAlgo = decodeOidContent(h.content);
  }
  return { realm, identifier, keyHash, hashAlgo };
}

function parseCapabilities(content: Uint8Array): X509Capability[] {
  const out: X509Capability[] = [];
  for (const el of derChildren(content)) {
    const f = derChildren(el.content);
    let i = 0;
    const scheme_id = new TextDecoder().decode(f[i++].content);
    const capability_id = new TextDecoder().decode(f[i++].content);
    let parameters: Uint8Array | undefined;
    if (i < f.length && f[i].tag === ctxConstructed(0)) {
      const inner = derChildren(f[i++].content);
      parameters = inner[0].content;
    }
    out.push({ scheme_id, capability_id, parameters });
  }
  return out;
}

function parseAuthorization(content: Uint8Array): X509Authorization {
  const f = derChildren(content);
  let i = 0;
  // reason SEQUENCE { reasonCode UTF8, description UTF8 }
  if (f[i].tag !== T_SEQUENCE) throw new Error("AIC: reason required");
  const reason = derChildren(f[i++].content);
  const reasonCode = new TextDecoder().decode(reason[0].content);
  const reasonDesc = new TextDecoder().decode(reason[1].content);
  let requestedLifetime = 0;
  if (i < f.length && f[i].tag === T_INTEGER) requestedLifetime = derIntValue(f[i++].content);
  if (i >= f.length || f[i].tag !== T_GENERALIZED_TIME) throw new Error("AIC: DA timestamp required");
  const timestamp = new Date(parseGeneralizedTime(f[i++].content));
  if (i >= f.length) throw new Error("AIC: DA nonce required");
  const nonce = f[i++].content;
  let signatureAlgorithm: number[] | null = null;
  if (i < f.length && f[i].tag === T_SEQUENCE) {
    const algSeq = derChildren(f[i++].content);
    signatureAlgorithm = decodeOidContent(algSeq[0].content);
  }
  const signatureValue = i < f.length ? f[i].content : new Uint8Array(0);
  return {
    reasonCode, reasonDesc, requestedLifetime, timestamp, nonce,
    signatureAlgorithm, signatureValue,
  };
}

function decodeOidContent(content: Uint8Array): number[] {
  // reuse asn1 module decodeOid
  const first = content[0];
  const oid: number[] = [Math.floor(first / 40), first % 40];
  let val = 0;
  for (let i = 1; i < content.length; i++) {
    val = val * 128 + (content[i] & 0x7f);
    if ((content[i] & 0x80) === 0) { oid.push(val); val = 0; }
  }
  return oid;
}

// ---- DelegationAuthTBS reconstruction (byte-identical to Go) -----------

export function encodeTBS(aic: X509AIC): Uint8Array {
  const parts: Uint8Array[] = [];
  if (aic.version !== 1) parts.push(derInt(aic.version));
  parts.push(derUtf8(aic.agentId));
  parts.push(encodePrincipalUid(aic.principalUid));
  parts.push(encodeReason(aic.authorization));
  parts.push(encodeCapabilitiesSeq(aic.capabilities));
  if (aic.delegationMode !== 0) parts.push(derInt(aic.delegationMode));
  if (aic.authorizationConstraints.length > 0) {
    parts.push(derCtxConstructed(0, encodeCapabilitiesSeq(aic.authorizationConstraints)));
  }
  if (aic.authorization.requestedLifetime !== 0) parts.push(derInt(aic.authorization.requestedLifetime));
  parts.push(derGeneralizedTime(aic.authorization.timestamp));
  parts.push(derOctet(aic.authorization.nonce));
  return derSeq(...parts);
}

function encodePrincipalUid(pu: X509PrincipalUid): Uint8Array {
  const parts: Uint8Array[] = [];
  parts.push(derUtf8(pu.realm));
  parts.push(derUtf8(pu.identifier));
  parts.push(derOctet(pu.keyHash));
  const oid = pu.hashAlgo && pu.hashAlgo.length ? pu.hashAlgo : OID_SHA256;
  parts.push(derCtxConstructed(0, derAlgorithmIdentifier(oid)));
  return derSeq(...parts);
}

function encodeReason(a: X509Authorization): Uint8Array {
  return derSeq(derUtf8(a.reasonCode), derUtf8(a.reasonDesc));
}

function encodeCapabilitiesSeq(caps: X509Capability[]): Uint8Array {
  return derSeq(...caps.map(encodeCapability));
}

function encodeCapability(c: X509Capability): Uint8Array {
  const parts: Uint8Array[] = [derUtf8(c.scheme_id), derUtf8(c.capability_id)];
  if (c.parameters && c.parameters.length) {
    parts.push(derCtxConstructed(0, derOctet(c.parameters)));
  }
  return derSeq(...parts);
}

// ---- claims mapping (draft Section 5.4) ---------------------------------

export async function mapToClaims(aic: X509AIC, opts: BridgeOptions): Promise<BridgeClaims> {
  const { hash_alg, key_hash } = hashNameAndKeyHash(aic);
  const principal = {
    realm: aic.principalUid.realm,
    id: aic.principalUid.identifier,
    key_hash,
    hash_alg,
  };

  const capabilities = aic.capabilities.map(x509CapToJson);
  const constraints = aic.authorizationConstraints.map(x509CapToJson);
  const delegation_mode = aic.delegationMode === 1 ? "representative" : "authorized";

  let ts = aic.authorization.timestamp;
  if (opts.now) ts = opts.now;
  let requestedLifetime = aic.authorization.requestedLifetime;
  if (opts.daRequestedLifetime && opts.daRequestedLifetime > 0) requestedLifetime = opts.daRequestedLifetime;
  const tsSec = Math.floor(ts.getTime() / 1000);
  const nonce = b64u(aic.authorization.nonce);

  const da = {
    ver: 2,
    iss: `${principal.realm}:${principal.id}`,
    sub: delegation_mode === "representative" ? `${principal.realm}:${principal.id}` : aic.agentId,
    aud: opts.daAudience as unknown as import("./aicjwt.ts").Audience,
    exp: tsSec + requestedLifetime,
    iat: tsSec,
    jti: nonce,
    agent_id: aic.agentId,
    principal,
    reason: { code: aic.authorization.reasonCode, desc: aic.authorization.reasonDesc },
    capabilities,
    delegation_mode,
    constraints: constraints.length ? constraints : undefined,
    requested_lifetime: requestedLifetime,
    ts: tsSec,
    nonce,
  };

  const outer = {
    iss: "",
    sub: aic.agentId,
    aud: opts.daAudience as unknown as import("./aicjwt.ts").Audience,
    iat: tsSec,
    exp: tsSec + requestedLifetime,
    jti: nonce,
    cnf: { jkt: "" },
    aic: {
      ver: aic.version,
      principal,
      delegation_mode,
      capabilities,
      constraints: constraints.length ? constraints : undefined,
      extensions: aic.extensions.length
        ? Object.fromEntries(aic.extensions.map((e) => [
            e.id.join("."),
            { critical: e.critical, der: arrayToB64u(e.value) },
          ]))
        : undefined,
    },
  };
  return { outer, da } as unknown as BridgeClaims;
}

function x509CapToJson(c: X509Capability): import("./aicjwt.ts").Capability {
  const j: import("./aicjwt.ts").Capability = { scheme: c.scheme_id, id: c.capability_id };
  if (c.parameters && c.parameters.length) {
    j.params = { der: arrayToB64u(c.parameters) };
  }
  return j;
}

function hashNameAndKeyHash(aic: X509AIC): { hash_alg: string; key_hash: string } {
  const oid = aic.principalUid.hashAlgo && aic.principalUid.hashAlgo.length ? aic.principalUid.hashAlgo : OID_SHA256;
  let name = "";
  if (oidEqual(oid, OID_SHA256)) name = "sha-256";
  else if (oidEqual(oid, OID_SHA384)) name = "sha-384";
  else if (oidEqual(oid, OID_SHA512)) name = "sha-512";
  else throw new Error(`x509 bridge: unsupported principalUid hash algo ${oidToString(oid)}`);
  return { hash_alg: name, key_hash: arrayToB64u(aic.principalUid.keyHash) };
}

export function arrayToB64u(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64u(b: Uint8Array): string {
  return arrayToB64u(b);
}

// ---- DA signature verification (WebCrypto) ------------------------------

// Verifies the principal-signed DelegationAuthorization over the
// reconstructed DelegationAuthTBS.  `principalPub` is the principal's
// WebCrypto public key (imported for the DA signature algorithm).
export async function verifyDelegation(aic: X509AIC, principalPub: CryptoKey): Promise<void> {
  const tbs = encodeTBS(aic);
  const algOid = aic.authorization.signatureAlgorithm;
  const sig = aic.authorization.signatureValue;

  if (algOid && oidEqual(algOid, OID_SIG_ED25519)) {
    const ok = await crypto.subtle.verify({ name: "Ed25519" }, principalPub, sig, tbs);
    if (!ok) throw new Error("x509 bridge: DelegationAuthTBS signature invalid");
    return;
  }
  if (algOid && (oidEqual(algOid, OID_SIG_RSA_SHA256) || oidEqual(algOid, OID_SIG_RSA_SHA384) || oidEqual(algOid, OID_SIG_RSA_SHA512))) {
    const name = "RSASSA-PKCS1-v1_5";
    const hash = oidEqual(algOid, OID_SIG_RSA_SHA256) ? "SHA-256" : oidEqual(algOid, OID_SIG_RSA_SHA384) ? "SHA-384" : "SHA-512";
    const alg: RsaHashedImportParams = { name, hash };
    const ok = await crypto.subtle.verify(alg, principalPub, sig, tbs);
    if (!ok) throw new Error("x509 bridge: DelegationAuthTBS signature invalid");
    return;
  }
  // ECDSA (default): WebCrypto expects raw r||s, not DER; if the value is
  // DER-encoded (SEQUENCE{r,s}) we decode it first.
  let raw = sig;
  if (algOid && (oidEqual(algOid, OID_SIG_ECDSA_SHA256) || oidEqual(algOid, OID_SIG_ECDSA_SHA384) || oidEqual(algOid, OID_SIG_ECDSA_SHA512))) {
    raw = derToRawECDSA(sig);
  }
  const hash = algOid && oidEqual(algOid, OID_SIG_ECDSA_SHA384) ? "SHA-384" : algOid && oidEqual(algOid, OID_SIG_ECDSA_SHA512) ? "SHA-512" : "SHA-256";
  const algE: EcdsaParams = { name: "ECDSA", hash } as EcdsaParams;
  const ok = await crypto.subtle.verify(algE, principalPub, raw, tbs);
  if (!ok) throw new Error("x509 bridge: DelegationAuthTBS signature invalid");
}

// Decode DER ECDSA SEQUENCE { INTEGER r, INTEGER s } to raw r||s. WebCrypto
// emits raw r||s while X.509 carries DER-encoded signatures; accept both.
function derToRawECDSA(der: Uint8Array): Uint8Array {
  if (der.length < 2 || der[0] !== T_SEQUENCE) return der;
  let seq: DERElement[];
  try {
    seq = derChildren(der);
  } catch {
    return der;
  }
  if (seq.length !== 1 || seq[0].tag !== T_SEQUENCE) return der;
  const ints = derChildren(seq[0].content);
  if (ints.length !== 2 || ints[0].tag !== T_INTEGER || ints[1].tag !== T_INTEGER) return der;
  const r = stripLeadZero(ints[0].content);
  const s = stripLeadZero(ints[1].content);
  const max = Math.max(r.length, s.length);
  const out = new Uint8Array(2 * max);
  out.set(r, max - r.length);
  out.set(s, 2 * max - s.length);
  return out;
}

function stripLeadZero(b: Uint8Array): Uint8Array {
  let i = 0;
  while (i < b.length - 1 && b[i] === 0) i++;
  return b.subarray(i);
}

export { parseAIC as parseAICExt };

// ---- AIC extension encoding (symmetric with encodeTBS/parseAIC) ---------

export function encodeAIC(aic: X509AIC): Uint8Array {
  const parts: Uint8Array[] = [];
  if (aic.version !== 1) parts.push(derInt(aic.version));
  parts.push(derUtf8(aic.agentId));
  parts.push(encodePrincipalUid(aic.principalUid));
  parts.push(encodeCapabilitiesSeq(aic.capabilities));
  if (aic.delegationMode !== 0) parts.push(derInt(aic.delegationMode));
  if (aic.authorizationConstraints.length > 0) {
    parts.push(derCtxConstructed(0, encodeCapabilitiesSeq(aic.authorizationConstraints)));
  }
  parts.push(encodeAuthorization(aic.authorization));
  if (aic.extensions.length > 0) {
    const exts = aic.extensions.map((e) => {
      const f: Uint8Array[] = [derOid(e.id)];
      if (e.critical) f.push(derPrimitiveBool(true));
      f.push(derOctet(e.value));
      return derSeq(...f);
    });
    parts.push(derCtxConstructed(1, derSeq(...exts)));
  }
  return derSeq(...parts);
}

function encodeAuthorization(a: X509Authorization): Uint8Array {
  const parts: Uint8Array[] = [encodeReason(a)];
  if (a.requestedLifetime !== 0) parts.push(derInt(a.requestedLifetime));
  parts.push(derGeneralizedTime(a.timestamp));
  parts.push(derOctet(a.nonce));
  if (a.signatureAlgorithm) parts.push(derAlgorithmIdentifier(a.signatureAlgorithm));
  if (a.signatureValue.length) parts.push(derOctet(a.signatureValue));
  return derSeq(...parts);
}

function derPrimitiveBool(v: boolean): Uint8Array {
  return derPrimitive(0x01, new Uint8Array([v ? 0xff : 0x00]));
}

/**
 * Builds a DER X.509 Certificate carrying the OIDAIC extension, using
 * minimal ASN.1 (valid per DER; not a signed/chainable cert).  Useful
 * for exercising the certificate-extraction path in tests/demos.
 */
export function buildAICCertificate(aic: X509AIC, spki: Uint8Array): Uint8Array {
  const ext = derSeq(derOid(OID_AIC), derOctet(encodeAIC(aic)));
  const tbsFields: Uint8Array[] = [];
  // version [0] EXPLICIT INTEGER 2 -> v3
  tbsFields.push(derCtxConstructed(0, derInt(2)));
  tbsFields.push(derInt(1)); // serial
  tbsFields.push(derAlgorithmIdentifier(OID_SIG_ECDSA_SHA256)); // signature
  tbsFields.push(derSeq()); // issuer (empty name)
  tbsFields.push(derSeq(derPrimitive(0x17, utf8z("260101000000Z")), derPrimitive(0x17, utf8z("270101000000Z")))); // validity
  tbsFields.push(derSeq()); // subject (empty name)
  tbsFields.push(derSeq(derAlgorithmIdentifier(OID_SIG_ECDSA_SHA256), derPrimitive(0x03, spki))); // subjectPublicKeyInfo
  tbsFields.push(derCtxConstructed(3, derSeq(ext))); // [3] extensions
  const tbs = derSeq(...tbsFields);
  const cert = derSeq(tbs, derSeq(derAlgorithmIdentifier(OID_SIG_ECDSA_SHA256), derPrimitive(0x03, new Uint8Array([0]))));
  return cert;
}

/**
 * Locates the OIDAIC extension value inside a DER X.509 certificate and
 * parses it.  Returns null when the extension is absent.
 */
export function findAIC(certDER: Uint8Array): X509AIC | null {
  const exts = certExtensions(certDER);
  const e = exts.get(oidToString(OID_AIC));
  if (!e) return null;
  return parseAIC(e.value);
}

function utf8z(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
