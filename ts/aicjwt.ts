// AIC-JWT WebCrypto reference implementation for
// draft-wei-aic-jwt-00 (AIC-JWT: JSON Web Token Profile for AI Agent
// Identity Certificates).
//
// Browser-compatible: uses only WebCrypto (globalThis.crypto.subtle),
// TextEncoder/TextDecoder, btoa/atob and BigInt.  No Node-specific
// APIs are used, so this module runs in browsers (via a bundler),
// Deno, and Node 19+.

export type Audience = string | string[];

export interface Header {
  alg: string;
  typ: string;
  kid?: string;
  crit?: string[];
  jwk?: JsonWebKey; // DPoP proofs (RFC 9449)
}

export interface Principal {
  realm: string;
  id: string;
  key_hash: string;
  hash_alg: string;
}

export interface Capability {
  scheme: string;
  id: string;
  params?: unknown;
}

export interface Reason {
  code: string;
  desc: string;
}

export interface Cnf {
  jkt: string;
}

export interface StatusRef {
  idx: number;
  uri: string;
}

export interface AICClaims {
  ver: number;
  principal: Principal;
  delegation_mode: string;
  capabilities: Capability[];
  constraints?: Capability[];
  chain_depth?: number;
  max_depth?: number;
  extensions?: Record<string, unknown>;
}

export interface OuterClaims {
  iss: string;
  sub: string;
  aud: Audience;
  iat: number;
  exp: number;
  nbf?: number;
  jti: string;
  cnf: Cnf;
  scope?: string;
  client_id?: string;
  status?: StatusRef;
  aic: AICClaims;
  da?: string;
  authorization_details?: unknown;
  act?: { sub: string };
}

export interface DAClaims {
  ver: number;
  iss: string;
  sub: string;
  aud: Audience;
  exp: number;
  iat?: number;
  jti: string;
  agent_id: string;
  principal: Principal;
  reason: Reason;
  capabilities: Capability[];
  delegation_mode: string;
  constraints?: Capability[];
  requested_lifetime: number;
  ts: number;
  nonce: string;
}

export interface DelegationPolicy {
  max_agents: number;
  allowed_mode: string;
  max_session_hours?: number;
}

export interface PAClaims {
  ver: number;
  principal: Principal;
  grants: Capability[];
  constraints?: Capability[];
  delegation_policy?: DelegationPolicy;
  extensions?: Record<string, unknown>;
}

export interface Decision {
  permit: boolean;
  actor: string;
  executor: string;
  principal: string;
  capabilities: Capability[];
  notes: string[];
}

export interface RequestContext {
  now: Date;
  sourceIP?: string;
  concurrentCount?: number;
}

export type CapabilityPlugin = (req: Capability, ctx: RequestContext) => void | Promise<void>;
export type StatusChecker = (ref: StatusRef) => void | Promise<void>;
export interface NonceStore {
  checkAndAdd(nonce: string): void | Promise<void>;
}

export interface VerifyOptions {
  now: Date;
  expectedIssuer?: string;
  expectedAudience?: string[];
  issuerKeys: Record<string, CryptoKey>;
  principalJWKS?: Record<string, CryptoKey>;
  presenterKey?: CryptoKey;
  requestCapability?: Capability;
  requestContext?: RequestContext;
  constraintStrict?: boolean;
  capabilityPlugins?: Record<string, CapabilityPlugin>;
  statusChecker?: StatusChecker;
  nonceStore?: NonceStore;
  rejectDepthGT1?: boolean;
  requireJtiNonceMatch?: boolean;
  pa?: PAClaims;
}

export const TYP_OUTER = "aic+jwt";
export const TYP_DA = "aic+da+jwt";
export const TYP_PA = "aic+pa+jwt";
export const MODE_AUTHORIZED = "authorized";
export const MODE_REPRESENTATIVE = "representative";
export const CONSTRAINT_SCHEME = "varwof/constraint-v1";
export const MAX_LIFETIME = 86400;
export const ALLOWED_MODE_REPRESENTATIVE = "representative_allowed";
export const MAX_TOKEN_SIZE = 64 * 1024; // draft Section 13.7 hard limit
export const MAX_PARAMS_SIZE = 512; // draft Section 13.7 params limit

export const ALLOWED_ALGS = new Set([
  "ES256", "ES384", "ES512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA",
]);
export const IMPLEMENTED_ALGS = new Set(["ES256", "RS256", "PS256", "PS384", "PS512", "EdDSA"]);

// ---- base64url / utf8 -------------------------------------------------

const te = new TextEncoder();
const td = new TextDecoder();

export function b64uEncode(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(s: string): Uint8Array {
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function utf8(s: string): Uint8Array {
  return te.encode(s);
}

// ---- JWS ---------------------------------------------------------------

export async function signCompact(
  header: Header,
  payload: unknown,
  key: CryptoKey,
): Promise<string> {
  if (!ALLOWED_ALGS.has(header.alg)) {
    throw new Error(`algorithm ${header.alg} not in AIC-JWT allowlist`);
  }
  if (!IMPLEMENTED_ALGS.has(header.alg)) {
    throw new Error(`algorithm ${header.alg} recognized but not implemented`);
  }
  const h = b64uEncode(utf8(JSON.stringify(header)));
  const p = b64uEncode(utf8(JSON.stringify(payload)));
  const input = utf8(h + "." + p);
  const sig = new Uint8Array(await signBytes(header.alg, input, key));
  return h + "." + p + "." + b64uEncode(sig);
}

export async function signBytes(alg: string, input: Uint8Array, key: CryptoKey): Promise<Uint8Array> {
  switch (alg) {
    case "ES256":
      return new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, input));
    case "RS256":
      return new Uint8Array(await crypto.subtle.sign({ name: "RSASSA-PKCS1-v1_5" }, key, input));
    case "PS256":
      return new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, key, input));
    case "PS384":
      return new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 48 }, key, input));
    case "PS512":
      return new Uint8Array(await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 64 }, key, input));
    case "EdDSA":
      return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, key, input));
    default:
      throw new Error(`algorithm ${alg} not supported`);
  }
}

export async function verifyBytes(alg: string, input: Uint8Array, sig: Uint8Array, key: CryptoKey): Promise<void> {
  let ok: boolean;
  switch (alg) {
    case "ES256":
      ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, input);
      break;
    case "RS256":
      ok = await crypto.subtle.verify({ name: "RSASSA-PKCS1-v1_5" }, key, sig, input);
      break;
    case "PS256":
      ok = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, key, sig, input);
      break;
    case "PS384":
      ok = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 48 }, key, sig, input);
      break;
    case "PS512":
      ok = await crypto.subtle.verify({ name: "RSA-PSS", saltLength: 64 }, key, sig, input);
      break;
    case "EdDSA":
      ok = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, input);
      break;
    default:
      throw new Error(`algorithm ${alg} not supported`);
  }
  if (!ok) throw new Error("signature verification failed");
}

// hasDuplicateJSONKeys reports whether the JSON text contains an
// object with duplicate member names.  Duplicate members are ambiguous
// across implementations (RFC 8725) and MUST NOT be accepted.
export function hasDuplicateJSONKeys(text: string): boolean {
  let i = 0;
  const skipWs = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const parseString = (): boolean => {
    i++; // opening quote
    while (i < text.length) {
      const c = text[i];
      if (c === "\\") { i += 2; continue; }
      if (c === '"') { i++; return true; }
      i++;
    }
    return false;
  };
  const walk = (): boolean => {
    skipWs();
    const c = text[i];
    if (c === "{") {
      i++;
      const seen = new Set<string>();
      skipWs();
      if (text[i] === "}") { i++; return false; }
      for (;;) {
        skipWs();
        if (text[i] !== '"') return false;
        const start = i;
        if (!parseString()) return false;
        const key = text.slice(start + 1, i - 1);
        if (seen.has(key)) return true;
        seen.add(key);
        skipWs();
        if (text[i] !== ":") return false;
        i++;
        if (walk()) return true;
        skipWs();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return false; }
        return false;
      }
    }
    if (c === "[") {
      i++;
      skipWs();
      if (text[i] === "]") { i++; return false; }
      for (;;) {
        if (walk()) return true;
        skipWs();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return false; }
        return false;
      }
    }
    if (c === '"') { parseString(); return false; }
    while (i < text.length && text[i] !== "," && text[i] !== "}" && text[i] !== "]" && text[i] !== " " && text[i] !== "\t" && text[i] !== "\n" && text[i] !== "\r") i++;
    return false;
  };
  try {
    return walk();
  } catch {
    return true; // malformed input: reject rather than accept
  }
}

export function parseCompact(token: string): { header: Header; payload: unknown; parts: string[] } {
  if (token.length > MAX_TOKEN_SIZE) {
    throw new Error(`token size ${token.length} exceeds max ${MAX_TOKEN_SIZE}`);
  }
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWS compact serialization");
  const hb = b64uDecode(parts[0]);
  const pb = b64uDecode(parts[1]);
  const hs = td.decode(hb);
  const ps = td.decode(pb);
  if (hasDuplicateJSONKeys(hs)) throw new Error("duplicate JSON member names in JWS header");
  if (hasDuplicateJSONKeys(ps)) throw new Error("duplicate JSON member names in JWS payload");
  let header: Header;
  try {
    header = JSON.parse(hs) as Header;
  } catch {
    throw new Error("bad JWS header");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(ps);
  } catch {
    throw new Error("bad JWS payload");
  }
  return { header, payload, parts };
}

export async function verifyCompact(token: string, alg: string, key: CryptoKey): Promise<void> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed JWS compact serialization");
  const sig = b64uDecode(parts[2]);
  await verifyBytes(alg, utf8(parts[0] + "." + parts[1]), sig, key);
}

// ---- key binding (draft Section 9.2) -----------------------------------

export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  let canon: string;
  switch (jwk.kty) {
    case "EC":
      canon = `{"crv":"${jwk.crv}","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
      break;
    case "RSA":
      canon = `{"e":"${jwk.e}","kty":"RSA","n":"${jwk.n}"}`;
      break;
    case "OKP":
      canon = `{"crv":"${jwk.crv}","kty":"OKP","x":"${jwk.x}"}`;
      break;
    default:
      throw new Error(`unsupported kty ${jwk.kty}`);
  }
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(canon)));
  return b64uEncode(d);
}

export async function spkiHash(key: CryptoKey, hashAlg: string): Promise<string> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", key));
  const alg =
    hashAlg === "sha-256" ? "SHA-256" :
    hashAlg === "sha-384" ? "SHA-384" :
    hashAlg === "sha-512" ? "SHA-512" : null;
  if (!alg) throw new Error(`unsupported SPKI hash algorithm ${hashAlg}`);
  const d = new Uint8Array(await crypto.subtle.digest(alg, spki));
  return b64uEncode(d);
}

export async function keyHashOf(key: CryptoKey, hashAlg: string): Promise<string> {
  const alg = hashAlg || "sha-256";
  if (alg === "jkt") {
    const jwk = await crypto.subtle.exportKey("jwk", key);
    return jwkThumbprint(jwk);
  }
  return spkiHash(key, alg);
}

// ---- capability matching (draft Section 6) ------------------------------

export function capPattern(c: Capability): string {
  return c.scheme + ":" + c.id;
}

function tokenize(segs: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < segs.length; i++) {
    if (i > 0) out.push(":");
    const s = segs[i];
    if (s === "*" || s === "**") {
      out.push(s);
      continue;
    }
    const parts = s.split("/");
    for (let j = 0; j < parts.length; j++) {
      if (j > 0) out.push("/");
      out.push(parts[j]);
    }
  }
  return out;
}

function matchTokens(p: string[], t: string[]): boolean {
  if (p.length === 0) return t.length === 0;
  const head = p[0];
  if (head === "**") {
    if (t.length === 0) return false;
    for (let i = 1; i <= t.length; i++) {
      if (matchTokens(p.slice(1), t.slice(i))) return true;
    }
    return false;
  }
  if (head === "*") {
    if (t.length === 0 || t[0] === "/" || t[0] === ":") return false;
    return matchTokens(p.slice(1), t.slice(1));
  }
  if (t.length === 0) return false;
  // Literal tokens may carry {a,b} alternation, [a-z] character
  // classes, or an embedded '*' (07-capability).
  if (!matchToken(p[0], t[0])) return false;
  return matchTokens(p.slice(1), t.slice(1));
}

function matchToken(pattern: string, target: string): boolean {
  return matchTokenAt(pattern, 0, target, 0);
}

function matchTokenAt(p: string, pi: number, t: string, ti: number): boolean {
  for (;;) {
    if (pi >= p.length) return ti >= t.length;
    const c = p[pi];
    if (c === "*") {
      for (let k = ti; k <= t.length; k++) {
        if (matchTokenAt(p, pi + 1, t, k)) return true;
      }
      return false;
    }
    if (c === "{") {
      const end = p.indexOf("}", pi + 1);
      if (end < 0) return false;
      for (const alt of p.slice(pi + 1, end).split(",")) {
        if (t.startsWith(alt, ti) && matchTokenAt(p, end + 1, t, ti + alt.length)) {
          return true;
        }
      }
      return false;
    }
    if (c === "[") {
      const end = p.indexOf("]", pi + 1);
      if (end < 0 || ti >= t.length) return false;
      if (!inCharClass(p.slice(pi + 1, end), t[ti])) return false;
      pi = end + 1;
      ti += 1;
      continue;
    }
    if (ti >= t.length || t[ti] !== c) return false;
    pi += 1;
    ti += 1;
  }
}

function inCharClass(body: string, ch: string): boolean {
  for (let i = 0; i < body.length; i++) {
    if (i + 2 < body.length && body[i + 1] === "-") {
      if (body[i] <= ch && ch <= body[i + 2]) return true;
      i += 2;
      continue;
    }
    if (body[i] === ch) return true;
  }
  return false;
}

function patternScore(ps: string[]): number {
  if (ps.length === 2 && ps[1] === "*") return 1; // scheme-level
  let hasDouble = false;
  let hasStar = false;
  let hasAlt = false;
  let hasClass = false;
  for (const seg of ps) {
    if (seg.includes("**")) hasDouble = true;
    if (seg.includes("*")) hasStar = true;
    if (seg.includes("{")) hasAlt = true;
    if (seg.includes("[")) hasClass = true;
  }
  if (hasDouble) return 4;
  if (hasStar) return 5;
  if (hasAlt) return 3;
  if (hasClass) return 2;
  return 6;
}

export function matchPattern(pattern: string, target: string): { matched: boolean; score: number } {
  const ps = pattern.split(":");
  const ts = target.split(":");
  if (ps.length === 2 && ps[1] === "*") {
    if (ts.length >= 2 && ts[0] === ps[0]) return { matched: true, score: 1 };
    return { matched: false, score: 0 };
  }
  if (!matchTokens(tokenize(ps), tokenize(ts))) return { matched: false, score: 0 };
  return { matched: true, score: patternScore(ps) };
}

export function matchCapabilities(allowed: Capability[], req: Capability): boolean {
  const target = capPattern(req);
  let best = 0;
  for (const c of allowed) {
    const r = matchPattern(capPattern(c), target);
    if (r.matched && r.score > best) best = r.score;
  }
  return best > 0;
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function paramsWithinGrant(grant: unknown, agent: unknown): boolean {
  if (grant === undefined || grant === null) return true;
  // The grant carries required bounds, but the agent supplied absent,
  // null, or otherwise malformed params (e.g. omitted entirely or {}).
  // This is a required-key omission and MUST NOT be treated as "within" (F8).
  if (agent === undefined || agent === null) return false;
  return paramsWithin(grant, agent);
}

function paramsWithin(grant: unknown, agent: unknown): boolean {
  if (isPlainObject(grant)) {
    if (!isPlainObject(agent)) return false;
    for (const k of Object.keys(agent)) {
      if (!(k in grant)) return false;
      if (!paramsWithin((grant as Record<string, unknown>)[k], (agent as Record<string, unknown>)[k])) return false;
    }
    // Every key the grant requires MUST be present in the agent; dropping a
    // bound/required parameter is an authorization escape (F8).
    for (const k of Object.keys(grant)) {
      if (!(k in agent)) return false;
    }
    return true;
  }
  if (typeof grant === "number") {
    return typeof agent === "number" && agent <= grant;
  }
  if (typeof grant === "string") return agent === grant;
  if (typeof grant === "boolean") return agent === grant;
  if (Array.isArray(grant)) {
    if (!Array.isArray(agent)) return false;
    for (const x of agent) {
      if (!grant.some((y) => stableStringify(y) === stableStringify(x))) return false;
    }
    return true;
  }
  return stableStringify(grant) === stableStringify(agent);
}

export function stableStringify(v: unknown): string {
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  if (isPlainObject(v)) {
    const keys = Object.keys(v).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(v[k])).join(",") + "}";
  }
  return JSON.stringify(v);
}

function capabilitySubset(agent: Capability, grants: Capability[]): boolean {
  const target = capPattern(agent);
  let best = 0;
  for (const g of grants) {
    const r = matchPattern(capPattern(g), target);
    if (!r.matched || r.score <= best) continue;
    if (!paramsWithinGrant(g.params, agent.params)) continue;
    best = r.score;
  }
  return best > 0;
}

// ---- constraints (draft Section 7) ---------------------------------------

function ipv4ToInt(s: string): number | null {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  let v = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    v = v * 256 + n;
  }
  return v >>> 0;
}

function ipv6ToBigInt(s: string): bigint | null {
  let head: string[] = [];
  let tail: string[] = [];
  const dbl = s.indexOf("::");
  if (dbl >= 0) {
    head = s.slice(0, dbl).split(":").filter(Boolean);
    tail = s.slice(dbl + 2).split(":").filter(Boolean);
  } else {
    head = s.split(":");
  }
  const all = [...head, ...tail];
  if (all.length > 8) return null;
  const missing = 8 - all.length;
  let v = 0n;
  let idx = 0;
  for (const h of head) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    v = (v << 16n) | BigInt(parseInt(h, 16));
    idx++;
  }
  for (let i = 0; i < missing; i++) {
    v = v << 16n;
    idx++;
  }
  for (const t of tail) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(t)) return null;
    v = (v << 16n) | BigInt(parseInt(t, 16));
    idx++;
  }
  return idx === 8 ? v : null;
}

function cidrContains(ip: string, cidr: string): boolean {
  if (cidr.includes("/")) {
    const [net, lenS] = cidr.split("/");
    const len = Number(lenS);
    if (ip.includes(":")) {
      const ipv = ipv6ToBigInt(ip);
      const netv = ipv6ToBigInt(net);
      if (ipv === null || netv === null || len < 0 || len > 128) return false;
      const mask = len === 0 ? 0n : (0xffffffffffffffffffffffffffffffffn << BigInt(128 - len)) & 0xffffffffffffffffffffffffffffffffn;
      return (ipv & mask) === (netv & mask);
    }
    const ipv = ipv4ToInt(ip);
    const netv = ipv4ToInt(net);
    if (ipv === null || netv === null || len < 0 || len > 32) return false;
    const mask = len === 0 ? 0 : (~0 << (32 - len)) >>> 0;
    return (ipv & mask) === (netv & mask);
  }
  return ip === cidr;
}

function evalAllowedCIDR(c: Capability, ctx: RequestContext): void {
  const cidrs = c.params as string[];
  if (!Array.isArray(cidrs)) throw new Error("allowed-cidr: params must be an array of CIDR strings");
  if (!ctx.sourceIP) throw new Error("allowed-cidr: no source IP in request context");
  for (const cidr of cidrs) {
    if (cidrContains(ctx.sourceIP, cidr)) return;
  }
  throw new Error(`allowed-cidr: source IP ${ctx.sourceIP} not in allowed ranges`);
}

function evalMaxConcurrent(c: Capability, ctx: RequestContext): void {
  const p = c.params as { max?: number };
  if (!p || typeof p.max !== "number" || p.max < 1) throw new Error("max-concurrent: params must be {max: N} with N >= 1");
  const count = ctx.concurrentCount ?? 0;
  if (count >= p.max) throw new Error(`max-concurrent: concurrent count ${count} exceeds max ${p.max}`);
}

function evalTimeWindow(c: Capability, ctx: RequestContext): void {
  const p = c.params as { start?: string; end?: string };
  if (!p || typeof p.start !== "string" || typeof p.end !== "string") {
    throw new Error("time-window: params must be {start: HH:MM, end: HH:MM}");
  }
  const parse = (s: string): number => {
    const m = /^(\d{2}):(\d{2})$/.exec(s);
    if (!m) throw new Error(`time-window: invalid HH:MM ${s}`);
    return Number(m[1]) * 60 + Number(m[2]);
  };
  const start = parse(p.start);
  const end = parse(p.end);
  const now = ctx.now;
  const cur = now.getUTCHours() * 60 + now.getUTCMinutes();
  if (start <= end) {
    if (cur < start || cur > end) throw new Error(`time-window: now outside [${p.start},${p.end}]`);
  } else if (cur < start && cur > end) {
    throw new Error(`time-window: now outside overnight window [${p.start},${p.end}]`);
  }
}

export const BUILTIN_CONSTRAINTS: Record<string, (c: Capability, ctx: RequestContext) => void> = {
  "allowed-cidr": evalAllowedCIDR,
  "max-concurrent": evalMaxConcurrent,
  "time-window": evalTimeWindow,
};

export function evaluateConstraints(cs: Capability[], ctx: RequestContext, strict: boolean): string[] {
  const notes: string[] = [];
  for (const c of cs) {
    if (c.scheme !== CONSTRAINT_SCHEME) {
      throw new Error(`constraint scheme ${c.scheme} not allowed (must be ${CONSTRAINT_SCHEME})`);
    }
    const eval_ = BUILTIN_CONSTRAINTS[c.id];
    if (!eval_) {
      if (strict) throw new Error(`unknown constraint type ${c.id} (strict mode)`);
      notes.push(`audit: unknown constraint type ${c.id} ignored`);
      continue;
    }
    eval_(c, ctx);
  }
  return notes;
}

// ---- validation pipeline (draft Section 11) ------------------------------

function checkHeader(h: Header, expectedTyp: string): void {
  if (h.typ !== expectedTyp) throw new Error(`unexpected typ ${h.typ} (expected ${expectedTyp})`);
  if (!h.alg || h.alg === "none") throw new Error("alg missing or none");
  if (!ALLOWED_ALGS.has(h.alg)) throw new Error(`alg ${h.alg} not in allowlist`);
  if (!h.kid) throw new Error("kid required");
  if (h.crit && h.crit.length > 0) throw new Error(`unsupported critical header ${h.crit[0]}`);
}

function audienceList(a: Audience): string[] {
  return Array.isArray(a) ? a : [a];
}

function checkOuterRequired(o: OuterClaims): void {
  if (!o.iss) throw new Error("iss required");
  if (!o.sub || o.sub.length > 256) throw new Error("sub (agentId) required, 1..256 chars");
  if (audienceList(o.aud).length === 0) throw new Error("aud required");
  if (audienceList(o.aud).some((a) => !a)) throw new Error("aud must not contain empty strings");
  if (!o.iat || !o.exp || o.exp <= o.iat) throw new Error("iat/exp required and exp must be after iat");
  if (!o.jti) throw new Error("jti required");
  if (!o.cnf || !o.cnf.jkt) throw new Error("cnf required");
  if (!o.aic) throw new Error("aic claim required");
  if (o.aic.ver !== 1) throw new Error("aic.ver must be 1");
  const p = o.aic.principal;
  if (!p || !p.realm || p.realm.length > 128 || !p.id || p.id.length > 256 || !p.key_hash) {
    throw new Error("aic.principal realm/id/key_hash required within size limits");
  }
  const ha = p.hash_alg || "sha-256";
  if (!["sha-256", "sha-384", "sha-512", "jkt"].includes(ha)) {
    throw new Error(`unsupported aic.principal.hash_alg ${p.hash_alg}`);
  }
  if (o.aic.delegation_mode !== MODE_AUTHORIZED && o.aic.delegation_mode !== MODE_REPRESENTATIVE) {
    throw new Error(`aic.delegation_mode must be ${MODE_AUTHORIZED} or ${MODE_REPRESENTATIVE}`);
  }
  if (!o.aic.capabilities || o.aic.capabilities.length < 1 || o.aic.capabilities.length > 256) {
    throw new Error("aic.capabilities must contain 1..256 entries");
  }
  for (const c of o.aic.capabilities) {
    if (c.params != null && JSON.stringify(c.params).length > MAX_PARAMS_SIZE) throw new Error(`aic.capabilities params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
  if (o.aic.constraints && o.aic.constraints.length > 32) throw new Error("aic.constraints must not exceed 32 entries");
  for (const c of o.aic.constraints ?? []) {
    if (c.params != null && JSON.stringify(c.params).length > MAX_PARAMS_SIZE) throw new Error(`aic.constraints params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
}

function checkDARequired(d: DAClaims): void {
  if (d.ver !== 2) throw new Error("DA ver must be 2");
  if (!d.iss || d.iss.length > 256) throw new Error("DA iss required, 1..256 chars");
  if (!d.sub || d.sub.length > 256) throw new Error("DA sub required, 1..256 chars");
  if (!d.aud || d.aud.length < 1) throw new Error("DA aud required");
  const audList = Array.isArray(d.aud) ? d.aud : [d.aud];
  if (audList.some((a) => !a)) throw new Error("DA aud must not contain empty strings");
  if (!d.exp) throw new Error("DA exp required");
  if (!d.jti || d.jti.length > 128) throw new Error("DA jti required, 1..128 chars");
  if (!d.agent_id || d.agent_id.length > 256) throw new Error("DA agent_id required, 1..256 chars");
  if (!d.principal || !d.principal.realm || !d.principal.id || !d.principal.key_hash) throw new Error("DA principal required");
  if (!d.reason || !d.reason.code || !d.reason.desc) throw new Error("DA reason.code and reason.desc required");
  if (!d.capabilities || d.capabilities.length < 1 || d.capabilities.length > 256) throw new Error("DA capabilities invalid");
  for (const c of d.capabilities) {
    if (c.params != null && JSON.stringify(c.params).length > MAX_PARAMS_SIZE) throw new Error(`DA capabilities params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
  if (d.delegation_mode !== MODE_AUTHORIZED && d.delegation_mode !== MODE_REPRESENTATIVE) throw new Error("DA delegation_mode invalid");
  if (d.constraints && d.constraints.length > 32) throw new Error("DA constraints must not exceed 32 entries");
  for (const c of d.constraints ?? []) {
    if (c.params != null && JSON.stringify(c.params).length > MAX_PARAMS_SIZE) throw new Error(`DA constraints params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
  if (!Number.isInteger(d.requested_lifetime) || d.requested_lifetime < 1 || d.requested_lifetime > MAX_LIFETIME) {
    throw new Error(`DA requested_lifetime must be in 1..${MAX_LIFETIME}`);
  }
  if (!d.ts) throw new Error("DA ts required");
  if (!d.nonce) throw new Error("DA nonce required");
  if (d.jti !== d.nonce) throw new Error("DA jti must equal nonce");
  // A zero iat is treated as absent (Go parity: a missing iat maps to
  // zero in a non-pointer int64).
  if (d.iat != null && d.iat !== 0 && d.iat !== d.ts) throw new Error("DA iat must equal ts when present");
}

async function resolvePrincipalKey(p: Principal, kid: string | undefined, opts: VerifyOptions): Promise<CryptoKey> {
  if (opts.principalJWKS && kid && opts.principalJWKS[kid]) return opts.principalJWKS[kid];
  if (opts.principalJWKS) {
    for (const k of Object.values(opts.principalJWKS)) {
      const alg = p.hash_alg || "sha-256";
      const h = await keyHashOf(k, alg);
      if (h === p.key_hash) return k;
    }
  }
  throw new Error(`principal key not resolvable (kid ${kid ?? "none"})`);
}

export async function validateDA(daToken: string, opts: VerifyOptions): Promise<DAClaims> {
  const { header, payload } = parseCompact(daToken);
  checkHeader(header, TYP_DA);
  const da = payload as DAClaims;
  checkDARequired(da);
  const expectedExp = da.ts + da.requested_lifetime;
  if (da.exp !== expectedExp) throw new Error(`DA exp ${da.exp} must equal ts+requested_lifetime ${expectedExp}`);
  const nowSec = Math.floor((opts.now ? opts.now.getTime() : Date.now()) / 1000);
  if (nowSec > da.exp) throw new Error(`DA expired (exp ${da.exp})`);
  const principalSubject = `${da.principal.realm}:${da.principal.id}`;
  if (da.iss !== principalSubject) throw new Error(`DA iss ${da.iss} != principal ${principalSubject}`);
  if (da.delegation_mode === MODE_AUTHORIZED) {
    if (da.sub !== da.agent_id) throw new Error(`authorized mode: DA sub ${da.sub} must be the agent ${da.agent_id}`);
  } else if (da.delegation_mode === MODE_REPRESENTATIVE) {
    if (da.sub !== principalSubject) throw new Error(`representative mode: DA sub ${da.sub} must be the resource owner ${principalSubject}`);
  }
  // F6: reject a stale DA whose ts is older than the requested_lifetime.
  // A replayed DA signed long ago (but with an unused nonce) must not pass.
  const rl = da.requested_lifetime;
  if (Number.isInteger(rl) && rl > 0 && typeof da.ts === "number") {
    const nowMs = opts.now ? opts.now.getTime() : Date.now();
    const now = Math.floor(nowMs / 1000);
    if (now - da.ts > rl) throw new Error("DA ts is stale");
  }
  const pub = await resolvePrincipalKey(da.principal, header.kid, opts);
  await verifyCompact(daToken, header.alg, pub);
  const alg = da.principal.hash_alg || "sha-256";
  const binding = await keyHashOf(pub, alg);
  if (binding !== da.principal.key_hash) throw new Error("DA principal key_hash mismatch");
  const nb = b64uDecode(da.nonce);
  if (nb.length !== 32) throw new Error("DA nonce must be the base64url of 32 bytes");
  if (opts.nonceStore) await opts.nonceStore.checkAndAdd(da.nonce);
  return da;
}

function checkConsistency(o: OuterClaims, da: DAClaims): void {
  if (da.delegation_mode === MODE_REPRESENTATIVE) {
    const psub = `${da.principal.realm}:${da.principal.id}`;
    if (o.sub !== da.sub || o.sub !== psub) throw new Error(`representative mode: outer sub ${o.sub} must be the resource owner ${da.sub}`);
    if (!o.act || o.act.sub !== da.agent_id) throw new Error(`representative mode: outer act must carry the agent ${da.agent_id}`);
  } else {
    if (da.agent_id !== o.sub) throw new Error(`DA agent_id ${da.agent_id} != outer sub ${o.sub}`);
    if (o.act) throw new Error("authorized mode: outer act must be absent");
  }
  if (stableStringify(da.principal) !== stableStringify(o.aic.principal)) throw new Error("DA principal != outer aic.principal");
  if (da.delegation_mode !== o.aic.delegation_mode) throw new Error("DA delegation_mode != outer aic.delegation_mode");
  if (stableStringify(da.capabilities) !== stableStringify(o.aic.capabilities)) throw new Error("DA capabilities != outer aic.capabilities");
  if (stableStringify(da.constraints ?? []) !== stableStringify(o.aic.constraints ?? [])) throw new Error("DA constraints != outer aic.constraints");
}

function checkPA(o: OuterClaims, opts: VerifyOptions): void {
  const pa = opts.pa;
  if (!pa) throw new Error("representative mode requires PrincipalAuthorization material");
  if (pa.ver !== 1) throw new Error("PA ver must be 1");
  if (stableStringify(pa.principal) !== stableStringify(o.aic.principal)) throw new Error("PA principal != outer aic.principal");
  if (!pa.delegation_policy || pa.delegation_policy.allowed_mode !== ALLOWED_MODE_REPRESENTATIVE) {
    throw new Error("delegation policy does not allow representative mode");
  }
  for (const c of o.aic.capabilities) {
    if (!capabilitySubset(c, pa.grants)) {
      throw new Error(`capability ${c.scheme}:${c.id} not within P_grants`);
    }
  }
  for (const g of pa.grants) {
    if (g.params != null && JSON.stringify(g.params).length > MAX_PARAMS_SIZE) throw new Error(`PA grants params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
  for (const c of pa.constraints ?? []) {
    if (c.params != null && JSON.stringify(c.params).length > MAX_PARAMS_SIZE) throw new Error(`PA constraints params exceed ${MAX_PARAMS_SIZE} bytes`);
  }
}

function checkDepth(a: AICClaims, rejectDepthGT1: boolean): void {
  const cd = a.chain_depth ?? 0;
  const md = a.max_depth ?? 0;
  if (cd < 0 || cd > 255 || md < 0 || md > 255) throw new Error("chain_depth/max_depth out of range");
  if (cd > md) throw new Error(`chain_depth ${cd} exceeds max_depth ${md}`);
  if (rejectDepthGT1 && md > 1) throw new Error(`max_depth ${md} exceeds recommended limit 1`);
}

export async function validate(token: string, opts: VerifyOptions): Promise<Decision> {
  // Step 1+2: parse, header checks, outer signature.
  const { header, payload } = parseCompact(token);
  checkHeader(header, TYP_OUTER);
  const issuerKey = opts.issuerKeys[header.kid ?? ""];
  if (!issuerKey) throw new Error(`step2: unknown issuer kid ${header.kid}`);
  await verifyCompact(token, header.alg, issuerKey);
  const outer = payload as OuterClaims;
  checkOuterRequired(outer);

  // Step 3: time.
  const now = Math.floor(opts.now.getTime() / 1000);
  if (outer.nbf !== undefined && now < outer.nbf) throw new Error("step3: token not yet valid (nbf)");
  if (now > outer.exp) throw new Error("step3: token expired");

  // Step 4: DA.
  let da: DAClaims | undefined;
  if (outer.da) {
    da = await validateDA(outer.da, opts);
    if (opts.requireJtiNonceMatch && outer.jti !== da.nonce) throw new Error("step4: outer jti does not match DA nonce");
    if (outer.exp - outer.iat > da.requested_lifetime) throw new Error("step4: token lifetime exceeds DA requested_lifetime");
    if (outer.exp > da.exp) throw new Error("step4: outer exp exceeds DA exp");
    if (!audienceList(da.aud).includes(outer.iss)) throw new Error("step4: DA aud does not include outer iss");
  } else if (outer.aic.delegation_mode === MODE_REPRESENTATIVE) {
    throw new Error("step4: representative mode requires a DA JWT");
  } else if (outer.exp - outer.iat > MAX_LIFETIME) {
    throw new Error("step3: lightweight profile lifetime exceeds max");
  }

  // Step 5: consistency.
  if (da) checkConsistency(outer, da);

  // Step 6: PA (representative).
  if (outer.aic.delegation_mode === MODE_REPRESENTATIVE) checkPA(outer, opts);

  // Step 7: constraints.
  const ctx: RequestContext = opts.requestContext ?? { now: opts.now };
  const notes = evaluateConstraints(outer.aic.constraints ?? [], ctx, opts.constraintStrict ?? false);

  // Step 8: depth.
  checkDepth(outer.aic, opts.rejectDepthGT1 ?? false);

  // Step 9: capability evaluation.
  if (opts.requestCapability) {
    if (!matchCapabilities(outer.aic.capabilities, opts.requestCapability)) {
      throw new Error(`step9: capability ${opts.requestCapability.scheme}:${opts.requestCapability.id} not allowed`);
    }
    const plugin = opts.capabilityPlugins?.[opts.requestCapability.scheme];
    if (!plugin) throw new Error(`step9: unknown capability scheme ${opts.requestCapability.scheme} (fail-closed)`);
    await plugin(opts.requestCapability, ctx);
  }

  // Step 10: status.
  if (outer.status) {
    if (!opts.statusChecker) throw new Error("step10: status claim present but no status checker configured");
    await opts.statusChecker(outer.status);
  }

  // Issuer / audience / presenter binding.
  if (opts.expectedIssuer && outer.iss !== opts.expectedIssuer) throw new Error(`iss mismatch`);
  if (opts.expectedAudience && opts.expectedAudience.length > 0) {
    const auds = audienceList(outer.aud);
    if (!opts.expectedAudience.some((a) => auds.includes(a))) throw new Error("aud mismatch (audience confusion)");
  }
  if (opts.presenterKey) {
    const thumb = await keyHashOf(opts.presenterKey, "jkt");
    if (thumb !== outer.cnf.jkt) throw new Error("cnf: presenter key does not match token cnf.jkt (token theft)");
  }

  // Audit actor per draft Section 8.1: in representative mode the
  // principal is recorded as the actor and the agent as the executor.
  // This is distinct from the RFC 8693 `act` claim (outer.act), which
  // names the executing agent on tokens whose subject is the resource
  // owner.
  const actor = outer.aic.delegation_mode === MODE_REPRESENTATIVE ? outer.aic.principal.id : outer.sub;
  const executor = outer.act?.sub ?? outer.sub;
  return {
    permit: true,
    actor,
    executor,
    principal: outer.aic.principal.id,
    capabilities: outer.aic.capabilities,
    notes,
  };
}

// ---- DPoP (RFC 9449) -----------------------------------------------------

export interface DPoPClaims {
  htm: string;
  htu: string;
  jti: string;
  iat: number;
  ath?: string;
}

export async function buildDPoP(
  keyPair: CryptoKeyPair,
  alg: string,
  htm: string,
  htu: string,
  accessToken: string,
  now: Date,
): Promise<{ proof: string; claims: DPoPClaims }> {
  // The proof header carries the PUBLIC key only (RFC 9449).
  const jwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  delete (jwk as { key_ops?: unknown }).key_ops;
  const ath = b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(accessToken))));
  const claims: DPoPClaims = { htm, htu, jti: randomID(), iat: Math.floor(now.getTime() / 1000), ath };
  const proof = await signCompact({ alg, typ: "dpop+jwt", jwk }, claims, keyPair.privateKey);
  return { proof, claims };
}

export async function verifyDPoP(
  proof: string,
  accessToken: string,
  htm: string,
  htu: string,
  now: Date,
  replay?: NonceStore,
): Promise<CryptoKey> {
  const { header, payload } = parseCompact(proof);
  if (!header.jwk) throw new Error("dpop: header jwk required");
  // Strip key_ops: the proof JWK is exported from a sign-capable key,
  // and the verifier only needs "verify".
  const jwk = { ...header.jwk };
  delete (jwk as { key_ops?: unknown }).key_ops;
  const key = await crypto.subtle.importKey(
    "jwk",
    jwk,
    importKeyAlgorithm(header.alg),
    true,
    ["verify"],
  );
  await verifyCompact(proof, header.alg, key);
  const c = payload as DPoPClaims;
  if (c.htm !== htm) throw new Error("dpop: htm mismatch");
  if (c.htu !== htu) throw new Error("dpop: htu mismatch");
  const ath = b64uEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(accessToken))));
  if (c.ath && c.ath !== ath) throw new Error("dpop: ath mismatch");
  const iatMs = c.iat * 1000;
  if (Math.abs(now.getTime() - iatMs) > 5 * 60 * 1000) throw new Error("dpop: iat outside freshness window");
  if (replay) await replay.checkAndAdd(c.jti);
  return key;
}

function importKeyAlgorithm(alg: string): RsaHashedImportParams | EcKeyImportParams | Algorithm {
  switch (alg) {
    case "ES256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "RS256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    case "PS256":
      return { name: "RSA-PSS", hash: "SHA-256" };
    case "PS384":
      return { name: "RSA-PSS", hash: "SHA-384" };
    case "PS512":
      return { name: "RSA-PSS", hash: "SHA-512" };
    case "EdDSA":
      return { name: "Ed25519" };
    default:
      throw new Error(`algorithm ${alg} not supported`);
  }
}

function randomID(): string {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return b64uEncode(b);
}
