// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// TS 版类型：与 go/types.go 同名字段/结构（Go 与 TS 必须一致）。

export interface Capability {
  scheme: string;
  id: string;
  params?: any;
}

export interface Constraint {
  type: string;
  params?: any;
}

export interface Principal {
  realm: string;
  id: string;
  key_hash: string; // base64url(SHA-256(SPKI DER))
  hash_alg: string; // "sha-256"
}

export interface Reason {
  code: string;
  desc: string;
}

export interface DA {
  ver: number;
  agent_id: string;
  principal: Principal;
  reason: Reason;
  capabilities: Capability[];
  delegation_mode: "authorized" | "representative";
  constraints: Constraint[];
  requested_lifetime: number; // 1..86400 秒
  ts: number;
  nonce: string; // 32 字节 base64url 无填充
}

export interface PA {
  ver: number;
  principal: Principal;
  grants: Capability[];
  constraints: Constraint[];
}

export interface WITGrant {
  spiffe_id: string;
  wit_svid: string;
  wit_private_key: ECJWK;
  kid: string;
  entitlement: Capability[];
  exp: number;
}

export interface Request {
  method: string;
  target_uri: string; // http/https，无 query/fragment
  body?: Uint8Array;
  requested_capability?: Capability;
  now: number;
}

export interface CheckResult {
  step: string;
  ok: boolean;
  detail: string;
}

export interface Decision {
  permit: boolean;
  reason: string;
  checks: CheckResult[];
}

export type { ECJWK } from "./jwk.ts";