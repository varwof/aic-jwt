// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 浏览器版 subset：C_agent ⊆ P_grants 判定 + 约束 fail-closed。
// 规则与 wit-wpt-interop（Go/TS）一致：id 通配（*、**、{a,b}、[a-z]，段内匹配），
// params 递归子集，未知约束 fail-closed。SUBSET-EXT 即按 scheme 定义处。

import type { Capability, Constraint } from "./types.ts";

export function matchID(pattern: string, id: string): boolean {
  if (pattern === "") {
    return pattern === id;
  }
  const psegs = pattern.split("/");
  const isegs = id.split("/");
  if (psegs.length === isegs.length) {
    for (let i = 0; i < psegs.length; i++) {
      const re = segmentRE(psegs[i]);
      if (!re || !re.test(isegs[i])) {
        return false;
      }
    }
    return true;
  }
  // SUBSET-EXT：段数不同回退整串匹配。
  const re = segmentRE(pattern);
  return !!re && re.test(id);
}

function segmentRE(seg: string): RegExp | undefined {
  const src = globToRegex(seg);
  if (src === undefined) {
    return undefined;
  }
  try {
    return new RegExp(src);
  } catch {
    return undefined;
  }
}

const LIT_RE = /^[A-Za-z0-9\-_\.:]*$/;

function globToRegex(pat: string): string | undefined {
  let b = "^";
  for (let i = 0; i < pat.length; i++) {
    const c = pat[i];
    if (c === "*") {
      if (pat[i + 1] === "*") {
        b += ".*";
        i++;
      } else {
        b += "[^/]*";
      }
    } else if (c === "{") {
      const end = pat.indexOf("}", i);
      if (end < 0) {
        return undefined;
      }
      const parts = pat.slice(i + 1, end).split(",");
      const alts: string[] = [];
      for (const p of parts) {
        if (!LIT_RE.test(p)) {
          return undefined;
        }
        alts.push(p.replace(/\*/g, "[^/]*"));
      }
      b += `(?:${alts.join("|")})`;
      i = end;
    } else if (c === "[") {
      const end = pat.indexOf("]", i);
      if (end < 0) {
        return undefined;
      }
      const cls = pat.slice(i, end + 1);
      if (!/^\[[A-Za-z0-9\-_^]+\]$/.test(cls)) {
        return undefined;
      }
      b += cls;
      i = end;
    } else {
      if (!/^[\w:\-\.\*]$/.test(c)) {
        return undefined;
      }
      b += c.replace(/[\\^$.*+?()[\]{}|]/g, "\\$&");
    }
  }
  return b + "$";
}

function number(v: any): number | undefined {
  return typeof v === "number" ? v : undefined;
}

export function paramsSubset(agent: any, grant: any): boolean {
  if (grant === null || grant === undefined) {
    return true;
  }
  if (typeof grant === "number") {
    const a = number(agent);
    return a !== undefined && a <= grant;
  }
  if (typeof grant === "string" || typeof grant === "boolean") {
    return agent === grant;
  }
  if (Array.isArray(grant)) {
    if (!Array.isArray(agent)) {
      return false;
    }
    return (agent as any[]).every((ag) =>
      (grant as any[]).some((gr) => paramsSubset(ag, gr)),
    );
  }
  if (typeof grant === "object") {
    if (typeof agent !== "object" || agent === null || Array.isArray(agent)) {
      return false;
    }
    for (const [k, gv] of Object.entries(grant)) {
      if (!(k in (agent as Record<string, unknown>))) {
        return false;
      }
      if (!paramsSubset((agent as Record<string, unknown>)[k], gv)) {
        return false;
      }
    }
    return true;
  }
  // SUBSET-EXT：未知类型按精确相等
  return agent === grant;
}

export function capabilitySpecSubset(agent: Capability, grant: Capability): boolean {
  if (agent.scheme !== grant.scheme) {
    return false;
  }
  if (!matchID(grant.id, agent.id)) {
    return false;
  }
  return paramsSubset(agent.params, grant.params);
}

export function capabilitiesCovered(
  agent: Capability[],
  grants: Capability[],
): { ok: boolean; detail: string } {
  for (const ac of agent) {
    const covered = grants.some((gr) => capabilitySpecSubset(ac, gr));
    if (!covered) {
      return {
        ok: false,
        detail: `subset: capability ${ac.scheme}:${ac.id} not covered by any grant`,
      };
    }
  }
  return { ok: true, detail: "subset ok" };
}

export function capabilityCoveredIn(
  req: Capability,
  entitlement: Capability[],
): { ok: boolean } {
  return capabilitiesCovered([req], entitlement);
}

const knownConstraintTypes: Record<string, (c: Constraint) => Error | undefined> = {
  max_rows: (c: Constraint): Error | undefined => {
    const n = number(c.params);
    if (n === undefined || n < 0) {
      return new Error("constraint max_rows requires a non-negative number");
    }
    return undefined;
  },
};

export function validateConstraints(cs: Constraint[]): void {
  for (const c of cs) {
    const fn = knownConstraintTypes[c.type];
    if (!fn) {
      throw new Error(`unknown constraint type ${c.type} (fail-closed)`);
    }
    const err = fn(c);
    if (err) {
      throw err;
    }
  }
}