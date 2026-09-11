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

/** deepEqual 按 JSON 值做深层精确相等（用于数组（enum）成员判定；数字精确比较）。 */
function deepEqual(a: any, b: any): boolean {
  if (a === b) {
    return true;
  }
  if (typeof a !== typeof b) {
    return false;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    if (a.length !== b.length) {
      return false;
    }
    return a.every((x, i) => deepEqual(x, b[i]));
  }
  if (a !== null && b !== null && typeof a === "object" && typeof b === "object") {
    const ka = Object.keys(a).sort();
    const kb = Object.keys(b).sort();
    if (ka.length !== kb.length) {
      return false;
    }
    return ka.every((k, i) => k === kb[i] && deepEqual(a[k], b[k]));
  }
  return false;
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
    // CLC-v1 §6.2 (v1.1) enum 语义：grant 数组 = 允许值集合（允许集合）。
    // agent 可给标量（须为成员）或数组（每个元素须为成员）；空集合不允许任何值。
    //（aligned to CLC-v1 §6.2 v1.1 on 2026-09-11）
    if (grant.length === 0) {
      return false;
    }
    const member = (v: any): boolean =>
      (grant as any[]).some((gm) => deepEqual(v, gm));
    if (Array.isArray(agent)) {
      return (agent as any[]).every((e) => member(e));
    }
    return member(agent);
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