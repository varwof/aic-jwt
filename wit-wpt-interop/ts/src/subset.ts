// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// TS 版 subset：C_agent ⊆ P_grants 的 scheme-specific 判定。语义与 go/subset.go
// 一致（id 通配 *、**、{a,b}、[a-z]，段内匹配；params 递归子集；未知约束
// fail-closed）。SUBSET-EXT 标记处即按 scheme 定义的扩展点。

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
  // SUBSET-EXT：段数不同时回退整串匹配（允许 ** 跨段）。
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
      const body = pat.slice(i + 1, end);
      const parts = body.split(",");
      const alts: string[] = [];
      for (const p of parts) {
        if (!LIT_RE.test(p)) {
          return undefined;
        }
        // 只允许 {a,b} 字面量；内含 * 时按单段通配处理
        alts.push(p.replaceAll("*", "[^/]*"));
      }
      b += `(?:${alts.join("|")})`;
      i = end;
    } else if (c === "[") {
      const end = pat.indexOf("]", i);
      if (end < 0) {
        return undefined;
      }
      const cls = pat.slice(i, end + 1);
      if (!validClass(cls)) {
        return undefined;
      }
      b += cls;
      i = end;
    } else {
      if (!/^[\w:\-\.\*]$/.test(c)) {
        return undefined;
      }
      b += c.replaceAll(/[\\^$.*+?()[\]{}|]/g, "\\$&");
    }
  }
  return b + "$";
}

function validClass(cls: string): boolean {
  if (cls.length < 3 || cls[0] !== "[" || cls[cls.length - 1] !== "]") {
    return false;
  }
  const inner = cls.slice(1, -1);
  return /^[A-Za-z0-9\-_^]*$/.test(inner);
}

function number(v: any): number | undefined {
  if (typeof v === "number") {
    return v;
  }
  return undefined;
}

/** params 递归子集：number agent≤grant；array 元素 ∈；object 递归；其它精确相等。 */
export function paramsSubset(agent: any, grant: any): boolean {
  if (grant === null || grant === undefined) {
    return true;
  }
  if (typeof grant === "number") {
    const a = number(agent);
    return a !== undefined && a <= grant;
  }
  if (typeof grant === "string") {
    return agent === grant;
  }
  if (typeof grant === "boolean") {
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
  return Object.is(agent, grant);
}

/** capability subset：scheme 相等 + id 通配 + params subset。 */
export function capabilitySpecSubset(agent: Capability, grant: Capability): boolean {
  if (agent.scheme !== grant.scheme) {
    return false;
  }
  if (!matchID(grant.id, agent.id)) {
    return false;
  }
  return paramsSubset(agent.params, grant.params);
}

/** agent 能力集 ⊆ grants；detail 含 "subset" 供拒绝原因引用。 */
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

export type ConstraintValidator = (c: Constraint) => Error | undefined;

/** 已知约束（fail-closed：未知类型即拒）。SUBSET-EXT 在此登记新约束校验器。 */
const knownConstraintTypes: Record<string, ConstraintValidator> = {
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