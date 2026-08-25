// Delegation: the agent builds an issuance request (with a 32-byte
// nonce), the human reviews it and signs the DelegationAuthorization
// (DA) JWT. This is draft Section 10.1 "PKI Mode" steps 1-2, executed
// entirely in the browser.
import { t } from "./i18n.ts";
import {
  MODE_REPRESENTATIVE,
  TYP_DA,
  b64uEncode,
  matchPattern,
  paramsWithinGrant,
  signCompact,
} from "../../../ts/aicjwt.ts";
import type { Capability, DAClaims, Reason } from "../../../ts/aicjwt.ts";
import { DEMO_ALG } from "./types.ts";
import type {
  AgentIdentity,
  DAApproval,
  DelegationRequest,
  HumanIdentity,
} from "./types.ts";

export interface SubsetCheck {
  ok: boolean;
  rejected: Capability[];
}

/**
 * Capability-level and parameter-level subset check (draft Sections
 * 6.2/6.3): every requested capability must match some grant, with
 * requested params inside the grant's params.
 */
export function capsWithinGrants(
  grants: Capability[],
  requested: Capability[],
): SubsetCheck {
  const rejected = requested.filter((r) => {
    for (const g of grants) {
      const m = matchPattern(g.id, r.id);
      if (m.matched && paramsWithinGrant(g.params, r.params)) return false;
    }
    return true;
  });
  return { ok: rejected.length === 0, rejected };
}

export async function createAgentIdentity(
  opts: { id?: string; displayName?: string } = {},
): Promise<AgentIdentity> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    id: opts.id ?? "agent:data-analyst-01",
    displayName: opts.displayName ?? t("identity.agentDisplayName"),
    keyPair,
  };
}

export function buildDelegationRequest(opts: {
  agent: AgentIdentity;
  capabilities: Capability[];
  reason?: Reason;
  requestedLifetime?: number;
  now?: Date;
}): DelegationRequest {
  const nonceBytes = new Uint8Array(32);
  crypto.getRandomValues(nonceBytes);
  return {
    agent: opts.agent,
    capabilities: opts.capabilities,
    reason: opts.reason ?? {
      code: "DATA_ANALYSIS",
      desc: t("delegation.reasonDesc"),
    },
    requestedLifetime: opts.requestedLifetime ?? 3600,
    nonce: b64uEncode(nonceBytes),
    ts: Math.floor((opts.now ?? new Date()).getTime() / 1000),
  };
}

/** The human reviews the request and signs the DA JWT. */
export async function approveDelegation(
  human: HumanIdentity,
  req: DelegationRequest,
  opts: { constraints?: Capability[]; now?: Date } = {},
): Promise<DAApproval> {
  const claims: DAClaims = {
    ver: 1,
    agent_id: req.agent.id,
    principal: human.claims.principal,
    reason: req.reason,
    capabilities: req.capabilities,
    delegation_mode: MODE_REPRESENTATIVE,
    constraints: opts.constraints,
    requested_lifetime: req.requestedLifetime,
    ts: req.ts,
    nonce: req.nonce,
  };
  const token = await signCompact(
    { alg: DEMO_ALG, typ: TYP_DA, kid: human.kid },
    claims,
    human.keyPair.privateKey,
  );
  return { token, claims };
}
