// Demo CA: simulates the certificate authority of draft Section 10.1
// (PKI Mode steps 3-5). It validates the human-signed DA (signature,
// key binding, nonce), enforces least privilege (delegated
// capabilities must be a subset of P_grants), then issues and signs
// the outer AIC-JWT -- the "agent certificate".
import { t } from "./i18n.ts";
import {
  ALLOWED_MODE_REPRESENTATIVE,
  MAX_LIFETIME,
  MODE_REPRESENTATIVE,
  TYP_OUTER,
  keyHashOf,
  signCompact,
  validateDA,
} from "../../../ts/aicjwt.ts";
import type { OuterClaims } from "../../../ts/aicjwt.ts";
import { capsWithinGrants } from "./delegation.ts";
import { DEMO_ALG } from "./types.ts";
import type {
  AgentCertificate,
  AgentIdentity,
  DAApproval,
  DemoCA,
  HumanIdentity,
} from "./types.ts";

export async function createDemoCA(
  opts: { issuer?: string; kid?: string } = {},
): Promise<DemoCA> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    issuer: opts.issuer ?? "https://demo-ca.example.com/aic",
    kid: opts.kid ?? "demo-ca-2026",
    keyPair,
  };
}

export async function issueAgentCertificate(opts: {
  ca: DemoCA;
  human: HumanIdentity;
  agent: AgentIdentity;
  da: DAApproval;
  audience?: string | string[];
  now?: Date;
}): Promise<AgentCertificate> {
  const now = opts.now ?? new Date();
  const nowSec = Math.floor(now.getTime() / 1000);

  // PKI Mode step 3: CA validates the DA signed by the human.
  const da = await validateDA(opts.da.token, {
    now,
    issuerKeys: {},
    principalJWKS: { [opts.human.kid]: opts.human.keyPair.publicKey },
  });

  const policy = opts.human.claims.delegation_policy;
  if (policy?.allowed_mode !== ALLOWED_MODE_REPRESENTATIVE) {
    throw new Error(t("err.caPolicy"));
  }
  // PKI Mode step 4: delegated capabilities must fit P_grants.
  const subset = capsWithinGrants(opts.human.claims.grants, da.capabilities);
  if (!subset.ok) {
    throw new Error(
      t("err.caSubset") +
        subset.rejected.map((c) => `${c.scheme}:${c.id}`).join(t("sep")),
    );
  }

  // PKI Mode step 5: CA constructs and signs the outer AIC-JWT.
  const lifetime = Math.min(da.requested_lifetime, MAX_LIFETIME);
  const rep = da.delegation_mode === MODE_REPRESENTATIVE;
  const subject = rep ? `${da.principal.realm}:${da.principal.id}` : da.agent_id;
  const claims: OuterClaims = {
    iss: opts.ca.issuer,
    sub: subject,
    aud: opts.audience ?? "https://gw.example.com",
    iat: nowSec,
    exp: nowSec + lifetime,
    jti: da.nonce,
    cnf: { jkt: await keyHashOf(opts.agent.keyPair.publicKey, "jkt") },
    aic: {
      ver: 1,
      principal: da.principal,
      delegation_mode: da.delegation_mode,
      capabilities: da.capabilities,
      constraints: da.constraints ?? [],
      chain_depth: 0,
      max_depth: 1,
    },
    da: opts.da.token,
  };
  if (rep) claims.act = { sub: da.agent_id };
  const token = await signCompact(
    { alg: DEMO_ALG, typ: TYP_OUTER, kid: opts.ca.kid },
    claims,
    opts.ca.keyPair.privateKey,
  );
  return { token, claims, da };
}

/** Flip one character of the signature segment (tampering demo). */
export function tamperToken(token: string): string {
  const parts = token.split(".");
  const sig = parts[2];
  const idx = Math.floor(sig.length / 2);
  const ch = sig[idx] === "A" ? "B" : "A";
  parts[2] = sig.slice(0, idx) + ch + sig.slice(idx + 1);
  return parts.join(".");
}

/** Re-issue an expired copy of the certificate (expiration demo). */
export async function expiredCopy(
  cert: AgentCertificate,
  opts: { ca: DemoCA; now: Date },
): Promise<string> {
  const nowSec = Math.floor(opts.now.getTime() / 1000);
  const claims: OuterClaims = {
    ...cert.claims,
    iat: nowSec - 600,
    exp: nowSec - 60,
  };
  return signCompact(
    { alg: DEMO_ALG, typ: TYP_OUTER, kid: opts.ca.kid },
    claims,
    opts.ca.keyPair.privateKey,
  );
}
