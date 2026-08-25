// Scenario orchestration: builds a complete demo world (human ->
// DA -> CA -> certificate) and runs the verification lab scenarios.
import { t } from "./i18n.ts";
import {
  approveDelegation,
  buildDelegationRequest,
  createAgentIdentity,
} from "./delegation.ts";
import {
  createDemoCA,
  expiredCopy,
  issueAgentCertificate,
  tamperToken,
} from "./ca.ts";
import { createHumanIdentity } from "./identity.ts";
import type { Capability, VerifyOptions } from "../../../ts/aicjwt.ts";
import type {
  AgentCertificate,
  AgentIdentity,
  DAApproval,
  DemoCA,
  HumanIdentity,
  ScenarioId,
  ScenarioResult,
} from "./types.ts";
import { verifyAgentCertificate } from "./verify.ts";

export interface DemoWorld {
  human: HumanIdentity;
  agent: AgentIdentity;
  ca: DemoCA;
  da: DAApproval;
  certificate: AgentCertificate;
  constraints: Capability[];
  verifierBase: VerifyOptions;
  now: Date;
}

export const SCENARIO_META: Record<
  ScenarioId,
  { title: string; description: string }
> = {
  happy: {
    title: t("scenario.happy.title"),
    description: t("scenario.happy.desc"),
  },
  overreach: {
    title: t("scenario.overreach.title"),
    description: t("scenario.overreach.desc"),
  },
  expired: {
    title: t("scenario.expired.title"),
    description: t("scenario.expired.desc"),
  },
  tampered: {
    title: t("scenario.tampered.title"),
    description: t("scenario.tampered.desc"),
  },
  spoofed: {
    title: t("scenario.spoofed.title"),
    description: t("scenario.spoofed.desc"),
  },
  concurrency: {
    title: t("scenario.concurrency.title"),
    description: t("scenario.concurrency.desc"),
  },
};

/** Gateway keyring and expectations shared by every verification run. */
export function buildVerifierBase(opts: {
  human: HumanIdentity;
  agent: AgentIdentity;
  ca: DemoCA;
  now: Date;
}): VerifyOptions {
  return {
    now: opts.now,
    expectedIssuer: opts.ca.issuer,
    expectedAudience: ["https://gw.example.com"],
    issuerKeys: { [opts.ca.kid]: opts.ca.keyPair.publicKey },
    principalJWKS: { [opts.human.kid]: opts.human.keyPair.publicKey },
    presenterKey: opts.agent.keyPair.publicKey,
    pa: opts.human.claims,
    rejectDepthGT1: true,
    // The gateway registers a plugin for the "database" scheme
    // (fail-closed: unknown schemes are rejected by the core).
    capabilityPlugins: {
      database: (req) => {
        const p = req.params as { max_rows?: number } | undefined;
        if (p?.max_rows != null && p.max_rows > 1000) {
          throw new Error(`database: max_rows ${p.max_rows} exceeds 1000`);
        }
      },
    },
  };
}

export async function createDemoWorld(
  opts: { agentCapabilities?: Capability[]; now?: Date } = {},
): Promise<DemoWorld> {
  const now = opts.now ?? new Date();
  const human = await createHumanIdentity({ now });
  const agent = await createAgentIdentity();
  const ca = await createDemoCA();
  const capabilities = opts.agentCapabilities ?? [
    { scheme: "database", id: "query:SELECT", params: { max_rows: 100 } },
  ];
  const constraints: Capability[] = [
    {
      scheme: "varwof/constraint-v1",
      id: "max-concurrent",
      params: { max: 5 },
    },
  ];
  const request = buildDelegationRequest({ agent, capabilities, now });
  const da = await approveDelegation(human, request, { constraints, now });
  const certificate = await issueAgentCertificate({
    ca,
    human,
    agent,
    da,
    now,
  });
  return {
    human,
    agent,
    ca,
    da,
    certificate,
    constraints,
    verifierBase: buildVerifierBase({ human, agent, ca, now }),
    now,
  };
}

export async function runScenario(
  world: DemoWorld,
  id: ScenarioId,
): Promise<ScenarioResult> {
  const meta = SCENARIO_META[id];
  const base: VerifyOptions = { ...world.verifierBase, now: world.now };
  const queryCap: Capability = {
    scheme: "database",
    id: "query:SELECT",
    params: { max_rows: 100 },
  };

  switch (id) {
    case "happy": {
      const report = await verifyAgentCertificate(world.certificate.token, {
        ...base,
        requestCapability: queryCap,
        requestContext: { now: world.now, concurrentCount: 1 },
      });
      return { id, ...meta, report };
    }
    case "overreach": {
      const report = await verifyAgentCertificate(world.certificate.token, {
        ...base,
        requestCapability: { scheme: "database", id: "admin:drop", params: {} },
        requestContext: { now: world.now, concurrentCount: 1 },
      });
      return { id, ...meta, report };
    }
    case "expired": {
      const token = await expiredCopy(world.certificate, {
        ca: world.ca,
        now: world.now,
      });
      const report = await verifyAgentCertificate(token, {
        ...base,
        requestCapability: queryCap,
        requestContext: { now: world.now, concurrentCount: 1 },
      });
      return { id, ...meta, report };
    }
    case "tampered": {
      const token = tamperToken(world.certificate.token);
      const report = await verifyAgentCertificate(token, {
        ...base,
        requestCapability: queryCap,
        requestContext: { now: world.now, concurrentCount: 1 },
      });
      return { id, ...meta, report };
    }
    case "spoofed": {
      const spoof = await createAgentIdentity({
        id: "agent:attacker-01",
        displayName: t("identity.attackerDisplayName"),
      });
      const report = await verifyAgentCertificate(world.certificate.token, {
        ...base,
        presenterKey: spoof.keyPair.publicKey,
        requestCapability: queryCap,
        requestContext: { now: world.now, concurrentCount: 1 },
      });
      return { id, ...meta, report };
    }
    case "concurrency": {
      const report = await verifyAgentCertificate(world.certificate.token, {
        ...base,
        requestCapability: queryCap,
        requestContext: { now: world.now, concurrentCount: 6 },
      });
      return { id, ...meta, report };
    }
  }
}

export interface IssuanceRefusal {
  rejected: boolean;
  reason: string;
  request: Capability[];
}

/** Demonstrate the CA refusing an out-of-scope delegation at issuance. */
export async function demonstrateOutOfScopeIssuance(
  world: DemoWorld,
): Promise<IssuanceRefusal> {
  const overreachAgent = await createAgentIdentity({
    id: "agent:overreach-01",
    displayName: t("identity.overreachDisplayName"),
  });
  const request = buildDelegationRequest({
    agent: overreachAgent,
    capabilities: [{ scheme: "database", id: "admin:drop", params: {} }],
    now: world.now,
  });
  const da = await approveDelegation(world.human, request, { now: world.now });
  try {
    await issueAgentCertificate({
      ca: world.ca,
      human: world.human,
      agent: overreachAgent,
      da,
      now: world.now,
    });
    return {
      rejected: false,
      reason: t("identity.unexpectedIssuance"),
      request: request.capabilities,
    };
  } catch (err) {
    return {
      rejected: true,
      reason: err instanceof Error ? err.message : String(err),
      request: request.capabilities,
    };
  }
}
