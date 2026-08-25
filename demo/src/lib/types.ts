// Demo-facing types. The crypto/claims types come from the core
// reference implementation (ts/aicjwt.ts); these types describe the
// artifacts the browser demo produces and verifies.
import type {
  Capability,
  DAClaims,
  Decision,
  OuterClaims,
  PAClaims,
  Reason,
  VerifyOptions,
} from "../../../ts/aicjwt.ts";

export type {
  Capability,
  DAClaims,
  Decision,
  OuterClaims,
  PAClaims,
  Reason,
  VerifyOptions,
};

/** Demo-wide JWS algorithm (WebCrypto ES256 is universal in Chrome). */
export const DEMO_ALG = "ES256";

export interface HumanIdentity {
  realm: string;
  id: string;
  displayName: string;
  keyPair: CryptoKeyPair;
  /** PA JWT, self-signed by the human (the "human JWT certificate"). */
  certificate: string;
  claims: PAClaims;
  kid: string;
}

export interface AgentIdentity {
  id: string;
  displayName: string;
  keyPair: CryptoKeyPair;
}

export interface DelegationRequest {
  agent: AgentIdentity;
  capabilities: Capability[];
  reason: Reason;
  requestedLifetime: number;
  nonce: string;
  ts: number;
}

export interface DAApproval {
  token: string;
  claims: DAClaims;
}

export interface DemoCA {
  issuer: string;
  kid: string;
  keyPair: CryptoKeyPair;
}

export interface AgentCertificate {
  token: string;
  claims: OuterClaims;
  da: DAClaims;
}

export type StepStatus = "ok" | "fail" | "skip";

export interface StepResult {
  n: number;
  label: string;
  status: StepStatus;
  detail?: string;
}

export interface VerifyReport {
  permit: boolean;
  steps: StepResult[];
  decision?: Decision;
  error?: string;
}

export type ScenarioId =
  | "happy"
  | "overreach"
  | "expired"
  | "tampered"
  | "spoofed"
  | "concurrency";

export interface ScenarioResult {
  id: ScenarioId;
  title: string;
  description: string;
  report?: VerifyReport;
}
