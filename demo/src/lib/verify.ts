// Gateway verification: wraps the core 11-step validation pipeline
// (draft Section 11) and produces a per-step audit report, plus two
// identity-focused bonus steps (presenter binding via cnf.jkt and
// issuer/audience checks) that the demo surfaces explicitly.
import { validate } from "../../../ts/aicjwt.ts";
import type { VerifyOptions } from "../../../ts/aicjwt.ts";
import { t } from "./i18n.ts";
import type { StepResult, VerifyReport } from "./types.ts";

export function stepLabel(n: number): string {
  return t(`vstep.${n}`);
}

function stepList(): StepResult[] {
  return Array.from({ length: 13 }, (_, i) => {
    const n = i + 1;
    return { n, label: stepLabel(n), status: "skip" as const };
  });
}

export async function verifyAgentCertificate(
  token: string,
  opts: VerifyOptions,
): Promise<VerifyReport> {
  const steps = stepList();
  try {
    const decision = await validate(token, opts);
    for (const s of steps) s.status = "ok";
    return { permit: true, steps, decision };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    const fail = classifyFailure(msg);
    for (const s of steps) {
      if (s.n < fail.n) s.status = "ok";
      else if (s.n === fail.n) {
        s.status = "fail";
        s.detail = msg;
      }
    }
    return { permit: false, steps, error: msg };
  }
}

function classifyFailure(msg: string): { n: number } {
  const m = /^step(\d+):/.exec(msg);
  if (m) return { n: Number(m[1]) };
  if (/cnf: presenter/.test(msg)) return { n: 12 };
  if (/iss mismatch|aud mismatch/.test(msg)) return { n: 13 };
  if (/unexpected typ|alg missing|alg .* not in allowlist|kid required|critical header/.test(msg)) {
    return { n: 2 };
  }
  if (/not yet valid|expired|lifetime exceeds/.test(msg)) return { n: 3 };
  if (/DA |nonce|principal key not resolvable|key_hash mismatch/.test(msg)) return { n: 4 };
  if (/consistency|!=/.test(msg)) return { n: 5 };
  if (/PA |representative mode requires|delegation policy|delegation_mode/.test(msg)) return { n: 6 };
  if (/constraint|max-concurrent|time-window|allowed-cidr|concurrent count/.test(msg)) return { n: 7 };
  if (/chain_depth|max_depth/.test(msg)) return { n: 8 };
  if (/capability .* not allowed|unknown capability scheme/.test(msg)) return { n: 9 };
  if (/status/.test(msg)) return { n: 10 };
  return { n: 1 };
}
