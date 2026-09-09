// EXPERIMENTAL: exploratory WIT/WPT interop study artifact (2026-09).
// 探索性试验产物，非稳定接口，勿用于生产或作为规范依据。

// 浏览器版验证管线（WIMSE 风格）+ WPT PoP 构造 + 防重放。
// 与 wit-wpt-interop（Go/TS）同规则；WebCrypto 实现，async。

import { signJWS, verifyJWS, parseHeader, b64e, b64d, wthOf, utf8 } from "./jose.ts";
import { pubOfJwk, privOfJwk } from "./jwk.ts";
import type { Capability, Request, Decision, CheckResult, WITGrant } from "./types.ts";

/** 防重放存储：同一 jti 只能通过一次。 */
export interface ReplayStore {
  checkAndAdd(jti: string, exp: number): void;
}

export class MemoryReplayStore implements ReplayStore {
  private seen = new Set<string>();
  checkAndAdd(jti: string, _exp: number): void {
    if (this.seen.has(jti)) {
      throw new Error("replay: jti already seen");
    }
    this.seen.add(jti);
  }
}

export interface VerifyOpts {
  allowedIdentity?: (spiffeId: string) => boolean;
  policy?: (entitlement: Capability[], req: Capability) => void;
  entitlement?: Capability[];
}

export class Verifier {
  trustBundle: Record<string, CryptoKey>;
  replay: ReplayStore;
  nowFn: () => number;

  constructor(trustBundle: Record<string, CryptoKey>, nowFn?: () => number) {
    this.trustBundle = trustBundle;
    this.replay = new MemoryReplayStore();
    this.nowFn = nowFn ?? (() => Math.floor(Date.now() / 1000));
  }

  async verify(
    wit: string,
    wpt: string,
    req: Request,
    opts: VerifyOpts = {},
  ): Promise<Decision> {
    const checks: CheckResult[] = [];
    let fail: CheckResult | undefined;
    const check = (step: string, ok: boolean, detail: string) => {
      const c: CheckResult = { step, ok, detail };
      checks.push(c);
      if (fail === undefined && !ok) {
        fail = c;
      }
    };
    const finish = (): Decision => {
      if (fail === undefined) {
        return { permit: true, reason: "PERMIT", checks };
      }
      return { permit: false, reason: fail.detail, checks };
    };

    // 1) WIT header 检查
    const allowAlgs = new Set(["ES256", "RS256", "PS256"]);
    const withdr = parseHeader<{ typ?: string; alg?: string; kid?: string }>(wit);
    if (!withdr || withdr.typ !== "wit+jwt") {
      check("header", false, `header: bad typ ${withdr?.typ ?? "missing"}`);
      return finish();
    }
    if (!withdr.alg || !allowAlgs.has(withdr.alg)) {
      check(
        "header",
        false,
        `header: alg ${withdr.alg} not allowed (must be asymmetric, non-none)`,
      );
      return finish();
    }
    if (!withdr.kid) {
      check("header", false, "header: kid is REQUIRED");
      return finish();
    }
    const bundlePub = this.trustBundle[withdr.kid];
    if (!bundlePub) {
      check("header", false, `header: kid ${withdr.kid} not in trust bundle`);
      return finish();
    }
    check("header", true, `typ=${withdr.typ} alg=${withdr.alg} kid=${withdr.kid}`);

    // 2) WIT 验签
    let witPayload: unknown;
    try {
      witPayload = (await verifyJWS(wit, bundlePub)).payload;
    } catch (e) {
      check("wit-signature", false, `wit-signature: ${(e as Error).message}`);
      return finish();
    }
    check("wit-signature", true, `verified with bundle kid ${withdr.kid}`);

    // 3) WIT 时间
    const now = this.nowFn();
    const witC = witPayload as {
      sub: string;
      iat?: number;
      exp?: number;
      aud?: unknown;
      cnf?: { jwk?: import("./jwk.ts").ECJWK; alg?: string };
    };
    if (!witC.exp || now >= witC.exp) {
      check("wit-time", false, `wit-time: expired (now=${now} exp=${witC.exp})`);
      return finish();
    }
    if (witC.iat && now < witC.iat) {
      check("wit-time", false, `wit-time: not yet valid (iat=${witC.iat})`);
      return finish();
    }
    check("wit-time", true, `valid at now ${now}`);

    // 4) WIT claims
    const allowed =
      opts.allowedIdentity ?? ((s: string) => s.startsWith("spiffe://"));
    if (!witC.sub || !witC.sub.startsWith("spiffe://") || !allowed(witC.sub)) {
      check(
        "wit-claims",
        false,
        `wit-claims: sub ${witC.sub} is not an allowed spiffe:// identity`,
      );
      return finish();
    }
    if (witC.aud !== undefined) {
      check(
        "wit-claims",
        false,
        "wit-claims: aud-in-wit (WIT-SVID MUST NOT carry aud)",
      );
      return finish();
    }
    if (!witC.cnf?.jwk || !witC.cnf.jwk.kty) {
      check("wit-claims", false, "wit-claims: cnf.jwk is REQUIRED");
      return finish();
    }
    if (witC.cnf.alg !== withdr.alg) {
      check(
        "wit-claims",
        false,
        `wit-claims: cnf.alg ${witC.cnf.alg} != header alg ${withdr.alg}`,
      );
      return finish();
    }
    let cnfPub: CryptoKey;
    try {
      cnfPub = await pubOfJwk(witC.cnf.jwk);
    } catch (e) {
      check("wit-claims", false, `wit-claims: bad cnf.jwk: ${(e as Error).message}`);
      return finish();
    }
    check("wit-claims", true, `sub=${witC.sub} cnf.jwk present`);

    // 7) PoP 呈现
    if (wpt === "") {
      check(
        "pop",
        false,
        "pop required: missing WPT (WIT MUST NOT be used as a bearer)",
      );
      return finish();
    }

    // 5) WPT 验签
    let wpthdr: { typ?: string; alg?: string };
    try {
      wpthdr = parseHeader<{ typ?: string; alg?: string }>(wpt);
    } catch (e) {
      check("pop", false, `pop: bad WPT header: ${(e as Error).message}`);
      return finish();
    }
    if (wpthdr.typ !== "wpt+jwt") {
      check("pop", false, `pop: bad WPT typ ${wpthdr.typ}`);
      return finish();
    }
    if (wpthdr.alg !== witC.cnf.alg) {
      check(
        "pop",
        false,
        `pop: alg mismatch (WPT alg ${wpthdr.alg} != cnf.jwk.alg ${witC.cnf.alg})`,
      );
      return finish();
    }
    let wptPayload: unknown;
    try {
      wptPayload = (await verifyJWS(wpt, cnfPub)).payload;
    } catch (e) {
      check("pop", false, `pop: WPT signature verification failed: ${(e as Error).message}`);
      return finish();
    }
    check("pop", true, "WPT verified with WIT cnf.jwk");

    // 6) WPT claims
    const wptC = wptPayload as { aud?: string; exp?: number; jti?: string; wth?: string };
    if (wptC.aud !== req.target_uri) {
      check(
        "wpt",
        false,
        `wpt: aud mismatch (wpt aud ${wptC.aud} != request target ${req.target_uri})`,
      );
      return finish();
    }
    if (!wptC.exp || now >= wptC.exp) {
      check("wpt", false, `wpt: expired (now=${now} exp=${wptC.exp})`);
      return finish();
    }
    if (wptC.exp - now > 300) {
      check("wpt", false, `wpt: exp not short-lived (${wptC.exp - now}s > 300s)`);
      return finish();
    }
    if (wptC.jti === undefined || b64d(wptC.jti).length !== 16) {
      check("wpt", false, "wpt: jti must be 128-bit base64url");
      return finish();
    }
    try {
      this.replay.checkAndAdd(wptC.jti, wptC.exp ?? 0);
    } catch (e) {
      check("wpt", false, `wpt: ${(e as Error).message}`);
      return finish();
    }
    if ((await wthOf(wit)) !== wptC.wth) {
      check("wpt", false, "wpt: wth mismatch (bound token hash differs)");
      return finish();
    }
    check("wpt", true, "aud/exp/jti/wth validated");

    // 8) 部署策略
    if (opts.policy && req.requested_capability) {
      try {
        opts.policy(opts.entitlement ?? [], req.requested_capability);
      } catch (e) {
        check("policy", false, `policy: ${(e as Error).message}`);
        return finish();
      }
      check("policy", true, "requested capability within entitlement");
    }
    return finish();
  }
}

/** agent 构造 PoP 凭证（用 WIT 的 cnf 私钥签 WPT）。呈现：Authorization: WPT <token>。 */
export async function mintWPT(
  wit: string,
  method: string,
  targetUri: string,
  now: number,
  priv: CryptoKey,
): Promise<string> {
  const jtiBytes = crypto.getRandomValues(new Uint8Array(16));
  const header = { typ: "wpt+jwt", alg: "ES256" };
  const claims = {
    aud: targetUri,
    exp: now + 120,
    iat: now,
    jti: b64e(jtiBytes),
    wth: await wthOf(wit),
  };
  return signJWS(header, claims, priv);
}

/** 从 WITGrant 取出 cnf 私钥（浏览器端 import 为可签名 Key）。 */
export async function witKeyOf(g: WITGrant): Promise<CryptoKey> {
  return privOfJwk(g.wit_private_key);
}

export { utf8 };