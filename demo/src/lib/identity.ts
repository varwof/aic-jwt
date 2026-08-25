// Human identity: the principal creates a key pair and self-signs a
// PrincipalAuthorization (PA) JWT -- the "human JWT certificate".
// It binds the identity (realm/id) to the key via an RFC 7638 JWK
// thumbprint (hash_alg "jkt", the browser-recommended form per draft
// Section 9.4) and lists the grants (P_grants) the human is willing
// to delegate to agents.
import { t } from "./i18n.ts";
import {
  ALLOWED_MODE_REPRESENTATIVE,
  TYP_PA,
  keyHashOf,
  parseCompact,
  signCompact,
  verifyCompact,
} from "../../../ts/aicjwt.ts";
import type { Capability, PAClaims, Principal } from "../../../ts/aicjwt.ts";
import { DEMO_ALG } from "./types.ts";
import type { HumanIdentity } from "./types.ts";

export interface CreateHumanOptions {
  realm?: string;
  id?: string;
  displayName?: string;
  grants?: Capability[];
  delegationPolicy?: PAClaims["delegation_policy"];
  now?: Date;
}

export const DEFAULT_GRANTS: Capability[] = [
  { scheme: "database", id: "query:*", params: { max_rows: 1000 } },
  { scheme: "database", id: "admin:reset", params: { window: "09:00-18:00" } },
];

export async function createHumanIdentity(
  opts: CreateHumanOptions = {},
): Promise<HumanIdentity> {
  const realm = opts.realm ?? "example.com";
  const id = opts.id ?? "alice";
  const displayName = opts.displayName ?? t("identity.humanDisplayName");
  const now = opts.now ?? new Date();

  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const principal: Principal = {
    realm,
    id,
    key_hash: await keyHashOf(keyPair.publicKey, "jkt"),
    hash_alg: "jkt",
  };
  const claims: PAClaims = {
    ver: 1,
    principal,
    grants: opts.grants ?? DEFAULT_GRANTS,
    delegation_policy: opts.delegationPolicy ?? {
      max_agents: 3,
      allowed_mode: ALLOWED_MODE_REPRESENTATIVE,
      max_session_hours: 8,
    },
  };
  const kid = `human-${id}-${Math.floor(now.getTime() / 1000)}`;
  const certificate = await signCompact(
    { alg: DEMO_ALG, typ: TYP_PA, kid },
    claims,
    keyPair.privateKey,
  );
  return { realm, id, displayName, keyPair, certificate, claims, kid };
}

/** Verify the human certificate against the human public key. */
export async function verifyHumanCertificate(
  certificate: string,
  humanKey: CryptoKey,
): Promise<PAClaims> {
  const { header } = parseCompact(certificate);
  if (header.typ !== TYP_PA) throw new Error(t("err.humanTyp", { typ: TYP_PA }));
  if (!header.kid) throw new Error(t("err.humanKid"));
  await verifyCompact(certificate, header.alg, humanKey);
  const claims = parseCompact(certificate).payload as PAClaims;
  if (claims.ver !== 1) throw new Error(t("err.humanVer"));
  if (!claims.principal?.key_hash) throw new Error(t("err.humanKeyHash"));
  if (!claims.grants?.length) throw new Error(t("err.humanGrants"));
  const binding = await keyHashOf(humanKey, claims.principal.hash_alg || "jkt");
  if (binding !== claims.principal.key_hash) {
    throw new Error(t("err.humanKeyMismatch"));
  }
  return claims;
}
