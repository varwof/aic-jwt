# AIC-JWT

[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)
[![IETF Internet-Draft](https://img.shields.io/badge/IETF-draft--wei--aic--jwt-blue)](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)

> ⚠️ **Preview** — Not for production use. APIs and features may change before
> official release. The AIC drafts are Experimental. Contributions welcome
> (PRs) — see [CONTRIBUTING](https://github.com/varwof/.github).

Reference implementation and conformance suite for AIC-JWT
(`draft-wei-aic-jwt-01`): the JSON Web Token profile of the AI Agent
Identity Certificate (AIC). It translates the specification's
requirements into executable tests and verifies end-to-end behavior
against real OAuth scenarios (RFC 9068 / 7523 / 8693 / 9449, OBO,
Token Status List).

**Same authorization semantics, two carriers: X.509 at the TLS layer,
JWT over HTTP.**

- Go reference implementation: this repository (wrapper), with the
  core logic in `github.com/varwof/types/aicjwt` (single source of
  truth).
- TypeScript/WebCrypto implementation: `ts/` (pure WebCrypto, runs in
  browsers; directly testable in Node).
- X.509 ↔ JWT bridge (draft §5.4 / Mode B): `x509_bridge.go` (Go) and
  `ts/x509_bridge.ts` map an X.509 AIC extension onto AIC-JWT claims.
- JWT-carrier path: `jwt_carrier_test.go` and `IssueFromDAShort`
  exercise short-lived, no-refresh issuance on the JWT carrier.
- Serverless browser demo: [`demo/`](demo/README.md) — human JWT
  certificate → agent certificate → verification, all in one
  self-contained HTML page (no backend needed).

## Quickstart

```bash
go test -race ./...          # Go suites (wrapper + OAuth scenarios)
npm run typecheck            # tsc --noEmit
npm run typecheck:tests      # tsc for test files
node --disable-warning=ExperimentalWarning --experimental-strip-types --test \
  ts/aicjwt.test.ts ts/x509_bridge.test.ts   # TS unit suites
npm test                     # demo library tests
cd verify && npm install && npm run gen \
  && npm run verify:jose && npm run verify:jwt   # third-party JWT check
npm run build && open demo/dist/index.html      # browser demo
```

## Drafts

- AIC-JWT (prepared revision): [draft-wei-aic-jwt-01.md](docs/draft-wei-aic-jwt-01.md)
  — RFC 7523 DA claims (DA ver=2), per-mode role placement, token
  exchange mapping (§10.4). The -00 revision remains current on the
  Datatracker until -01 is posted.
- AIC-JWT: [draft-wei-aic-jwt-00.md](docs/draft-wei-aic-jwt-00.md) (also `.xml` / `.txt` / `.html`) — read online: [Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)
- AIC X.509 companion: [draft-wei-aic-identity-cert-01.md](docs/draft-wei-aic-identity-cert-01.md) (also `.xml` / `.txt` / `.html`) — read online: [Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)

Repository copies of draft text are snapshots (pinned to types v0.5.2);
the authoritative text is the version posted on the Datatracker.

## How it works

AIC-JWT is the JWT carrier of the same authorization data model as the
X.509 AIC extension:

- **Two-layer signature.** A principal signs a Delegation
  Authorization (DA) JWT (ver=2) that bounds the agent's capabilities;
  an issuer (CA or AS) validates the DA and signs the outer AIC-JWT.
- **Roles per mode.** Authorized: agent is `sub` (RFC 7523 Section 3,
  item 2A). Representative: resource owner/principal is `sub`, agent
  is `act`; an accountable operator that differs from the resource
  owner needs a separate binding (future work).
- **Verification.** The 11-step pipeline validates JWS, time, RFC 7523
  DA claims, outer/DA consistency, PA (representative), constraints,
  depth, capabilities, status, issuer/audience and presenter binding;
  `Decision` exposes both actor and executor for audit.
- **Seams.** OAuth RFC 7523/8693 issuance and exchange are
  implemented; SPIFFE JWT-SVID projection is authorized-mode only;
  AIC-specific semantics are validated by this project's verifiers,
  while the standard JWT layer is consumable by generic JWT libraries.

## Run

```bash
go test -race ./...             # all Go tests incl. race (OAuth scenarios)
go vet ./...                    # vet
npm run typecheck               # tsc --noEmit
node --test ts/aicjwt.test.ts ts/x509_bridge.test.ts   # TS/WebCrypto unit suites, 24 cases (Node 22+)
npm test                        # demo library tests (Node 22+)
cd verify && npm install        # third-party JWT verification deps
cd verify && npm run gen && npm run verify:jose && npm run verify:jwt
npm run build                   # build self-contained demo/dist/index.html
open demo/dist/index.html       # serverless browser demo, English default (index.zh.html = Chinese)
```

## Layout

| File | Purpose |
|------|---------|
| `reexport.go` | Wrapper re-exporting the `types/aicjwt` API: claims, JWS, capability matching, constraints, key binding, 11-step validation |
| `oauth.go` | OAuth protocol layer: AS (assertion / code / token-exchange), RS, DPoP, Token Status List |
| `x509_bridge.go` | X.509 AIC extension → AIC-JWT claims (MapX509ToClaims, §5.4 Mode B) |
| `jwt_carrier_test.go` | JWT-carrier integration tests (short-lived issuance, single-key across carriers, JOSE integrity) |
| `oauth_scenarios_test.go` | 9 OAuth end-to-end scenarios |
| `helpers_test.go` | Scenario test helpers (token issuance / construction) |
| `ts/` | Browser WebCrypto reference implementation (independent of Go) |
| `ts/asn1.ts`, `ts/x509_bridge.ts` | TS X.509 ASN.1 + X.509→JWT bridge |
| `demo/` | Serverless browser demo (TS library + UI, builds to a self-contained HTML) |
| `verify/` | Third-party JWT verification (jose, jsonwebtoken) against generated fixtures |
| `docs/draft-wei-aic-jwt-01.md` | Copy of the prepared -01 revision |

## Changes and verification (2026-09-06)

Recent changes reflect OAuth WG review (Lombardo/Schrock, 2026-09-04):

- **RFC 7523 assertion**: the DA JWT now carries `iss`, `sub`, `aud`,
  `exp`, `iat` and `jti` (jti = nonce; exp = ts + requested_lifetime),
  and DA `ver` is 2, so -00-shaped DAs are rejected explicitly rather
  than silently downgraded.
- **Per-mode role placement**: representative mode puts the resource
  owner in `sub` and the agent in `act`; authorized mode keeps the
  agent in `sub` as the authorized accessor (RFC 7523 Section 3, item
  2A).  Consistency checks and the validation decision (`Executor`
  alongside `Actor`) are updated accordingly.
- **Token exchange**: the mapping is documented in -01 Section 10.4;
  representative-mode tokens are rejected as actor credentials.
- **Dependency**: `github.com/varwof/types` v0.5.2.
- **Third-party verification**: `verify/` validates that an AIC-JWT is
  a standard JWT consumable by `jose` and `jsonwebtoken` (signature,
  iss, aud, exp).  AIC-specific semantics remain validated by the
  AIC-JWT reference implementations.

## Evidence and boundaries

- Go suites pass under `go test -race` and `go vet`; TypeScript
  sources and tests pass `tsc --noEmit`.  Coverage: types pki 92%,
  types/aicjwt 88%, types/cmd 88%, aic-jwt 90%.
- Third-party JWT verification passes with `jose` and
  `jsonwebtoken` — see [verify/RESULTS.md](verify/RESULTS.md).
- Browser demo covers the happy path plus overreach, expiry,
  tampering, spoofed-presenter and constraint scenarios.
- Independent joint validation with EMILIA is tracked in
  [emiliaprotocol/emilia-protocol#730](https://github.com/emiliaprotocol/emilia-protocol/pull/730).

Boundaries: this project implements AIC-JWT semantics and the OAuth
7523/8693 seams it declares; it is not an OAuth authorization-server
implementation.  Generic JWT libraries validate the standard JWT layer
only.  The drafts are Experimental; the -00 revision is current on the
Datatracker until -01 is posted.

## Demo

The [`demo/`](demo/README.md) page walks through the full AIC-JWT
lifecycle entirely in the browser using WebCrypto:

1. A human generates a key pair and self-signs a PrincipalAuthorization
   (PA) JWT — the "human JWT certificate" with identity binding and
   P_grants.
2. An agent builds a delegation request (with a 32-byte nonce); the
   human reviews and signs the DA JWT.
3. A demo CA validates the DA and issues the outer AIC-JWT — the
   "agent certificate" — binding the agent's public key via `cnf.jkt`.
4. A gateway runs the 11-step validation pipeline (plus identity
   binding checks) and renders a per-step audit report, with canned
   scenarios for overreach, expiry, tampering, identity spoofing, and
   constraint violations.

Open `demo/dist/index.html` directly in Chrome, or use `?auto` to run
the whole flow automatically.

## Architecture

The core logic (claims model, JWS, capability matching, constraint
evaluation, key binding, 11-step validation pipeline) lives in
**`github.com/varwof/types/aicjwt`**. This repository keeps the OAuth
protocol-layer simulation, the scenario tests, and the TS browser
implementation. Functionality will progressively merge into the main
varwof repositories.

## License

Apache-2.0
