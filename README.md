# AIC-JWT

Reference implementation and conformance suite for AIC-JWT
(`draft-wei-aic-jwt-00`): the JSON Web Token profile of the AI Agent
Identity Certificate (AIC). It translates the specification's
requirements into executable tests and verifies end-to-end behavior
against real OAuth scenarios (RFC 9068 / 7523 / 8693 / 9449, OBO,
Token Status List).

- Go reference implementation: this repository (wrapper), with the
  core logic in `github.com/varwof/types/aicjwt` (single source of
  truth).
- TypeScript/WebCrypto implementation: `ts/` (pure WebCrypto, runs in
  browsers; directly testable in Node).
- Serverless browser demo: [`demo/`](demo/README.md) — human JWT
  certificate → agent certificate → verification, all in one
  self-contained HTML page (no backend needed).

## Drafts

- AIC-JWT: [draft-wei-aic-jwt-00.md](docs/draft-wei-aic-jwt-00.md) (also `.xml` / `.txt` / `.html`) — read online: [Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-jwt/)
- AIC X.509 companion: [draft-wei-aic-identity-cert-01.md](docs/draft-wei-aic-identity-cert-01.md) (also `.xml` / `.txt` / `.html`) — read online: [Datatracker](https://datatracker.ietf.org/doc/draft-wei-aic-identity-cert/)

## Run

```bash
go test ./... -v                # all Go tests (incl. OAuth scenarios)
go test -cover ./...            # coverage
node --test ts/aicjwt.test.ts   # TS/WebCrypto, 15 cases (Node 22+)
npm test                        # demo library tests (Node 22+)
npm run build                   # build self-contained demo/dist/index.html
open demo/dist/index.html       # serverless browser demo, English default (index.zh.html = Chinese)
```

## Layout

| File | Purpose |
|------|---------|
| `reexport.go` | Wrapper re-exporting the `types/aicjwt` API: claims, JWS, capability matching, constraints, key binding, 11-step validation |
| `oauth.go` | OAuth protocol layer: AS (assertion / code / token-exchange), RS, DPoP, Token Status List |
| `oauth_scenarios_test.go` | 9 OAuth end-to-end scenarios |
| `helpers_test.go` | Scenario test helpers (token issuance / construction) |
| `ts/` | Browser WebCrypto reference implementation (independent of Go) |
| `demo/` | Serverless browser demo (TS library + UI, builds to a self-contained HTML) |
| `draft-wei-aic-jwt-00.md` | Copy of the draft |

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
