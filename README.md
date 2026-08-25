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

## Drafts

- AIC-JWT: [draft-wei-aic-jwt-00.md](docs/draft-wei-aic-jwt-00.md) (also `.xml` / `.txt` / `.html`)
- AIC X.509 companion: [draft-wei-aic-identity-cert-00.md](docs/draft-wei-aic-identity-cert-00.md) (also `.xml` / `.txt` / `.html`)

## Run

```bash
go test ./... -v                # all Go tests (incl. OAuth scenarios)
go test -cover ./...            # coverage
node --test ts/aicjwt.test.ts   # TS/WebCrypto, 15 cases (Node 22+)
```

## Layout

| File | Purpose |
|------|---------|
| `reexport.go` | Wrapper re-exporting the `types/aicjwt` API: claims, JWS, capability matching, constraints, key binding, 11-step validation |
| `oauth.go` | OAuth protocol layer: AS (assertion / code / token-exchange), RS, DPoP, Token Status List |
| `oauth_scenarios_test.go` | 9 OAuth end-to-end scenarios |
| `helpers_test.go` | Scenario test helpers (token issuance / construction) |
| `ts/` | Browser WebCrypto reference implementation (independent of Go) |
| `draft-wei-aic-jwt-00.md` | Copy of the draft |

## Architecture

The core logic (claims model, JWS, capability matching, constraint
evaluation, key binding, 11-step validation pipeline) lives in
**`github.com/varwof/types/aicjwt`**. This repository keeps the OAuth
protocol-layer simulation, the scenario tests, and the TS browser
implementation. Functionality will progressively merge into the main
varwof repositories.

## License

Apache-2.0
