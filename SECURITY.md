# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in `varwof/aic-jwt`, please do not
open a public issue. Report it privately to
[pki@varwof.com](mailto:pki@varwof.com).

Please include:

- The affected version(s)
- A description of the vulnerability and its impact
- A minimal reproducer if available

You should receive an acknowledgement within a few business days. We ask
that you give us reasonable time to address the issue before public
disclosure.

## Scope

This repository is a reference implementation and conformance suite for
AIC-JWT (`draft-wei-aic-jwt-00`): a Go wrapper over
`github.com/varwof/types/aicjwt` plus a TypeScript/WebCrypto
implementation and a browser demo. Issues of interest include:

- OAuth token endpoint logic (RFC 6749 / 7523 / 8693 / 9449, OBO)
- Token expiry / revocation / replay enforcement
- Concurrency safety of the reference nonce / auth-code stores
- Cross-implementation consistency between the Go and TypeScript paths

Note: the actual validation pipeline (claims model, JWS, capability
matching, constraints, key binding, 11-step validation) lives in
`github.com/varwof/types/aicjwt`; see the `types` repository's
`SECURITY.md` for findings in that layer.

## Supported Versions

Security fixes are applied to the latest release. Older releases are
supported on a best-effort basis.

## Funding note: no paid third-party audit

This is an individual / open-source project; no paid third-party
security audit has been conducted. Validation relies on internal
AI-assisted review, automated tests (race-enabled), and independent
cross-implementation exercise where available.

## Security Audit History

Review practice: development includes AI-assisted security review and
RFC compliance cross-checks (JOSE / JWT (RFC 7515/7519/9068), PKI (RFC 5280)). Consolidated findings are
logged below; each is retained as a historical record after resolution.

### 2026-09-01 -- internal security review (AI-assisted), resolved

Method: internal security/correctness review of the current `main`,
assisted by AI tooling, with RFC cross-checks against JOSE / JWT (RFC 7515/7519/9068), PKI (RFC 5280).
Status: all findings below were resolved in the 2026-09-01 security
pass (commit 71d1dfd) and verified by the full test suite. Fixes were verified by the full test suite (race-enabled).

Next scheduled review: quarterly (next: 2026-12-01).
Independent exercise: independent implementation (EMILIA crossing, 13/13) exercised the AIC-JWT carrier.

### Resolved findings (2026-09-01)

### Security (high)

1. **No expiry check on `verifyPrincipalToken`** (`oauth.go:430`).
   The RFC 8693 `TokenExchange` path verifies the subject
   (principal) token's signature but never checks `iat`/`exp`. An
   expired principal token is accepted. Reproducer test confirmed:
   a token issued ~3h earlier with a 100s lifetime was accepted.

2. **No expiry check on `verifyAgentActor`** (`oauth.go:283`).
   The OBO authorization-code exchange authenticates the agent's
   actor token (signature + `sub` match) but never checks
   `iat`/`exp`/`nbf`. An expired or not-yet-valid actor token is
   accepted. Reproducer test confirmed.

### Robustness / correctness

3. **Data race on `memNonceStore` and issuer maps**
   (`oauth.go:609`, `NewMemNonceStore` at `:622`, `Codes`/`Status`
   maps at `:79-80`). The local `memNonceStore.CheckAndAdd` mutates
   its map without a lock; `ExchangeCode` reads/writes `code.Used`
   and marks codes used without a lock. Single-issuer concurrent
   requests can race. (The `types` package `MemNonceStore` uses a
   mutex; this wrapper's does not.)

4. **`verifyPrincipalToken` does not validate `iss`/`aud`/`nbf`** and
   `verifyAgentActor` does not check `iss`/`aud`; a token issued by a
   different issuer sharing a key rollover could be accepted.

5. **DPoP `VerifyDPoP` trusts `hdr.Alg` without an explicit allowlist
   check** (`oauth.go:487`). `verifyBytes` effectively limits to the
   implemented algorithms, but relying on the switch rather than
   `CheckHeader` allowlist means a header carrying an unexpected alg
   code path is handled implicitly.

6. **`DA ts` freshness is never checked** (via `validateDA` in
   `types/aicjwt/validate.go`). `checkDARequired` requires a non-zero
   `ts` but there is no freshness window; a replayed DA signed long
   ago (but with an unused nonce) passes.

### Cross-implementation inconsistencies (Go vs TypeScript)

7. **`rejectDepthGT1` default differs.** The TS `validate`
   (`ts/aicjwt.ts:877`) defaults to `true` (`?? true`), while the Go
   `ResourceServer.Check` uses `rs.RejectDepthGT1` which defaults to
   `false`. A token with `max_depth > 1` is therefore rejected by the
   TS path but accepted by the Go path for the same config.

8. **`paramsWithinGrant` mirrors the constraint-bypass in `types`.**
   Both `ts/aicjwt.ts:528` and the Go wrapper (via
   `types/aicjwt/capmatch.go`) allow an agent to omit a grant key and
   still be "within" the grant, e.g. escaping a `{"max":5}` or
   `{"level":"admin"}` bound by sending `{}`/absent params.

### Environment (not a code bug)

9. `go.mod` declares `go 1.26` while the available toolchain is
   1.25.10; coverage and some analysis tooling fail with a version
   mismatch in this environment.
