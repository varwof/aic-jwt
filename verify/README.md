# AIC-JWT third-party JWT verification

Purpose: show that an AIC-JWT is a standard JWT (RFC 7519) and can be
consumed by ordinary JWT libraries.  Two libraries are used:

- `jose` (verify-jose.mjs)
- `jsonwebtoken` (verify-jsonwebtoken.mjs)

This validates the standard JWT layer only: signature (ES256, P-256),
`iss`, `aud`, `exp`, `sub`.  AIC-specific semantics (the `aic` claim,
nested `da` DelegationAuthorization, capability/parameter bounds,
nonce/replay rules) are outside what a generic JWT library can check
and are validated by the AIC-JWT reference implementation
(`ts/aicjwt.ts` / Go `types/aicjwt`).

## Usage

```bash
cd verify
npm install
npm run gen          # generate fixtures/sample-aic-jwt.json
npm run verify:jose  # verify with jose
npm run verify:jwt   # verify with jsonwebtoken
```

The fixture is generated with the AIC-JWT TypeScript implementation
(DA ver=2, authorized mode, ES256) so the exact bytes are reproducible.
