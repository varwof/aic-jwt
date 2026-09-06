// Verifies the fixture AIC-JWT with the `jose` library (standard JWT
// layer: signature, iss, aud, exp).  AIC-specific semantics are
// validated separately by the AIC-JWT reference implementation.
import { readFile } from "node:fs/promises";
import { importJWK, jwtVerify } from "jose";

const { token, issuerJwk, expected } = JSON.parse(
  await readFile(new URL("./fixtures/sample-aic-jwt.json", import.meta.url), "utf8"),
);

const key = await importJWK(issuerJwk, "ES256");
const { payload } = await jwtVerify(token, key, {
  issuer: expected.iss,
  audience: expected.aud,
  algorithms: ["ES256"],
});

console.log("jose verify: OK");
console.log("  iss:", payload.iss);
console.log("  sub:", payload.sub);
console.log("  aud:", JSON.stringify(payload.aud));
console.log("  exp:", payload.exp, "iat:", payload.iat, "jti present:", Boolean(payload.jti));
console.log("  aic present:", Boolean(payload.aic), "| da present:", Boolean(payload.da));
