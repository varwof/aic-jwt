// Verifies the fixture AIC-JWT with the `jsonwebtoken` library.
// jsonwebtoken expects a PEM/KeyObject, so the JWK from the fixture is
// converted with jose's exportSPKI.
import { readFile } from "node:fs/promises";
import jwt from "jsonwebtoken";
import { exportSPKI, importJWK } from "jose";

const { token, issuerJwk, expected } = JSON.parse(
  await readFile(new URL("./fixtures/sample-aic-jwt.json", import.meta.url), "utf8"),
);

const spki = await exportSPKI(await importJWK(issuerJwk, "ES256"));
const payload = jwt.verify(token, spki, {
  algorithms: ["ES256"],
  issuer: expected.iss,
  audience: expected.aud,
});

console.log("jsonwebtoken verify: OK");
console.log("  iss:", payload.iss);
console.log("  sub:", payload.sub);
console.log("  aud:", JSON.stringify(payload.aud));
console.log("  exp:", payload.exp, "iat:", payload.iat, "jti present:", Boolean(payload.jti));
console.log("  aic present:", Boolean(payload.aic), "| da present:", Boolean(payload.da));
