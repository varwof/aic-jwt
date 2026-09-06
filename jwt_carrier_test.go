// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

// Integration tests for the JWT-carrier path of AIC:
//  1. short-lived issuance (issue-a-DA-once / fetch-fresh-token-each-call)
//  2. single-key identity across X.509 and JWT carriers
//  3. JOSE carrier integrity (tamper / expiry / replay)
//
// These verify that the AIC X.509 philosophy (principal-authorized short-lived
// credentials, one key pair, fail-closed verification) is realisable on the
// AIC-JWT carrier without any OAuth-protocol machinery.

package aicjson

import (
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func rsCheck(env *testEnv, tok string, now time.Time) error {
	_, err := env.rs.Check(HTTPRequest{
		Method: "GET", URL: "https://rs.example.com/api/db", Audience: "https://rs.example.com",
		AuthzHeader: "Bearer " + tok, RequestCap: &Capability{Scheme: "database", ID: "query:SELECT"},
		Context: defaultCtx(env),
	}, now)
	return err
}

// TestShortLivedIssuance verifies the X.509-style migration to JWT:
// short-lived tokens are minted from freshly signed, short-lived DAs;
// a token is valid only within its own lifetime; the DA window bounds
// every minted token; and no refresh/revocation machinery is needed
// because the holder simply re-applies (new DA, new nonce) when the
// current token lapses - mirroring a short-lived X.509 certificate.
func TestShortLivedIssuance(t *testing.T) {
	env := newTestEnv(t)
	aud := []string{"https://rs.example.com"}
	t0 := env.now
	caps := []Capability{
		{Scheme: "database", ID: "query:*", Params: json.RawMessage(`{"max_rows":1000}`)},
	}

	// First cycle: principal signs a 15-minute DA, AS mints a token
	// whose lifetime is capped at the DA window.
	da1, daClaims1 := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
		d.RequestedLifetime = 900 // 15 min
		d.Exp = d.TS + 900
	})
	tok1, outer1, err := env.issuer.IssueFromDAShort(da1, &env.agentKey.PublicKey, aud, 600, t0)
	if err != nil {
		t.Fatalf("short issuance failed: %v", err)
	}
	if got := outer1.Exp - outer1.Iat; got != 600 {
		t.Fatalf("short token lifetime = %d, want 600", got)
	}
	if t0.Add(time.Duration(outer1.Exp-outer1.Iat) * time.Second).After(time.Unix(daClaims1.Exp, 0)) {
		t.Fatalf("token outlives its DA window")
	}
	if err := rsCheck(env, tok1, t0); err != nil {
		t.Fatalf("short token rejected at t0: %v", err)
	}

	// Ten minutes in, the first token is still within its 10-minute
	// window.
	t10 := t0.Add(10 * time.Minute)
	if err := rsCheck(env, tok1, t10); err != nil {
		t.Fatalf("short token rejected within window at t10: %v", err)
	}

	// The DA that minted tok1 is consumed (nonce single-use): replaying
	// it to mint again within its window must be refused by the issuer,
	// even though the DA is not yet expired.
	if _, _, err := env.issuer.IssueFromDAShort(da1, &env.agentKey.PublicKey, aud, 600, t10); err == nil {
		t.Fatalf("DA nonce replay accepted by issuer")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce-reuse rejection, got: %v", err)
	}

	// At t20 the first token is expired (issued at t0, lifetime 600s);
	// the RS must fail closed even though nothing revokes it.
	t20 := t0.Add(20 * time.Minute)
	err = rsCheck(env, tok1, t20)
	if err == nil {
		t.Fatalf("expired short token accepted by RS")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected 'expired' on stale token, got: %v", err)
	}

	// Second cycle: the agent simply applies again - a fresh DA with a
	// fresh nonce is signed at t20, and a new short token is minted.  No
	// refresh token, no revocation: re-application replaces both.
	da2, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
		d.TS = t20.Unix()
		d.Iat = d.TS
		d.RequestedLifetime = 900
		d.Exp = d.TS + 900
	})
	tok2, _, err := env.issuer.IssueFromDAShort(da2, &env.agentKey.PublicKey, aud, 600, t20)
	if err != nil {
		t.Fatalf("re-issuance failed: %v", err)
	}
	if err := rsCheck(env, tok2, t20); err != nil {
		t.Fatalf("fresh token rejected at t20: %v", err)
	}

	// The old DA cannot be replayed to mint again after it lapses;
	// it is expired, so issuance is refused (fail closed).
	if _, _, err := env.issuer.IssueFromDAShort(da1, &env.agentKey.PublicKey, aud, 600, t20); err == nil {
		t.Fatalf("lapsed DA accepted by issuer")
	}

	// Lifetime exceeding the DA window must be refused up front.
	if _, _, err := env.issuer.IssueFromDAShort(da2, &env.agentKey.PublicKey, aud, 7200, t20); err == nil {
		t.Fatalf("expected refusal for lifetime > DA requested_lifetime")
	}
}

// TestSingleKeyDualCarrier proves that one key pair is the identity in
// both the X.509 and the JWT carrier: the cert's SPKI hash, the
// principal key_hash, and the agent cnf.jkt all derive from the same
// public key, and an X.509 certificate can serve as the trust anchor
// (credential bundle) that resolves the JWT's principal key without a
// JWKS endpoint.
func TestSingleKeyDualCarrier(t *testing.T) {
	env := newTestEnv(t)

	// The agent's key pair - the same identity in both carriers.
	agentCert := selfSignedCert(t, env.agentKey, "agent:db-analyst-01")

	// X.509 carrier: SPKI hash of the cert's SubjectPublicKeyInfo.
	spkiFromCert, err := SPKIHash(agentCert, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	// JWT carrier: SPKI hash computed directly from the public key.
	spkiFromKey, err := SPKIHashPub(&env.agentKey.PublicKey, "sha-256")
	if err != nil {
		t.Fatal(err)
	}
	if spkiFromCert != spkiFromKey {
		t.Fatalf("SPKI hash differs between cert and key: %q != %q", spkiFromCert, spkiFromKey)
	}

	// JWT cnf.jkt binding of the same key.
	jkt, err := KeyHashOf(&env.agentKey.PublicKey, "jkt")
	if err != nil {
		t.Fatal(err)
	}

	// Build a DA whose principal carries the SPKI key_hash (as the AIC
	// X.509 extension does), plus an outer token binding the agent via jkt.
	daTok, da := buildDA(t, env, ModeAuthorized, []Capability{
		{Scheme: "database", ID: "query:*", Params: json.RawMessage(`{"max_rows":1000}`)},
	}, nil)
	if da.Principal.HashAlg != "sha-256" {
		t.Fatalf("principal hash_alg = %q, want sha-256 (X.509-style)", da.Principal.HashAlg)
	}

	tok, outer, err := env.issuer.IssueFromDAShort(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, 300, env.now)
	if err != nil {
		t.Fatal(err)
	}
	if outer.Cnf == nil || outer.Cnf.Jkt != jkt {
		t.Fatalf("outer cnf.jkt = %v, want %q", outer.Cnf, jkt)
	}
	if err := rsCheck(env, tok, env.now); err != nil {
		t.Fatalf("JWKS-backed RS rejected token: %v", err)
	}

	// Resolution via offline credential bundle: the X.509 certificate is
	// the trust anchor; no JWKS lookup is used.
	rsBundle := &ResourceServer{
		ID:                "https://rs.example.com",
		IssuerID:          env.issuer.ID,
		IssuerKeys:        env.issuer.IssuerKeys(),
		PrincipalMaterial: &PrincipalKeyMaterial{X5C: []*x509.Certificate{env.principalCert}},
		CapabilityPlugins: databasePlugins(),
		StatusChecker:     env.issuer.StatusCheckerFor(),
		RejectDepthGT1:    true,
		PA:                env.pa,
	}
	_, err = rsBundle.Check(HTTPRequest{
		Method: "GET", URL: "https://rs.example.com/api/db", Audience: "https://rs.example.com",
		AuthzHeader: "Bearer " + tok, RequestCap: &Capability{Scheme: "database", ID: "query:SELECT"},
		Context: defaultCtx(env),
	}, env.now)
	if err != nil {
		t.Fatalf("bundle-backed RS rejected token: %v", err)
	}
}

// TestJOSECarrierIntegrity verifies the JOSE carrier fails closed on
// signature tampering, expiry and DA replay - the same way an X.509
// verifier rejects a bad signature or expired certificate.
func TestJOSECarrierIntegrity(t *testing.T) {
	env := newTestEnv(t)
	daTok, _ := buildDA(t, env, ModeAuthorized, []Capability{
		{Scheme: "database", ID: "query:*", Params: json.RawMessage(`{"max_rows":1000}`)},
	}, nil)
	tok, _, err := env.issuer.IssueFromDAShort(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, 300, env.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := rsCheck(env, tok, env.now); err != nil {
		t.Fatalf("baseline token rejected: %v", err)
	}

	// Signature tampering flips a character in the middle of the
	// signature segment (the final char only carries base64 padding bits
	// for a 64-byte EC signature, so it must not be used).
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("token is not a compact JWS")
	}
	sigSeg := parts[2]
	mid := len(sigSeg) / 2
	orig := sigSeg[mid]
	var repl byte
	for _, c := range "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" {
		if byte(c) != orig {
			repl = byte(c)
			break
		}
	}
	tampered := parts[0] + "." + parts[1] + "." + sigSeg[:mid] + string(repl) + sigSeg[mid+1:]
	if err := rsCheck(env, tampered, env.now); err == nil {
		t.Fatalf("tampered signature accepted by RS")
	}

	// Replay: the same DA token presented again to the issuer must be
	// refused (issuer-side nonce store), matching a reused
	// DelegationAuthorization in the X.509 world.
	if _, _, err := env.issuer.IssueFromDAShort(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, 300, env.now); err == nil {
		t.Fatalf("DA replay accepted by issuer")
	} else if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce-reuse rejection, got: %v", err)
	}

	// Alg confusion: an unallowed JOSE alg must be rejected by the header
	// check even before any signature verification, in the same way an
	// X.509 verifier rejects an unsupported signature algorithm.
	if err := checkHeader(Header{Alg: "HS256", Typ: TypOuter, Kid: "issuer-1"}, TypOuter); err == nil {
		t.Fatalf("header with disallowed alg HS256 accepted")
	}
	if err := checkHeader(Header{Alg: "none", Typ: TypOuter, Kid: "issuer-1"}, TypOuter); err == nil {
		t.Fatalf("header with alg none accepted")
	}
	if err := checkHeader(Header{Alg: "ES256", Typ: "wrong", Kid: "issuer-1"}, TypOuter); err == nil {
		t.Fatalf("header with wrong typ accepted")
	}
}
