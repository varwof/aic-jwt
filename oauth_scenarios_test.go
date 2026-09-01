// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjson

import (
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"testing"
	"time"
)

// TestOAuthScenarioAccessTokenBearer verifies the RFC 9068-style
// bearer access token path: issuance, in-scope permit, out-of-scope
// deny and audience confusion.
func TestOAuthScenarioAccessTokenBearer(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	dec := requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	if dec.Actor != "agent:db-analyst-01" {
		t.Fatalf("authorized mode audit actor should be the agent, got %q", dec.Actor)
	}
	// Out of scope: admin:reset is not in the agent capabilities.
	requireDeny(t, env, tok, &Capability{Scheme: "database", ID: "admin:reset"}, "not allowed")
	// Audience confusion: token minted for RS-A must not be accepted by RS-B.
	req := HTTPRequest{
		Method:      "GET",
		URL:         "https://rs-b.example.com/api",
		Audience:    "https://rs-b.example.com",
		AuthzHeader: "Bearer " + tok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     defaultCtx(env),
	}
	if _, err := env.rs.Check(req, env.now); err == nil {
		t.Fatalf("expected audience confusion rejection")
	}
}

// TestOAuthScenarioAssertionGrant verifies the RFC 7523
// assertion-style grant: the Agent presents the principal-signed DA as
// a client assertion at the token endpoint (draft Section 10.2).
func TestOAuthScenarioAssertionGrant(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	req := TokenRequest{
		GrantType:           GrantTypeJWTBearer,
		ClientID:            "agent-1",
		ClientAssertion:     daTok,
		ClientAssertionType: AssertionTypeJWT,
	}
	resp, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatalf("assertion grant: %v", err)
	}
	if resp.TokenType != TokenTypeBearer || resp.AccessToken == "" {
		t.Fatalf("bad token response: %+v", resp)
	}
	requirePermit(t, env, resp.AccessToken, &Capability{Scheme: "database", ID: "query:SELECT"})
	// Wrong assertion type must be rejected.
	req.ClientAssertionType = "urn:wrong"
	if _, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now); err == nil {
		t.Fatalf("expected rejection of wrong assertion type")
	}
}

// TestOAuthScenarioTokenExchange verifies RFC 8693 delegation: the
// subject is the principal, the actor is the Agent, and the exchanged
// token carries the capability intersection.
func TestOAuthScenarioTokenExchange(t *testing.T) {
	env := newTestEnv(t)
	subjectTok, err := env.issuer.NewPrincipalToken("zhangsan",
		[]Capability{{Scheme: "database", ID: "query:*", Params: json.RawMessage(`{"max_rows":1000}`)}},
		[]string{env.issuer.ID}, 3600, env.now)
	if err != nil {
		t.Fatal(err)
	}
	actorCaps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}
	daTok, _ := buildDA(t, env, ModeAuthorized, actorCaps, nil)
	actorTok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{env.issuer.ID}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	req := TokenRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     subjectTok,
		SubjectTokenType: TokenTypeAccessToken,
		ActorToken:       actorTok,
		ActorTokenType:   TokenTypeAIC,
	}
	resp, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatalf("token exchange: %v", err)
	}
	requirePermit(t, env, resp.AccessToken, &Capability{Scheme: "database", ID: "query:SELECT"})
	requireDeny(t, env, resp.AccessToken, &Capability{Scheme: "database", ID: "query:EXPLAIN"}, "not allowed")
	// A subject grant that does not overlap the actor capability must fail.
	subjectTok2, _ := env.issuer.NewPrincipalToken("zhangsan",
		[]Capability{{Scheme: "http", ID: "GET:/api/v1/*"}},
		[]string{env.issuer.ID}, 3600, env.now)
	req.SubjectToken = subjectTok2
	if _, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now); err == nil {
		t.Fatalf("expected insufficient_scope for non-overlapping grants")
	}
}

// TestOAuthScenarioDPoP verifies RFC 9449 sender-constrained bearer
// usage: proof validation, cnf binding, replay and htu checks.
func TestOAuthScenarioDPoP(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	proof, _, err := BuildDPoP(env.agentKey, "ES256", "POST", "https://rs.example.com/api/db", tok, env.now)
	if err != nil {
		t.Fatal(err)
	}
	req := HTTPRequest{
		Method:      "POST",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + tok,
		DPoPHeader:  proof,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     defaultCtx(env),
	}
	if _, err := env.rs.Check(req, env.now); err != nil {
		t.Fatalf("DPoP request should pass: %v", err)
	}
	// Replay of the same proof against the same RS must be rejected.
	if _, err := env.rs.Check(req, env.now); err == nil {
		t.Fatalf("expected DPoP proof replay rejection")
	}
	// Wrong htu must be rejected.
	proof2, _, err := BuildDPoP(env.agentKey, "ES256", "POST", "https://rs.example.com/evil", tok, env.now)
	if err != nil {
		t.Fatal(err)
	}
	req2 := req
	req2.DPoPHeader = proof2
	if _, err := env.rs.Check(req2, env.now); err == nil {
		t.Fatalf("expected htu mismatch rejection")
	}
}

// TestOAuthScenarioStatusListRevocation verifies Token Status List
// revocation at the resource server.
func TestOAuthScenarioStatusListRevocation(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
	// Build a token that carries a status reference.
	outer := &OuterClaims{
		Iss:    env.issuer.ID,
		Sub:    "agent:db-analyst-01",
		Aud:    Audience{"https://rs.example.com"},
		Iat:    env.now.Unix(),
		Exp:    env.now.Add(3600 * time.Second).Unix(),
		Jti:    da.Nonce,
		Cnf:    &Cnf{Jkt: agentJkt(t, env)},
		Status: &StatusRef{Idx: 1, URI: "https://as.example.com/status/1"},
		Aic: &AICClaims{
			Ver:            1,
			Principal:      da.Principal,
			DelegationMode: ModeAuthorized,
			Capabilities:   caps,
		},
		Da: daTok,
	}
	tok, err := env.issuer.signOuter(outer)
	if err != nil {
		t.Fatal(err)
	}
	requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	// Revoke and verify the RS now denies.
	env.issuer.Revoke("https://as.example.com/status/1")
	requireDeny(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"}, "revoked")
}

// TestOAuthScenarioOBOAuthCode verifies the OBO-style authorization
// code flow with PKCE: the code is bound to the requested actor and
// exchanged for an AIC-JWT with sub=agentId.
func TestOAuthScenarioOBOAuthCode(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
	verifier := "db-verifier-secret-123"
	code, err := env.issuer.NewAuthCode("web-app", "agent:db-analyst-01", da.Principal, daTok, verifier, time.Minute, env.now)
	if err != nil {
		t.Fatal(err)
	}
	// The agent authenticates with its own token (actor_token).
	actorTok, _, err := env.issuer.IssueLightweight("agent:db-analyst-01", &env.agentKey.PublicKey,
		da.Principal, caps, nil, 1800, []string{"https://as.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	req := TokenRequest{
		GrantType:    GrantTypeAuthCode,
		Code:         code,
		ClientID:     "web-app",
		CodeVerifier: verifier,
		ActorToken:   actorTok,
	}
	resp, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatalf("code exchange: %v", err)
	}
	requirePermit(t, env, resp.AccessToken, &Capability{Scheme: "database", ID: "query:SELECT"})
	// PKCE failure.
	req.CodeVerifier = "wrong-verifier"
	if _, err := env.issuer.HandleTokenRequest(req, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now); err == nil {
		t.Fatalf("expected PKCE failure")
	}
}

// TestOAuthScenarioRepresentativeAuditActor verifies that
// delegation_mode selects the accountability actor in audit records.
func TestOAuthScenarioRepresentativeAuditActor(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}
	daTok, _ := buildDA(t, env, ModeRepresentative, caps, nil)
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	dec := requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	if dec.Actor != "zhangsan" {
		t.Fatalf("representative mode audit actor should be the principal, got %q", dec.Actor)
	}
	// Capability outside P_grants must be denied at runtime.
	daTok2, _ := buildDA(t, env, ModeRepresentative,
		[]Capability{{Scheme: "database", ID: "admin:purge"}}, nil)
	tok2, _, err := env.issuer.IssueFromDA(daTok2, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	requireDeny(t, env, tok2, &Capability{Scheme: "database", ID: "admin:purge"}, "P_grants")
}

// TestOAuthScenarioBundleVsJWKS verifies that the same token verifies
// both with online principal JWKS and with the optional credential
// bundle (x5c) -- the bundle is a deployment optimization, not a
// requirement.
func TestOAuthScenarioBundleVsJWKS(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	// Bundle-only RS (no online JWKS).
	rs2 := *env.rs
	rs2.PrincipalJWKS = nil
	rs2.PrincipalMaterial = &PrincipalKeyMaterial{X5C: []*x509.Certificate{env.principalCert}}
	req := HTTPRequest{
		Method:      "GET",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + tok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     defaultCtx(env),
	}
	if _, err := rs2.Check(req, env.now); err != nil {
		t.Fatalf("bundle-only verification should pass: %v", err)
	}
}

// TestOAuthScenarioLightweightConsumer verifies the lightweight
// consumer profile (no DA, authorized mode) and that representative
// mode without a DA is refused.
func TestOAuthScenarioLightweightConsumer(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "http", ID: "GET:/api/v1/*"}}
	principal := principalBinding(t, env.principalKey)
	tok, _, err := env.issuer.IssueLightweight("agent:web-01", &env.agentKey.PublicKey,
		principal, caps, nil, 1800, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	requirePermit(t, env, tok, &Capability{Scheme: "http", ID: "GET:/api/v1/users"})
	// Representative without DA must fail the pipeline.
	badTok, _ := buildOuter(t, env, "", nil, ModeRepresentative, caps, nil)
	req := HTTPRequest{
		Method:      "GET",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + badTok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     defaultCtx(env),
	}
	if _, err := env.rs.Check(req, env.now); err == nil {
		t.Fatalf("expected representative-without-DA rejection")
	}
}

// TestOAuthScenarioConstraintEnforcement verifies authorization
// constraints at the RS (allowed-cidr, time-window, max-concurrent).
func TestOAuthScenarioConstraintEnforcement(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	constraints := []Capability{
		{Scheme: ConstraintScheme, ID: "allowed-cidr", Params: json.RawMessage(`["10.0.0.0/8"]`)},
		{Scheme: ConstraintScheme, ID: "time-window", Params: json.RawMessage(`{"start":"00:00","end":"23:59"}`)},
		{Scheme: ConstraintScheme, ID: "max-concurrent", Params: json.RawMessage(`{"max":5}`)},
	}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) { d.Constraints = constraints })
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	// Source IP outside the CIDR whitelist.
	req := HTTPRequest{
		Method:      "GET",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + tok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     RequestContext{Now: env.now, SourceIP: netip.MustParseAddr("192.168.99.1"), ConcurrentCount: 1},
	}
	if _, err := env.rs.Check(req, env.now); err == nil {
		t.Fatalf("expected CIDR constraint rejection")
	}
	// Concurrency over the max.
	req2 := HTTPRequest{
		Method:      "GET",
		URL:         "https://rs.example.com/api/db",
		Audience:    "https://rs.example.com",
		AuthzHeader: "Bearer " + tok,
		RequestCap:  &Capability{Scheme: "database", ID: "query:SELECT"},
		Context:     RequestContext{Now: env.now, SourceIP: netip.MustParseAddr("10.1.2.3"), ConcurrentCount: 5},
	}
	if _, err := env.rs.Check(req2, env.now); err == nil {
		t.Fatalf("expected max-concurrent rejection")
	}
}

// TestOAuthScenarioMultiLevelDelegation verifies depth-1 delegation.
func TestOAuthScenarioMultiLevelDelegation(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	da, err := ValidateDA(daTok, VerifyOptions{Now: env.now, PrincipalJWKS: env.issuer.PrincipalJWKS})
	if err != nil {
		t.Fatal(err)
	}
	_ = da
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	// chain_depth > max_depth must be rejected (built directly, since
	// the issuer never emits such tokens).
	badTok, _ := buildOuter(t, env, daTok, da, ModeAuthorized, caps, func(o *OuterClaims) {
		o.Aic.ChainDepth = 2
		o.Aic.MaxDepth = 1
	})
	requireDeny(t, env, badTok, &Capability{Scheme: "database", ID: "query:SELECT"}, "max_depth")
}
