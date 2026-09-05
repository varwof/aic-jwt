// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjson

import (
	"encoding/json"
	"strings"
	"testing"
)

// Regression tests for the token-endpoint issuance side of the RFC 7523
// role/claims model adopted after OAuth WG review (2026-09-04):
//
// Jeff Lombardo (Amazon): the agent is the OAuth client/actor, and the
// authorization grant subject is the party whose authorization is
// represented; carrying "the agent as subject" in representative mode
// leaves no slot for the resource owner's consent.
//
// Iman Schrock (EMILIA): AIC-JWT Section 5.2 lacked the RFC 7523
// required claims and Section 10.2 presented the DA as a jwt-bearer
// grant, so the two did not interoperate; the assertion must be fixed
// and the issued token defined per mode (representative: resource
// owner/principal is sub and the agent is act/client_id; authorized:
// the agent may be sub as the authorized accessor, RFC 7523 Section 3
// item 2A).
func assertErrContains(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected error containing %q, got: %v", want, err)
	}
}

func TestIssueFromDARequiresDAAudience(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, func(d *DAClaims) {
		// A DA minted for a different authorization server must not be
		// redeemable at this one.
		d.Aud = Audience{"https://other.example.com"}
	})
	_, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
		[]string{"https://rs.example.com"}, env.now)
	assertErrContains(t, err, "does not include this AS")
}

func TestIssueFromDARolePlacement(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}

	t.Run("authorized: agent is subject", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
		_, outer, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		if outer.Sub != da.AgentID {
			t.Fatalf("authorized outer sub = %q, want agent %q", outer.Sub, da.AgentID)
		}
		if outer.Act != nil {
			t.Fatalf("authorized outer act = %v, want nil", outer.Act)
		}
	})

	t.Run("representative: resource owner is subject, agent is act", func(t *testing.T) {
		daTok, da := buildDA(t, env, ModeRepresentative, caps, nil)
		_, outer, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		if outer.Sub != da.Principal.SubjectID() {
			t.Fatalf("representative outer sub = %q, want resource owner %q", outer.Sub, da.Principal.SubjectID())
		}
		if outer.Act == nil || outer.Act.Sub != da.AgentID {
			t.Fatalf("representative outer act = %v, want agent %q", outer.Act, da.AgentID)
		}
	})
}

func TestOAuthJWTBearerGrantRepresentative(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}
	daTok, _ := buildDA(t, env, ModeRepresentative, caps, nil)
	resp, err := env.issuer.HandleTokenRequest(TokenRequest{
		GrantType:          GrantTypeJWTBearer,
		ClientAssertionType: AssertionTypeJWT,
		Assertion:          daTok,
	}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatalf("HandleTokenRequest: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatal("expected an access token")
	}
	dec, err := env.rs.Check(HTTPRequest{
		AuthzHeader: "Bearer " + resp.AccessToken,
		Audience:    "https://rs.example.com",
		Method:      "GET",
		URL:         "https://rs.example.com/api",
	}, env.now)
	if err != nil {
		t.Fatalf("RS check: %v", err)
	}
	if !dec.Permit {
		t.Fatal("expected permit")
	}
	if dec.Actor != "zhangsan" {
		t.Fatalf("audit actor = %q, want principal zhangsan in representative mode", dec.Actor)
	}
	if dec.Executor != "agent:db-analyst-01" {
		t.Fatalf("executor = %q, want agent:db-analyst-01", dec.Executor)
	}
}

func TestJWTBearerClientAssertionRestrictions(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}

	t.Run("authorized client assertion accepted", func(t *testing.T) {
		grantDA, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		actorDA, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		actorTok, _, err := env.issuer.IssueFromDA(actorDA, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		resp, err := env.issuer.HandleTokenRequest(TokenRequest{
			GrantType:           GrantTypeJWTBearer,
			ClientAssertionType: AssertionTypeJWT,
			Assertion:           grantDA,
			ClientAssertion:     actorTok,
			ClientID:            "agent:db-analyst-01",
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("HandleTokenRequest: %v", err)
		}
		if resp.AccessToken == "" {
			t.Fatal("expected access token")
		}
	})

	t.Run("representative client assertion rejected", func(t *testing.T) {
		grantDA, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		repDA, _ := buildDA(t, env, ModeRepresentative, caps, nil)
		repTok, _, err := env.issuer.IssueFromDA(repDA, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		_, err = env.issuer.HandleTokenRequest(TokenRequest{
			GrantType:           GrantTypeJWTBearer,
			ClientAssertionType: AssertionTypeJWT,
			Assertion:           grantDA,
			ClientAssertion:     repTok,
			ClientID:            "agent:db-analyst-01",
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		assertErrContains(t, err, "authorized-mode AIC-JWT")
	})

	t.Run("client assertion subject must match client_id", func(t *testing.T) {
		grantDA, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		actorDA, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		actorTok, _, err := env.issuer.IssueFromDA(actorDA, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		_, err = env.issuer.HandleTokenRequest(TokenRequest{
			GrantType:           GrantTypeJWTBearer,
			ClientAssertionType: AssertionTypeJWT,
			Assertion:           grantDA,
			ClientAssertion:     actorTok,
			ClientID:            "other-client",
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		assertErrContains(t, err, "client_id")
	})
}

func TestTokenExchangeRoleMatrix(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT", Params: json.RawMessage(`{"max_rows":100}`)}}
	subjectToken, err := env.issuer.NewPrincipalToken("zhangsan", env.pa.Grants,
		[]string{env.issuer.ID}, 3600, env.now)
	if err != nil {
		t.Fatalf("NewPrincipalToken: %v", err)
	}

	t.Run("authorized actor token exchanges", func(t *testing.T) {
		daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		actorTok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		resp, err := env.issuer.TokenExchange(TokenRequest{
			GrantType:        GrantTypeTokenExchange,
			SubjectToken:     subjectToken,
			SubjectTokenType: TokenTypeAIC,
			ActorToken:       actorTok,
			ActorTokenType:   TokenTypeAIC,
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("TokenExchange: %v", err)
		}
		dec, err := env.rs.Check(HTTPRequest{
			AuthzHeader: "Bearer " + resp.AccessToken,
			Audience:    "https://rs.example.com",
			Method:      "GET",
			URL:         "https://rs.example.com/api",
		}, env.now)
		if err != nil {
			t.Fatalf("RS check: %v", err)
		}
		if !dec.Permit || dec.Actor != "agent:db-analyst-01" {
			t.Fatalf("exchange result wrong: permit=%v actor=%q", dec.Permit, dec.Actor)
		}
		if dec.Executor != "agent:db-analyst-01" {
			t.Fatalf("exchange executor = %q, want agent:db-analyst-01", dec.Executor)
		}
	})

	t.Run("representative token is rejected as actor credential", func(t *testing.T) {
		daTok, _ := buildDA(t, env, ModeRepresentative, caps, nil)
		repTok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("IssueFromDA: %v", err)
		}
		_, err = env.issuer.TokenExchange(TokenRequest{
			GrantType:        GrantTypeTokenExchange,
			SubjectToken:     subjectToken,
			SubjectTokenType: TokenTypeAIC,
			ActorToken:       repTok,
			ActorTokenType:   TokenTypeAIC,
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		assertErrContains(t, err, "not an actor credential")
	})
}
