// SPDX-FileCopyrightText: 2026 Jijie Wei (varwof)
// SPDX-License-Identifier: Apache-2.0

package aicjson

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestIssueFromDAShortBoundaries(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}

	daTok := func() string {
		tok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
		return tok
	}

	t.Run("lifetime below 1 rejected", func(t *testing.T) {
		_, _, err := env.issuer.IssueFromDAShort(daTok(), &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, 0, env.now)
		requireErrContains(t, err, "lifetime 0 out of range")
	})

	t.Run("lifetime exceeding DA exp rejected", func(t *testing.T) {
		_, _, err := env.issuer.IssueFromDAShort(daTok(), &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, 7200, env.now)
		requireErrContains(t, err, "exceeds DA expiration")
	})

	t.Run("short-lived token issued within DA window", func(t *testing.T) {
		tok, outer, err := env.issuer.IssueFromDAShort(daTok(), &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, 30, env.now)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if outer.Exp-outer.Iat != 30 {
			t.Fatalf("expected 30s lifetime, got %ds", outer.Exp-outer.Iat)
		}
		requirePermit(t, env, tok, &Capability{Scheme: "database", ID: "query:SELECT"})
	})

	t.Run("DA validation failure propagates", func(t *testing.T) {
		_, _, err := env.issuer.IssueFromDAShort("not-a-token", &env.agentKey.PublicKey,
			[]string{"https://rs.example.com"}, 30, env.now)
		requireErrContains(t, err, "DA validation failed")
	})
}

func TestIssueLightweightBoundaries(t *testing.T) {
	env := newTestEnv(t)
	p := principalBinding(t, env.principalKey)
	caps := []Capability{{Scheme: "http", ID: "GET:/api/v1/*"}}

	t.Run("lifetime out of range", func(t *testing.T) {
		_, _, err := env.issuer.IssueLightweight("agent:web-01", &env.agentKey.PublicKey,
			p, caps, nil, 0, []string{"https://rs.example.com"}, env.now)
		requireErrContains(t, err, "lightweight lifetime out of range")
		_, _, err = env.issuer.IssueLightweight("agent:web-01", &env.agentKey.PublicKey,
			p, caps, nil, MaxLifetime+1, []string{"https://rs.example.com"}, env.now)
		requireErrContains(t, err, "lightweight lifetime out of range")
	})

	t.Run("bad key material propagates", func(t *testing.T) {
		_, _, err := env.issuer.IssueLightweight("agent:web-01", nil,
			p, caps, nil, 1800, []string{"https://rs.example.com"}, env.now)
		if err == nil {
			t.Fatal("expected error for nil public key")
		}
	})
}

func TestTokenExchangeFailureBranches(t *testing.T) {
	env := newTestEnv(t)
	subjectTok, err := env.issuer.NewPrincipalToken("zhangsan",
		[]Capability{{Scheme: "database", ID: "query:*"}},
		[]string{env.issuer.ID}, 3600, env.now)
	if err != nil {
		t.Fatal(err)
	}
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	actorTok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
		[]string{env.issuer.ID}, env.now)
	if err != nil {
		t.Fatal(err)
	}
	aud := []string{"https://rs.example.com"}
	validReq := TokenRequest{
		GrantType:    GrantTypeTokenExchange,
		SubjectToken: subjectTok, ActorToken: actorTok,
	}

	t.Run("wrong grant type", func(t *testing.T) {
		req := validReq
		req.GrantType = "urn:ietf:params:oauth:grant-type:nope"
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "unsupported_grant_type")
	})

	t.Run("missing subject or actor token", func(t *testing.T) {
		req := validReq
		req.SubjectToken = ""
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "subject_token and actor_token required")
	})

	t.Run("malformed subject token", func(t *testing.T) {
		req := validReq
		req.SubjectToken = "garbage"
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "invalid_subject_token")
	})

	t.Run("expired subject token", func(t *testing.T) {
		req := validReq
		req.SubjectToken = subjectTok
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud,
			env.now.Add(2*time.Hour))
		requireErrContains(t, err, "token expired")
	})

	t.Run("expired actor token", func(t *testing.T) {
		req := validReq
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud,
			env.now.Add(4*time.Hour))
		if err == nil {
			t.Fatal("expected actor rejection")
		}
	})

	t.Run("representative-mode actor rejected pre-validation", func(t *testing.T) {
		repTok, _ := buildOuter(t, env, "", nil, ModeRepresentative, caps, nil)
		req := validReq
		req.ActorToken = repTok
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "representative-mode token is not an actor credential")
	})

	t.Run("malformed actor token", func(t *testing.T) {
		req := validReq
		req.ActorToken = "garbage"
		_, err := env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "invalid_actor_token")
	})

	t.Run("actor with no overlapping grants", func(t *testing.T) {
		subjects := []Capability{{Scheme: "http", ID: "GET:/api/v1/*"}}
		noOverlap, err := env.issuer.NewPrincipalToken("zhangsan", subjects,
			[]string{env.issuer.ID}, 3600, env.now)
		if err != nil {
			t.Fatal(err)
		}
		req := validReq
		req.SubjectToken = noOverlap
		_, err = env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "insufficient_scope")
	})

	t.Run("subject token with unknown kid", func(t *testing.T) {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "x",
			"aud": []string{env.issuer.ID}, "iat": env.now.Unix(), "exp": env.now.Add(3600).Unix(),
			"jti": "x1", "grants": []Capability{}})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "unknown-kid"})
		badTok, err := SignCompact(hb, pb, "ES256", other)
		if err != nil {
			t.Fatal(err)
		}
		req := validReq
		req.SubjectToken = badTok
		_, err = env.issuer.TokenExchange(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "unknown kid")
	})
}

func TestExchangeCodeFailureBranches(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, da := buildDA(t, env, ModeAuthorized, caps, nil)
	verifier := "db-verifier-secret-123"
	code, err := env.issuer.NewAuthCode("web-app", "agent:db-analyst-01",
		da.Principal, daTok, verifier, time.Minute, env.now)
	if err != nil {
		t.Fatal(err)
	}
	aud := []string{"https://rs.example.com"}
	validReq := TokenRequest{GrantType: GrantTypeAuthCode, Code: code,
		ClientID: "web-app", CodeVerifier: verifier}

	t.Run("unknown code", func(t *testing.T) {
		req := validReq
		req.Code = "missing"
		_, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "invalid_grant")
	})

	t.Run("expired code", func(t *testing.T) {
		req := validReq
		_, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud,
			env.now.Add(2*time.Minute))
		requireErrContains(t, err, "invalid_grant")
	})

	t.Run("client id mismatch", func(t *testing.T) {
		req := validReq
		req.ClientID = "other-app"
		_, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "code bound to different client")
	})

	t.Run("missing verifier", func(t *testing.T) {
		req := validReq
		req.CodeVerifier = ""
		_, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "code_verifier required")
	})

	t.Run("bad verifier", func(t *testing.T) {
		req := validReq
		req.CodeVerifier = "wrong-verifier"
		_, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now)
		requireErrContains(t, err, "PKCE verification failed")
	})

	t.Run("code single use", func(t *testing.T) {
		// Fresh code; a prior subtest invalidated a wrong-verifier use
		// against a different verifier, so mint a new one.
		code2, err := env.issuer.NewAuthCode("web-app", "agent:db-analyst-01",
			da.Principal, daTok, verifier, time.Minute, env.now)
		if err != nil {
			t.Fatal(err)
		}
		req := validReq
		req.Code = code2
		if _, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now); err != nil {
			t.Fatalf("first use should pass: %v", err)
		}
		if _, err := env.issuer.ExchangeCode(req, &env.agentKey.PublicKey, aud, env.now); err == nil {
			t.Fatal("expected second-use rejection")
		}
	})
}

func TestVerifyAgentActorFailureBranches(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	actorTok, _, err := env.issuer.IssueLightweight("agent:db-analyst-01",
		&env.agentKey.PublicKey, principalBinding(t, env.principalKey), caps, nil,
		1800, []string{"https://as.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("happy path", func(t *testing.T) {
		if err := env.issuer.verifyAgentActor(actorTok, "agent:db-analyst-01", env.now); err != nil {
			t.Fatalf("unexpected: %v", err)
		}
	})

	t.Run("malformed", func(t *testing.T) {
		err := env.issuer.verifyAgentActor("garbage", "agent:db-analyst-01", env.now)
		requireErrContains(t, err, "invalid_actor_token")
	})

	t.Run("wrong typ header", func(t *testing.T) {
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "agent:db-analyst-01"})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "beware", "kid": "issuer-1"})
		badTok, err := SignCompact(hb, pb, "ES256", env.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(badTok, "agent:db-analyst-01", env.now)
		if err == nil {
			t.Fatal("expected typ rejection")
		}
	})

	t.Run("unknown kid", func(t *testing.T) {
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "agent:db-analyst-01"})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "nope"})
		badTok, err := SignCompact(hb, pb, "ES256", env.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(badTok, "agent:db-analyst-01", env.now)
		requireErrContains(t, err, "unknown kid")
	})

	t.Run("signature invalid", func(t *testing.T) {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "agent:db-analyst-01"})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "issuer-1"})
		wrongSig, err := SignCompact(hb, pb, "ES256", other)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(wrongSig, "agent:db-analyst-01", env.now)
		if err == nil {
			t.Fatal("expected signature rejection")
		}
	})

	t.Run("sub mismatch", func(t *testing.T) {
		err := env.issuer.verifyAgentActor(actorTok, "agent:someone-else", env.now)
		requireErrContains(t, err, "!= requested_actor")
	})

	t.Run("issuer mismatch", func(t *testing.T) {
		// Same signing key and kid, different AS id: the signature
		// verifies but the issuer check must reject.
		altIss := NewIssuer("https://other-as.example.com", "issuer-1",
			env.issuerKey, "ES256",
			map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey})
		dupTok, _, err := altIss.IssueLightweight("agent:db-analyst-01",
			&env.agentKey.PublicKey, principalBinding(t, env.principalKey), caps, nil,
			1800, []string{"https://as.example.com"}, env.now)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(dupTok, "agent:db-analyst-01", env.now)
		requireErrContains(t, err, "issuer")
	})

	t.Run("audience mismatch", func(t *testing.T) {
		tok, _, err := env.issuer.IssueLightweight("agent:db-analyst-01",
			&env.agentKey.PublicKey, principalBinding(t, env.principalKey), caps, nil,
			1800, []string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(tok, "agent:db-analyst-01", env.now)
		requireErrContains(t, err, "audience")
	})

	t.Run("expired", func(t *testing.T) {
		err := env.issuer.verifyAgentActor(actorTok, "agent:db-analyst-01",
			env.now.Add(2*time.Hour))
		requireErrContains(t, err, "token expired")
	})

	t.Run("not yet valid", func(t *testing.T) {
		// Sign with an explicit future iat and verify at `now`: the
		// iat-not-before (within-1-minute grace) check must reject.
		pb, _ := json.Marshal(map[string]any{
			"iss": env.issuer.ID, "sub": "agent:db-analyst-01", "typ": TypOuter,
			"aud": []string{"https://as.example.com"},
			"iat": env.now.Add(10 * time.Minute).Unix(),
			"exp": env.now.Add(11 * time.Minute).Unix(),
			"jti": "future-jti",
		})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "issuer-1"})
		futureTok, err := SignCompact(hb, pb, "ES256", env.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		err = env.issuer.verifyAgentActor(futureTok, "agent:db-analyst-01", env.now)
		requireErrContains(t, err, "not yet valid")
	})
}

func TestVerifyDPoPFailureBranches(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)
	tok, _, err := env.issuer.IssueFromDA(daTok, &env.agentKey.PublicKey,
		[]string{"https://rs.example.com"}, env.now)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("malformed proof", func(t *testing.T) {
		_, err := VerifyDPoP("garbage", tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "dpop")
	})

	t.Run("missing jwk header", func(t *testing.T) {
		pb, _ := json.Marshal(map[string]any{"htm": "POST", "htu": "https://rs.example.com/api/db",
			"jti": "j1", "iat": env.now.Unix()})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dpop+jwt"})
		noJWK, err := SignCompact(hb, pb, "ES256", env.agentKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(noJWK, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "header jwk required")
	})

	t.Run("unsupported alg", func(t *testing.T) {
		pub := &env.agentKey.PublicKey
		jwk, _ := PublicKeyToJWK(pub)
		hb, _ := json.Marshal(map[string]any{"alg": "RS512", "typ": "dpop+jwt", "jwk": jwk})
		pb, _ := json.Marshal(map[string]any{"htm": "POST", "htu": "https://rs.example.com/api/db",
			"jti": "j1", "iat": env.now.Unix()})
		// Craft the token manually: SignCompact would refuse RS512 with
		// an EC key, so fake the signature bytes.
		raw := b64uEncode(hb) + "." + b64uEncode(pb) + "." + b64uEncode([]byte("fakesig"))
		_, err = VerifyDPoP(raw, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "unsupported alg")
	})

	t.Run("htm mismatch", func(t *testing.T) {
		proof2, _, err := BuildDPoP(env.agentKey, "ES256", "GET",
			"https://rs.example.com/api/db", tok, env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "htm mismatch")
	})

	t.Run("htu mismatch", func(t *testing.T) {
		proof2, _, err := BuildDPoP(env.agentKey, "ES256", "POST",
			"https://rs.example.com/evil", tok, env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "htu mismatch")
	})

	t.Run("ath mismatch", func(t *testing.T) {
		proof2, _, err := BuildDPoP(env.agentKey, "ES256", "POST",
			"https://rs.example.com/api/db", "some-other-token", env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		requireErrContains(t, err, "ath mismatch")
	})

	t.Run("iat outside freshness window", func(t *testing.T) {
		proof2, _, err := BuildDPoP(env.agentKey, "ES256", "POST",
			"https://rs.example.com/api/db", tok, env.now.Add(-10*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, NewMemNonceStore())
		requireErrContains(t, err, "freshness window")
	})

	t.Run("replay rejected", func(t *testing.T) {
		replay := NewMemNonceStore()
		proof2, _, err := BuildDPoP(env.agentKey, "ES256", "POST",
			"https://rs.example.com/api/db", tok, env.now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, replay); err != nil {
			t.Fatalf("first use: %v", err)
		}
		_, err = VerifyDPoP(proof2, tok, "POST", "https://rs.example.com/api/db",
			env.now, replay)
		requireErrContains(t, err, "replay")
	})

	t.Run("bad jwk in header", func(t *testing.T) {
		pb, _ := json.Marshal(map[string]any{"htm": "POST", "htu": "https://rs.example.com/api/db",
			"jti": "j1", "iat": env.now.Unix()})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "dpop+jwt",
			"jwk": map[string]any{"kty": "RSA", "n": "not-base64", "e": "AQAB"}})
		badJWK, err := SignCompact(hb, pb, "ES256", env.agentKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyDPoP(badJWK, tok, "POST", "https://rs.example.com/api/db",
			env.now, nil)
		if err == nil {
			t.Fatal("expected jwk error")
		}
	})
}

func TestHandleTokenRequestDispatch(t *testing.T) {
	env := newTestEnv(t)
	caps := []Capability{{Scheme: "database", ID: "query:SELECT"}}
	daTok, _ := buildDA(t, env, ModeAuthorized, caps, nil)

	t.Run("jwt bearer without assertion", func(t *testing.T) {
		_, err := env.issuer.HandleTokenRequest(TokenRequest{
			GrantType: GrantTypeJWTBearer,
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		requireErrContains(t, err, "jwt-bearer assertion")
	})

	t.Run("unknown grant type", func(t *testing.T) {
		_, err := env.issuer.HandleTokenRequest(TokenRequest{
			GrantType: "urn:ietf:params:oauth:grant-type:password",
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		requireErrContains(t, err, "unsupported_grant_type")
	})

	t.Run("client assertion fallback from client_assertion field", func(t *testing.T) {
		resp, err := env.issuer.HandleTokenRequest(TokenRequest{
			GrantType:           GrantTypeJWTBearer,
			ClientAssertion:     daTok,
			ClientAssertionType: AssertionTypeJWT,
		}, &env.agentKey.PublicKey, []string{"https://rs.example.com"}, env.now)
		if err != nil {
			t.Fatalf("fallback: %v", err)
		}
		if resp.AccessToken == "" {
			t.Fatal("expected access token")
		}
	})
}

func TestParseOuterPayloadFailures(t *testing.T) {
	t.Run("malformed token", func(t *testing.T) {
		_, err := parseOuterPayload("garbage")
		if err == nil {
			t.Fatal("expected parse failure")
		}
	})

	t.Run("missing aic claim", func(t *testing.T) {
		env := newTestEnv(t)
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "x"})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "issuer-1"})
		tok, err := SignCompact(hb, pb, "ES256", env.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseOuterPayload(tok)
		requireErrContains(t, err, "no aic claim")
	})

	t.Run("bad json payload", func(t *testing.T) {
		env := newTestEnv(t)
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": TypOuter, "kid": "issuer-1"})
		tok, err := SignCompact(hb, []byte("{invalid json"), "ES256", env.issuerKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = parseOuterPayload(tok)
		if err == nil {
			t.Fatal("expected unmarshal failure")
		}
	})
}

func TestPrincipalTokenVerificationFailures(t *testing.T) {
	env := newTestEnv(t)

	t.Run("malformed", func(t *testing.T) {
		_, err := env.issuer.verifyPrincipalToken("garbage", env.now)
		requireErrContains(t, err, "invalid_subject_token")
	})

	t.Run("unknown kid", func(t *testing.T) {
		other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pb, _ := json.Marshal(map[string]any{"iss": env.issuer.ID, "sub": "x",
			"iat": env.now.Unix(), "exp": env.now.Add(3600).Unix()})
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "ghost"})
		bad, err := SignCompact(hb, pb, "ES256", other)
		if err != nil {
			t.Fatal(err)
		}
		_, err = env.issuer.verifyPrincipalToken(bad, env.now)
		requireErrContains(t, err, "unknown kid")
	})

	t.Run("wrong issuer", func(t *testing.T) {
		// Same key/kid, different AS id: sig verifies, iss check rejects.
		altIss := NewIssuer("https://other-as.example.com", "issuer-1",
			env.issuerKey, "ES256",
			map[string]crypto.PublicKey{"principal-1": &env.principalKey.PublicKey})
		tok, err := altIss.NewPrincipalToken("zhangsan",
			[]Capability{{Scheme: "http", ID: "GET:/api/v1/*"}},
			[]string{"https://other-as.example.com"}, 3600, env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = env.issuer.verifyPrincipalToken(tok, env.now)
		requireErrContains(t, err, "issuer")
	})

	t.Run("wrong audience", func(t *testing.T) {
		tok, err := env.issuer.NewPrincipalToken("zhangsan",
			[]Capability{{Scheme: "http", ID: "GET:/api/v1/*"}},
			[]string{"https://rs.example.com"}, 3600, env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = env.issuer.verifyPrincipalToken(tok, env.now)
		requireErrContains(t, err, "audience")
	})

	t.Run("expired", func(t *testing.T) {
		tok, err := env.issuer.NewPrincipalToken("zhangsan",
			[]Capability{{Scheme: "http", ID: "GET:/api/v1/*"}},
			[]string{env.issuer.ID}, 3600, env.now)
		if err != nil {
			t.Fatal(err)
		}
		_, err = env.issuer.verifyPrincipalToken(tok, env.now.Add(2*time.Hour))
		requireErrContains(t, err, "token expired")
	})

	t.Run("bad json payload", func(t *testing.T) {
		env := newTestEnv(t)
		hb, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "at+jwt", "kid": "principal-1"})
		tok, err := SignCompact(hb, []byte("not json"), "ES256", env.principalKey)
		if err != nil {
			t.Fatal(err)
		}
		_, err = env.issuer.verifyPrincipalToken(tok, env.now)
		if err == nil {
			t.Fatal("expected unmarshal failure")
		}
	})
}

func TestBearerTokenAndNormalizeURL(t *testing.T) {
	t.Run("bearer extraction", func(t *testing.T) {
		if got := BearerToken("Bearer abc.def.ghi"); got != "abc.def.ghi" {
			t.Fatalf("got %q", got)
		}
		if got := BearerToken("Basic abc"); got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
		if got := BearerToken(""); got != "" {
			t.Fatalf("expected empty, got %q", got)
		}
	})

	t.Run("url parse failure", func(t *testing.T) {
		if _, err := NormalizeURL(strings.Repeat("%", 300)); err == nil {
			t.Fatal("expected parse failure")
		}
	})

	t.Run("query and fragment stripped", func(t *testing.T) {
		got, err := NormalizeURL("https://rs.example.com/api/db?page=2#frag")
		if err != nil {
			t.Fatal(err)
		}
		if got != "https://rs.example.com/api/db" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("round trip via url.Parse", func(t *testing.T) {
		u, err := url.Parse("  https://bad host")
		_ = u
		if err == nil {
			t.Fatal("expected parse error for malformed URL")
		}
	})
}

func TestReexportHelpers(t *testing.T) {
	env := newTestEnv(t)

	t.Run("match capabilities", func(t *testing.T) {
		allowed := []Capability{{Scheme: "database", ID: "query:*"}}
		if !MatchCapabilities(allowed, Capability{Scheme: "database", ID: "query:SELECT"}) {
			t.Fatal("expected match")
		}
		if MatchCapabilities(allowed, Capability{Scheme: "http", ID: "GET:/x"}) {
			t.Fatal("expected no match")
		}
	})

	t.Run("params within grant", func(t *testing.T) {
		grant := json.RawMessage(`{"max_rows":1000}`)
		agent := json.RawMessage(`{"max_rows":10}`)
		ok, err := ParamsWithinGrant(grant, agent)
		if err != nil || !ok {
			t.Fatalf("expected true, got %v/%v", ok, err)
		}
		bad := json.RawMessage(`{"max_rows":9999}`)
		ok, err = ParamsWithinGrant(grant, bad)
		if err != nil || ok {
			t.Fatalf("expected false, got %v/%v", ok, err)
		}
		// Malformed agent params are an omission, not an error.
		ok, err = ParamsWithinGrant(grant, json.RawMessage(`{"x":`))
		if err != nil || ok {
			t.Fatalf("expected false, got %v/%v", ok, err)
		}
		// Malformed grant params surface as an error.
		if _, err := ParamsWithinGrant(json.RawMessage(`{"x":`), json.RawMessage(`{}`)); err == nil {
			t.Fatal("expected parse error")
		}
	})

	t.Run("evaluate constraints", func(t *testing.T) {
		cs := []Capability{{Scheme: ConstraintScheme, ID: "time-window",
			Params: json.RawMessage(`{"start":"00:00","end":"23:59"}`)}}
		denied, err := EvaluateConstraints(cs, defaultCtx(env), false)
		if err != nil {
			t.Fatal(err)
		}
		if len(denied) != 0 {
			t.Fatalf("expected no denials, got %v", denied)
		}
	})

	t.Run("jwk thumbprint + parse", func(t *testing.T) {
		jwk, err := PublicKeyToJWK(&env.principalKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		thumb, err := JWKThumbprint(jwk)
		if err != nil || thumb == "" {
			t.Fatalf("thumbprint: %q %v", thumb, err)
		}
		raw, _ := json.Marshal(jwk)
		parsed, err := ParseJWK(raw)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Kty != jwk.Kty {
			t.Fatalf("round trip mismatch")
		}
		if _, err := ParseJWK([]byte("{")); err == nil {
			t.Fatal("expected parse failure")
		}
		if _, err := JWKThumbprint(JWK{Kty: "oct"}); err == nil {
			t.Fatal("expected thumbprint failure for unsupported kty")
		}
	})

	t.Run("json raw equal", func(t *testing.T) {
		eq, err := JSONRawEqual(json.RawMessage(`{"a":1}`), json.RawMessage(`{"a":1}`))
		if err != nil || !eq {
			t.Fatalf("expected equal: %v %v", eq, err)
		}
		eq, err = JSONRawEqual(json.RawMessage(`[1,{"b":2}]`), json.RawMessage(`[1,{"b":3}]`))
		if err != nil || eq {
			t.Fatalf("expected unequal: %v %v", eq, err)
		}
	})

	t.Run("cap to pki conversion", func(t *testing.T) {
		c := CapToPKI(Capability{Scheme: "database", ID: "query:SELECT"})
		if c.CapabilityId != "query:SELECT" {
			t.Fatalf("got %+v", c)
		}
	})

	t.Run("jwk to public", func(t *testing.T) {
		jwk, err := PublicKeyToJWK(&env.principalKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := JWKToPublic(jwk)
		if err != nil {
			t.Fatal(err)
		}
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok || ec.X == nil {
			t.Fatalf("expected ecdsa public key, got %T", pub)
		}
		unsupported := JWK{Kty: "it_me"}
		if _, err := JWKToPublic(unsupported); err == nil {
			t.Fatal("expected unsupported kty failure")
		}
	})

	t.Run("spki hash helpers", func(t *testing.T) {
		h, err := SPKIHashPub(&env.principalKey.PublicKey, "sha-256")
		if err != nil || h == "" {
			t.Fatalf("spki hash: %q %v", h, err)
		}
		if _, err := SPKIHash(env.principalCert, "sha-256"); err != nil {
			t.Fatal(err)
		}
		if _, err := SPKIHash(env.principalCert, "md5"); err == nil {
			t.Fatal("expected unsupported alg failure")
		}
	})

	t.Run("check header helper", func(t *testing.T) {
		if err := checkHeader(Header{Alg: "ES256", Typ: TypOuter, Kid: "issuer-1"}, TypOuter); err != nil {
			t.Fatal(err)
		}
		if err := checkHeader(Header{Alg: "none", Typ: TypOuter, Kid: "issuer-1"}, TypOuter); err == nil {
			t.Fatal("expected alg rejection")
		}
		if err := checkHeader(Header{Alg: "ES256", Typ: "other", Kid: "issuer-1"}, TypOuter); err == nil {
			t.Fatal("expected typ rejection")
		}
		if err := checkHeader(Header{Alg: "ES256", Typ: TypOuter, Kid: "issuer-1", Crit: []string{"exp"}}, TypOuter); err == nil {
			t.Fatal("expected crit rejection")
		}
	})

	t.Run("capability subset helper", func(t *testing.T) {
		if capabilitySubset(Capability{Scheme: "database", ID: "query:SELECT"},
			[]Capability{{Scheme: "database", ID: "query:*"}}) != true {
			t.Fatal("expected subset")
		}
	})

	t.Run("b64u encode and decode", func(t *testing.T) {
		enc := b64uEncode([]byte("hello"))
		dec, err := b64uDecode(enc)
		if err != nil || string(dec) != "hello" {
			t.Fatalf("round trip failed: %v %q", err, dec)
		}
		if _, err := b64uDecode(strings.Repeat("=", 3)); err != nil {
			// base64 with padding chars fails under RawURLEncoding
		}
	})

	t.Run("key hash of", func(t *testing.T) {
		h, err := KeyHashOf(&env.principalKey.PublicKey, "jkt")
		if err != nil || h == "" {
			t.Fatalf("jkt: %q %v", h, err)
		}
		if _, err := KeyHashOf(nil, "sha-256"); err == nil {
			t.Fatal("expected failure for nil key")
		}
	})

	t.Run("parse compact negative", func(t *testing.T) {
		if _, _, _, err := ParseCompact("a.b"); err == nil {
			t.Fatal("expected parse failure")
		}
	})
}

func TestMemNonceStoreReplay(t *testing.T) {
	s := NewMemNonceStore()
	if err := s.CheckAndAdd("abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckAndAdd("abc"); err == nil {
		t.Fatal("expected replay rejection")
	}
}

func TestRandomIDAndHex(t *testing.T) {
	a, err := randomID(16)
	if err != nil || len(a) != 32 {
		t.Fatalf("expected 32 hex chars, got %q %v", a, err)
	}
	b, err := randomID(8)
	if err != nil || len(b) != 16 {
		t.Fatalf("expected 16 hex chars, got %q %v", b, err)
	}
	raw := base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := base64.RawURLEncoding.DecodeString(raw); err != nil {
		t.Fatal(err)
	}
}

func TestNewPrincipalTokenRoundTrip(t *testing.T) {
	env := newTestEnv(t)
	tok, err := env.issuer.NewPrincipalToken("zhangsan",
		[]Capability{{Scheme: "database", ID: "query:SELECT"}},
		[]string{env.issuer.ID}, 3600, env.now)
	if err != nil {
		t.Fatal(err)
	}
	c, err := env.issuer.verifyPrincipalToken(tok, env.now)
	if err != nil {
		t.Fatal(err)
	}
	if c.Sub != "zhangsan" {
		t.Fatalf("got sub %q", c.Sub)
	}
	if len(c.Grants) != 1 {
		t.Fatalf("got %d grants", len(c.Grants))
	}
}
